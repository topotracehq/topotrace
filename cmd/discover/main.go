/*******************************************************************************
 * @file         main.go
 * @brief        Command discover is TopoTrace's network/asset discovery scanner: a TCP connect sweep across a CIDR (or a single address/comma-separated list), best-effort banner grabbing on anything that answers, and a report of what it found to TopoTrace's POST /api/discover-report.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command discover is TopoTrace's network/asset discovery scanner: a TCP
// connect sweep across a CIDR (or a single address/comma-separated
// list), best-effort banner grabbing on anything that answers, and a
// report of what it found to TopoTrace's POST /api/discover-report.
//
// This is deliberately a small slice of the asset-discovery space (see
// https://github.com/redhuntlabs/Awesome-Asset-Discovery for the much
// larger field this borrows its framing from), not a general-purpose
// scanner: a fixed short list of common ports, a plain TCP connect scan
// (no SYN/stealth scanning, which needs raw sockets and usually root),
// and a handful of protocol-agnostic banner-grab heuristics. The point
// is answering one question for an operator -- "what's alive on this
// network that TopoTrace doesn't already manage?" -- not replacing nmap.
//
//	go run ./cmd/discover -cidr 192.168.1.0/24 -server http://localhost:8080 -token ...
//	go run ./cmd/discover -targets 10.0.0.5,10.0.0.6 -ports 22,80,443
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// commonPorts is the default port list -- a small, well-known set
// covering the services an operator is most likely to care about
// finding unmanaged instances of, not an attempt at exhaustive
// coverage. -ports overrides this entirely.
var commonPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

// maxAddresses caps how many hosts a single run will enumerate from a
// CIDR, so a fat-fingered /8 doesn't turn into an accidental multi-hour
// sweep of the whole internet. -force lifts the cap.
const maxAddresses = 65536

type result struct {
	address string
	ports   []int
	banners map[string]string
}

func main() {
	cidr := flag.String("cidr", "", "CIDR range to sweep, e.g. 192.168.1.0/24 (mutually exclusive with -targets)")
	targets := flag.String("targets", "", "comma-separated list of hosts/IPs to scan (mutually exclusive with -cidr)")
	portsFlag := flag.String("ports", "", "comma-separated list of ports to check (default: a common-services list)")
	server := flag.String("server", "http://localhost:8080", "TopoTrace server base URL to report results to")
	token := flag.String("token", "", "bearer token for the report (needs at least the 'remediate' role if the server has -auth-token set)")
	scannedBy := flag.String("scanned-by", "", "operator-supplied label recorded with this scan (default: hostname)")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "per-port connect timeout")
	bannerTimeout := flag.Duration("banner-timeout", 500*time.Millisecond, "how long to wait for a banner after connecting")
	concurrency := flag.Int("concurrency", 200, "max concurrent connection attempts")
	force := flag.Bool("force", false, "allow scanning more than 65536 addresses from a single CIDR")
	dryRun := flag.Bool("dry-run", false, "scan and print results, but don't POST a report")
	flag.Parse()

	if (*cidr == "") == (*targets == "") {
		fmt.Fprintln(os.Stderr, "specify exactly one of -cidr or -targets")
		os.Exit(1)
	}

	addrs, err := resolveTargets(*cidr, *targets, *force)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolving targets:", err)
		os.Exit(1)
	}
	ports := commonPorts
	if *portsFlag != "" {
		ports, err = parsePorts(*portsFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parsing -ports:", err)
			os.Exit(1)
		}
	}

	by := *scannedBy
	if by == "" {
		if h, err := os.Hostname(); err == nil {
			by = h
		} else {
			by = "discover-cli"
		}
	}

	fmt.Fprintf(os.Stderr, "discover: sweeping %d address(es) x %d port(s), concurrency=%d\n", len(addrs), len(ports), *concurrency)
	results := sweep(addrs, ports, *timeout, *bannerTimeout, *concurrency)
	sort.Slice(results, func(i, j int) bool { return results[i].address < results[j].address })

	for _, r := range results {
		fmt.Printf("%s: open ports %v\n", r.address, r.ports)
		for port, banner := range r.banners {
			fmt.Printf("  [%s] %s\n", port, truncate(banner, 120))
		}
	}
	fmt.Fprintf(os.Stderr, "discover: %d host(s) with at least one open port (of %d scanned)\n", len(results), len(addrs))

	if *dryRun {
		return
	}
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "discover: nothing to report, skipping POST")
		return
	}
	if err := report(*server, *token, *cidr, by, results); err != nil {
		fmt.Fprintln(os.Stderr, "reporting to server:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "discover: report sent")
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// resolveTargets expands -cidr into every host address in the range
// (skipping the network and broadcast addresses for IPv4), or splits
// -targets on commas. Exactly one of cidr/targets is expected to be
// non-empty; the caller enforces that.
func resolveTargets(cidr, targets string, force bool) ([]string, error) {
	if targets != "" {
		var out []string
		for _, t := range strings.Split(targets, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				out = append(out, t)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no targets parsed from %q", targets)
		}
		return out, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported")
	}

	var addrs []string
	count := 0
	for a := cloneIP(ipnet.IP); ipnet.Contains(a); incIP(a) {
		count++
		if count > maxAddresses && !force {
			return nil, fmt.Errorf("%s expands to more than %d addresses; pass -force to scan it anyway", cidr, maxAddresses)
		}
		addrs = append(addrs, a.String())
	}
	// Drop network and broadcast addresses for anything larger than a
	// /31 or /32, where they're not meaningful hosts to probe.
	ones, bits := ipnet.Mask.Size()
	if bits-ones >= 2 && len(addrs) >= 2 {
		addrs = addrs[1 : len(addrs)-1]
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s contains no scannable host addresses", cidr)
	}
	return addrs, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed")
	}
	return out, nil
}

// sweep runs a bounded-concurrency TCP connect scan across every
// address x port combination and returns one result per address that
// had at least one open port.
func sweep(addrs []string, ports []int, timeout, bannerTimeout time.Duration, concurrency int) []result {
	type job struct {
		address string
		port    int
	}
	type hit struct {
		address string
		port    int
		banner  string
	}

	// A fixed pool of worker goroutines pulling from a job channel,
	// rather than spawning one goroutine per address x port pair up
	// front -- a full default sweep (65536 addresses x 19 ports) is
	// over a million combinations, and a goroutine-per-task plus a
	// semaphore would still pay the cost of creating and scheduling all
	// of them at once just to have most immediately block. This keeps
	// live goroutines bounded by concurrency the whole time.
	jobs := make(chan job, concurrency*2)
	hits := make(chan hit, 256)
	var wg sync.WaitGroup

	if concurrency < 1 {
		concurrency = 1
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				target := net.JoinHostPort(j.address, strconv.Itoa(j.port))
				conn, err := net.DialTimeout("tcp", target, timeout)
				if err != nil {
					continue
				}
				banner := grabBanner(conn, j.port, bannerTimeout)
				conn.Close()
				hits <- hit{address: j.address, port: j.port, banner: banner}
			}
		}()
	}

	go func() {
		for _, addr := range addrs {
			for _, port := range ports {
				jobs <- job{address: addr, port: port}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(hits)
	}()

	byAddr := map[string]*result{}
	for h := range hits {
		r, ok := byAddr[h.address]
		if !ok {
			r = &result{address: h.address, banners: map[string]string{}}
			byAddr[h.address] = r
		}
		r.ports = append(r.ports, h.port)
		if h.banner != "" {
			r.banners[strconv.Itoa(h.port)] = h.banner
		}
	}

	out := make([]result, 0, len(byAddr))
	for _, r := range byAddr {
		sort.Ints(r.ports)
		out = append(out, *r)
	}
	return out
}

// grabBanner makes one best-effort attempt to read whatever a service
// offers unprompted (SSH, FTP, SMTP, and plenty of others announce
// themselves immediately on connect); for the handful of ports that
// don't (plain HTTP), it sends a minimal HEAD request first. Never
// blocks longer than bannerTimeout, and any error just means an empty
// banner -- this is advisory information for the dashboard, not
// something a scan should fail over.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}
	if err == nil || port != 80 && port != 8080 && port != 8000 {
		return ""
	}
	// Nothing volunteered and this looks like plain HTTP -- ask.
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n")); err != nil {
		return ""
	}
	conn.SetDeadline(time.Now().Add(timeout))
	n, _ = conn.Read(buf)
	if n == 0 {
		return ""
	}
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	return strings.TrimSpace(line)
}

type discoverReportRequest struct {
	ScannedBy   string                 `json:"scanned_by"`
	ScannedCIDR string                 `json:"scanned_cidr"`
	Assets      []discoveredAssetInput `json:"assets"`
}

type discoveredAssetInput struct {
	Address   string            `json:"address"`
	OpenPorts []int             `json:"open_ports"`
	Banners   map[string]string `json:"banners,omitempty"`
}

func report(server, token, cidr, scannedBy string, results []result) error {
	req := discoverReportRequest{ScannedBy: scannedBy, ScannedCIDR: cidr}
	for _, r := range results {
		req.Assets = append(req.Assets, discoveredAssetInput{Address: r.address, OpenPorts: r.ports, Banners: r.banners})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	url := strings.TrimRight(server, "/") + "/api/discover-report"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}
