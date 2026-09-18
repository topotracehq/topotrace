/*******************************************************************************
 * @file         main.go
 * @brief        Command seed populates a Muster store with a realistic, varied set of synthetic demo data -- a dozen-plus hosts across Linux/Windows/macOS, a mix of compliant and non-compliant posture, real-looking vulnerability findings, a couple of st...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command seed populates a Muster store with a realistic, varied set of
// synthetic demo data -- a dozen-plus hosts across Linux/Windows/macOS,
// a mix of compliant and non-compliant posture, real-looking
// vulnerability findings, a couple of stale hosts, a few unmanaged
// discovered assets, a shadow-AI detection, and a handful of policy/
// software rules -- so the dashboard looks like a real fleet instead of
// an empty demo instance.
//
// It talks to the Store directly (the same package cmd/muster wires up:
// memstore or pgstore, picked with the same -data-dir/-postgres-dsn
// flags cmd/muster itself takes), not over the network -- there's no
// "insert one host's worth of arbitrary facts" HTTP endpoint in the API
// today (POST /api/mobile-report is deliberately restricted to
// android/ios, and the real MUSTER1 agent protocol wants an exact,
// regex-matched capture-file format per platform), and reaching
// straight for the Store is exactly what this tool's job -- seeding a
// large, varied, hand-authored dataset in one shot -- calls for.
//
// A note on timing, stated plainly rather than glossed over: against
// the default memstore backend, this only takes effect the next time
// cmd/muster (re)starts against the same -data-dir -- memstore keeps
// its state in memory once loaded and has no way to notice a second
// process editing its snapshot file live. Point both at the same
// -postgres-dsn instead and it works against an already-running server
// immediately, no restart needed, since both processes are just two
// clients of the same database.
//
//	go run ./cmd/seed                                   # then (re)start cmd/muster
//	go run ./cmd/seed -postgres-dsn "postgres://..."     # live against a running Postgres-backed server
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"muster/internal/model"
	"muster/internal/store"
	"muster/internal/store/memstore"
	"muster/internal/store/pgstore"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "same -data-dir as cmd/muster -- the memstore JSON snapshot lives at <data-dir>/muster.json. Ignored when -postgres-dsn is set.")
	postgresDSN := flag.String("postgres-dsn", os.Getenv("MUSTER_POSTGRES_DSN"), "same -postgres-dsn/MUSTER_POSTGRES_DSN as cmd/muster -- seed straight into Postgres instead of memstore. This is the option that works against an already-running server with no restart.")
	flag.Parse()

	ctx := context.Background()

	var st store.Store
	if *postgresDSN != "" {
		pg, err := pgstore.New(ctx, *postgresDSN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seed: opening postgres store:", err)
			os.Exit(1)
		}
		defer pg.Close()
		st = pg
		fmt.Println("seed: writing into postgres store (live -- an already-running server backed by this DSN will see this immediately)")
	} else {
		path := *dataDir + "/muster.json"
		mem, err := memstore.New(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seed: opening memstore:", err)
			os.Exit(1)
		}
		st = mem
		fmt.Printf("seed: writing into memstore snapshot at %s\n", path)
	}

	n, err := seed(ctx, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed: failed:", err)
		os.Exit(1)
	}

	fmt.Printf("seed: wrote %d hosts, %d software rules, %d policy rules, %d discovered assets, %d score-history points (30 days), %d golden baselines\n", n.hosts, n.softwareRules, n.policyRules, n.discoveredAssets, n.historyPoints, n.baselines)
	if *postgresDSN == "" {
		fmt.Println("seed: memstore backend -- (re)start cmd/muster against the same -data-dir to serve this data.")
	}
}

type counts struct {
	hosts, softwareRules, policyRules, discoveredAssets, historyPoints, baselines int
}

func seed(ctx context.Context, st store.Store) (counts, error) {
	now := time.Now().UTC()
	var n counts

	for _, h := range demoHosts(now) {
		firstSeen := h.LastCooked.Add(-h.age)
		if err := st.UpsertHost(ctx, model.Host{
			Name: h.Name, Platform: h.Platform, Group: h.Group, Tags: h.Tags,
			FirstSeen: firstSeen, LastCooked: h.LastCooked,
		}); err != nil {
			return n, fmt.Errorf("upserting host %s: %w", h.Name, err)
		}
		for category, data := range h.Facts {
			if _, err := st.UpsertFact(ctx, model.Fact{
				Host: h.Name, Category: category, Data: data, CookedAt: h.LastCooked,
			}); err != nil {
				return n, fmt.Errorf("upserting %s/%s: %w", h.Name, category, err)
			}
		}
		n.hosts++
	}

	for _, r := range demoSoftwareRules() {
		if _, err := st.CreateSoftwareRule(ctx, r); err != nil {
			return n, fmt.Errorf("creating software rule %s: %w", r.Name, err)
		}
		n.softwareRules++
	}

	for _, r := range demoPolicyRules() {
		if _, err := st.CreateRule(ctx, r); err != nil {
			return n, fmt.Errorf("creating policy rule %s: %w", r.Name, err)
		}
		n.policyRules++
	}

	for _, a := range demoDiscoveredAssets() {
		if _, err := st.UpsertDiscoveredAsset(ctx, a); err != nil {
			return n, fmt.Errorf("recording discovered asset %s: %w", a.Address, err)
		}
		n.discoveredAssets++
	}

	hosts, err := st.ListHosts(ctx)
	if err != nil {
		return n, fmt.Errorf("listing hosts for history: %w", err)
	}
	if n.historyPoints, err = seedHistory(ctx, st, hosts, now); err != nil {
		return n, err
	}
	if n.baselines, err = seedBaselines(ctx, st); err != nil {
		return n, err
	}

	if _, err := st.RecordAudit(ctx, "seed-tool", "seed-demo-data", "", fmt.Sprintf("%d hosts, %d software rules, %d policy rules, %d discovered assets", n.hosts, n.softwareRules, n.policyRules, n.discoveredAssets)); err != nil {
		return n, fmt.Errorf("recording seed audit entry: %w", err)
	}

	return n, nil
}

// seedHost is one synthetic host: identity/board metadata plus every
// fact category to upsert for it. age is how long ago the host first
// reported, purely for a believable FirstSeen -- LastCooked is set
// explicitly per host so a couple can be backdated past the 24h
// staleness threshold (internal/policy.StaleAfter) to demo the STALE
// badge/posture penalty for real, not just describe it.
type seedHost struct {
	Name       string
	Platform   string
	Group      string
	Tags       []string
	LastCooked time.Time
	age        time.Duration
	Facts      map[string]map[string]any
}

// sw builds an installed_software-shaped fact from (name, version,
// architecture) triples -- the same {"count","items"} shape
// internal/cook.listResult produces.
func sw(rows ...[3]string) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"name": r[0], "version": r[1], "architecture": r[2]})
	}
	return map[string]any{"count": len(items), "items": items}
}

// winSW builds a Windows-shaped installed_software fact (no
// architecture column -- cookWinSoftware only ever produces name/version).
func winSW(rows ...[2]string) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"name": r[0], "version": r[1]})
	}
	return map[string]any{"count": len(items), "items": items}
}

// ext builds one browser_extensions item the way
// internal/cook.parseBrowserExtensions produces it.
func ext(browser, profile, id, name, version string, mv int, perms, hosts []string, store bool) map[string]any {
	if perms == nil {
		perms = []string{}
	}
	if hosts == nil {
		hosts = []string{}
	}
	return map[string]any{
		"browser": browser, "profile": profile, "id": id, "name": name, "version": version,
		"manifest_version": mv, "permissions": perms, "host_permissions": hosts, "from_web_store": store,
	}
}

// cert builds one tls_certificates item; expires is relative to now.
func certItem(id, subject, issuer string, expires time.Time) map[string]any {
	return map[string]any{"id": id, "subject": subject, "issuer": issuer, "not_after": expires.UTC().Format(time.RFC3339)}
}

func certsFact(items ...map[string]any) map[string]any {
	return map[string]any{"count": len(items), "items": items}
}

// ifaces builds a network_interfaces fact from IPv4 addresses the way
// internal/cook.parseLinuxInterfaces produces it.
func ifaces(addrs ...string) map[string]any {
	items := make([]map[string]any, 0, len(addrs)+1)
	items = append(items, map[string]any{"interface": "lo", "family": "inet", "address": "127.0.0.1"})
	for i, a := range addrs {
		items = append(items, map[string]any{"interface": fmt.Sprintf("eth%d", i), "family": "inet", "address": a})
	}
	return map[string]any{"count": len(items), "items": items}
}

func exts(items ...map[string]any) map[string]any {
	return map[string]any{"count": len(items), "items": items}
}

func disks(rows ...[4]any) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"filesystem": r[0], "size_mb": r[1], "used_mb": r[2], "available_mb": r[3]})
	}
	return map[string]any{"count": len(items), "items": items}
}

func winDisks(rows ...[3]any) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"filesystem": r[0], "size_mb": r[1], "available_mb": r[2]})
	}
	return map[string]any{"count": len(items), "items": items}
}

func pendingUpdates(rows ...[3]string) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"package": r[0], "available_version": r[1], "current_version": r[2]})
	}
	return map[string]any{"count": len(items), "items": items}
}

func linuxFirewall(status string) map[string]any {
	return map[string]any{"ufw_status": status}
}

func winFirewall(domain, private, public bool) map[string]any {
	b := func(v bool) string {
		if v {
			return "True"
		}
		return "False"
	}
	return map[string]any{"Domain_enabled": b(domain), "Private_enabled": b(private), "Public_enabled": b(public)}
}

func linuxSummary(distro, version, kernel, cpu string, numCPUs, memMB int, uptime string) map[string]any {
	return map[string]any{
		"os": "Linux", "distribution": distro, "distribution_version": version,
		"kernel_version": kernel, "cpu_model": cpu, "cpu_vendor": "GenuineIntel",
		"cpu_speed_mhz": 2600, "num_cpus": numCPUs, "memory_mb": memMB, "uptime": uptime,
	}
}

func windowsSummary(caption, version, build, cpu string, numCPUs, memMB int, uptime string) map[string]any {
	return map[string]any{
		"os": "Windows", "distribution": caption, "distribution_version": version,
		"kernel_version": build, "cpu_model": cpu, "cpu_vendor": "GenuineIntel",
		"cpu_speed_mhz": 3100, "num_cpus": numCPUs, "memory_mb": memMB,
		"os_architecture": "64-bit", "uptime": uptime,
	}
}

func darwinSummary(product, version, kernel, cpu string, numCPUs, memMB int, uptime string) map[string]any {
	return map[string]any{
		"os": "Darwin", "distribution": product, "distribution_version": version,
		"kernel_version": kernel, "cpu_model": cpu, "num_cpus": numCPUs,
		"memory_mb": memMB, "uptime": uptime,
	}
}

// demoHosts is the seeded fleet: 15 hosts across linux/windows/darwin,
// a mix of compliant and non-compliant posture, three with real-looking
// vulnerability findings against internal/vuln.Dataset's curated CVEs,
// three with a shadow-AI detection (internal/allowlist.ShadowAIPatterns),
// one generic (non-AI) software-allowlist violation, and two backdated
// past the staleness threshold.
func demoHosts(now time.Time) []seedHost {
	day := 24 * time.Hour

	return []seedHost{
		{
			Name: "web01.prod", Platform: "linux", Group: "prod", Tags: []string{"public", "nginx"},
			LastCooked: now, age: 120 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "22.04.4 LTS", "5.15.0-105-generic", "Intel Xeon Platinum 8259CL", 4, 8192, "45 days, 3:12"),
				"network_interfaces": ifaces("10.0.1.10"),
				"installed_software": sw(
					[3]string{"openssh-server", "9.6p1-3ubuntu1", "amd64"},
					[3]string{"openssl", "3.0.13-0ubuntu3.4", "amd64"},
					[3]string{"nginx", "1.24.0-2ubuntu7.3", "amd64"},
					[3]string{"curl", "8.5.0-2ubuntu10.4", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 51200, 18400, 32800}),
				"firewall_av_status": linuxFirewall("active"),
				"tls_certificates": certsFact(
					certItem("/etc/letsencrypt/live/www.example.com/cert.pem", "CN = www.example.com", "C = US, O = Let's Encrypt, CN = R11", now.Add(61*day)),
					certItem("/etc/nginx/ssl/api-gateway.crt", "CN = api-gateway.example.com", "CN = Example Corp Internal CA", now.Add(12*day)),
				),
			},
		},
		{
			Name: "web02.prod", Platform: "linux", Group: "prod", Tags: []string{"public", "nginx"},
			LastCooked: now, age: 118 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "22.04.4 LTS", "5.15.0-105-generic", "Intel Xeon Platinum 8259CL", 4, 8192, "45 days, 3:09"),
				"network_interfaces": ifaces("10.0.1.12"),
				"installed_software": sw(
					[3]string{"openssh-server", "9.6p1-3ubuntu1", "amd64"},
					[3]string{"openssl", "3.0.13-0ubuntu3.4", "amd64"},
					[3]string{"nginx", "1.24.0-2ubuntu7.3", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 51200, 17900, 33300}),
				"firewall_av_status": linuxFirewall("active"),
			},
		},
		{
			Name: "api01.prod", Platform: "linux", Group: "prod", Tags: []string{"internal", "criticality:high"},
			LastCooked: now, age: 95 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "20.04.6 LTS", "5.4.0-190-generic", "Intel Xeon Platinum 8259CL", 4, 16384, "12 days, 0:41"),
				"network_interfaces": ifaces("10.0.1.11"),
				"installed_software": sw(
					// curl <= 7.83.1 is in internal/vuln.Dataset (CVE-2022-32221).
					[3]string{"curl", "7.68.0-1ubuntu2.22", "amd64"},
					[3]string{"libcurl4", "7.68.0-1ubuntu2.22", "amd64"},
					// vsftpd matches the seeded deny software-rule -- a
					// generic (non-shadow-AI) allowlist violation.
					[3]string{"vsftpd", "3.0.3-12", "amd64"},
					[3]string{"python3", "3.8.10-0ubuntu1.13", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 102400, 71200, 25900}),
				"firewall_av_status": linuxFirewall("inactive"),
				"tls_certificates": certsFact(
					certItem("/etc/ssl/private/api01.crt", "CN = api01.prod.example.com", "CN = Example Corp Internal CA", now.Add(-9*day)),
				),
				"patch_update_status": pendingUpdates(
					[3]string{"libssl3", "3.0.13", "3.0.10"},
					[3]string{"linux-libc-dev", "5.4.0-192.212", "5.4.0-190.210"},
					[3]string{"tzdata", "2024a-0ubuntu0.20.04", "2023d-0ubuntu0.20.04"},
					[3]string{"sudo", "1.9.5p2-3ubuntu2", "1.9.5p2-3ubuntu1"},
					[3]string{"openssh-client", "8.2p1-4ubuntu0.11", "8.2p1-4ubuntu0.10"},
					[3]string{"gzip", "1.10-4ubuntu4.1", "1.10-4ubuntu4"},
				),
			},
		},
		{
			Name: "db01.prod", Platform: "linux", Group: "prod", Tags: []string{"database", "pii", "criticality:critical"},
			LastCooked: now, age: 200 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "24.04.1 LTS", "6.8.0-45-generic", "Intel Xeon Gold 6252", 8, 32768, "3 days, 7:55"),
				"network_interfaces": ifaces("10.0.1.20"),
				"installed_software": sw(
					// sudo <= 1.9.5 and openssl <= 1.1.1n are both real
					// entries in internal/vuln.Dataset.
					[3]string{"sudo", "1.8.31-1ubuntu1.5", "amd64"},
					[3]string{"openssl", "1.1.1f-1ubuntu2.23", "amd64"},
					[3]string{"libssl1.1", "1.1.1f-1ubuntu2.23", "amd64"},
					[3]string{"postgresql-14", "14.11-0ubuntu0.20.04.1", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 512000, 402000, 84300}),
				"firewall_av_status": linuxFirewall("inactive"),
				"patch_update_status": pendingUpdates(
					[3]string{"libssl1.1", "1.1.1f-1ubuntu2.24", "1.1.1f-1ubuntu2.23"},
					[3]string{"postgresql-14", "14.12-0ubuntu0.20.04.1", "14.11-0ubuntu0.20.04.1"},
					[3]string{"openssh-server", "8.2p1-4ubuntu0.11", "8.2p1-4ubuntu0.10"},
					[3]string{"curl", "7.68.0-1ubuntu2.24", "7.68.0-1ubuntu2.22"},
					[3]string{"vim", "8.1.2269-1ubuntu5.24", "8.1.2269-1ubuntu5.23"},
					[3]string{"bash", "5.0-6ubuntu1.2", "5.0-6ubuntu1.1"},
					[3]string{"tar", "1.30+dfsg-7ubuntu0.20.04.4", "1.30+dfsg-7ubuntu0.20.04.3"},
					[3]string{"coreutils", "8.30-3ubuntu2.25", "8.30-3ubuntu2.24"},
					[3]string{"perl-base", "5.30.0-9ubuntu0.5", "5.30.0-9ubuntu0.4"},
					[3]string{"apt", "2.0.10", "2.0.9"},
				),
			},
		},
		{
			Name: "cache01.prod", Platform: "linux", Group: "prod", Tags: []string{"redis"},
			LastCooked: now, age: 88 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "22.04.4 LTS", "5.15.0-105-generic", "Intel Xeon Platinum 8259CL", 2, 4096, "60 days, 11:02"),
				"network_interfaces": ifaces("10.0.1.30"),
				"installed_software": sw(
					[3]string{"redis-server", "6.0.16-1ubuntu1.2", "amd64"},
					[3]string{"openssl", "3.0.13-0ubuntu3.4", "amd64"},
					// Shadow AI: ollama, not on any allowlist.
					[3]string{"ollama", "0.1.32", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 25600, 6200, 18100}),
				"firewall_av_status": linuxFirewall("active"),
			},
		},
		{
			Name: "build01.eng", Platform: "linux", Group: "eng", Tags: []string{"ci"},
			LastCooked: now, age: 60 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "24.04.1 LTS", "6.8.0-45-generic", "AMD EPYC 7402P", 16, 65536, "6 days, 14:20"),
				"network_interfaces": ifaces("10.0.2.10"),
				"installed_software": sw(
					// bash <= 4.3.25 (Shellshock, CVE-2014-6271) is the
					// most severe entry in internal/vuln.Dataset.
					[3]string{"bash", "4.3-11ubuntu1", "amd64"},
					[3]string{"git", "1:2.25.1-1ubuntu3.13", "amd64"},
					[3]string{"docker-ce", "5:24.0.9-1~ubuntu.20.04~focal", "amd64"},
					// Shadow AI: an unofficial ChatGPT desktop wrapper.
					[3]string{"chatgpt-desktop", "0.11.0", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 204800, 168300, 26100}),
				"firewall_av_status": linuxFirewall("inactive"),
				"patch_update_status": pendingUpdates(
					[3]string{"bash", "5.0-6ubuntu1.2", "4.3-11ubuntu1"},
					[3]string{"docker-ce", "5:25.0.3-1~ubuntu.20.04~focal", "5:24.0.9-1~ubuntu.20.04~focal"},
					[3]string{"git", "1:2.25.1-1ubuntu3.14", "1:2.25.1-1ubuntu3.13"},
					[3]string{"linux-libc-dev", "5.4.0-192.212", "5.4.0-190.210"},
				),
			},
		},
		{
			Name: "jump01.eng", Platform: "linux", Group: "eng", Tags: []string{"bastion"},
			LastCooked: now, age: 210 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Debian", "12 (bookworm)", "6.1.0-18-amd64", "Intel Xeon E5-2650", 2, 4096, "90 days, 2:15"),
				"network_interfaces": ifaces("10.0.2.5"),
				"installed_software": sw(
					[3]string{"openssh-server", "1:9.2p1-2+deb12u3", "amd64"},
					[3]string{"fail2ban", "1.0.2-3", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 20480, 5100, 14400}),
				"firewall_av_status": linuxFirewall("active"),
			},
		},
		{
			Name: "legacy01", Platform: "linux", Group: "", Tags: []string{"decommission-candidate"},
			LastCooked: now.Add(-3 * day), age: 400 * day,
			Facts: map[string]map[string]any{
				"system_summary":     linuxSummary("Ubuntu", "18.04.6 LTS", "4.15.0-213-generic", "Intel Xeon E5-2680", 2, 4096, "180 days, 6:40"),
				"network_interfaces": ifaces("10.0.4.55"),
				"installed_software": sw(
					[3]string{"apache2", "2.4.29-1ubuntu4.27", "amd64"},
					[3]string{"php7.2", "7.2.24-0ubuntu0.18.04.17", "amd64"},
				),
				"disk_usage":         disks([4]any{"/dev/sda1", 40960, 38200, 1900}),
				"firewall_av_status": linuxFirewall("inactive"),
				"patch_update_status": pendingUpdates(
					[3]string{"apache2", "2.4.29-1ubuntu4.29", "2.4.29-1ubuntu4.27"},
					[3]string{"openssl", "1.1.1-1ubuntu2.1~18.04.23", "1.1.1-1ubuntu2.1~18.04.21"},
					[3]string{"linux-libc-dev", "4.15.0-213.224", "4.15.0-213.223"},
				),
			},
		},
		{
			Name: "WIN-FIN02", Platform: "windows", Group: "finance", Tags: []string{"desktop"},
			LastCooked: now, age: 150 * day,
			Facts: map[string]map[string]any{
				"system_summary":     windowsSummary("Microsoft Windows 11 Enterprise", "23H2", "22631", "Intel Core i7-1265U", 12, 16384, "2 days, 4:00"),
				"network_interfaces": ifaces("10.0.3.31"),
				"installed_software": winSW(
					[2]string{"Microsoft 365 Apps for Enterprise", "16.0.17425"},
					[2]string{"Adobe Acrobat Reader DC", "24.002.20736"},
				),
				"disk_usage":         winDisks([3]any{"C:", 512000, 289400}),
				"firewall_av_status": winFirewall(true, true, true),
			},
		},
		{
			Name: "WIN-FIN03", Platform: "windows", Group: "finance", Tags: []string{"desktop"},
			LastCooked: now, age: 140 * day,
			Facts: map[string]map[string]any{
				"system_summary":     windowsSummary("Microsoft Windows 11 Enterprise", "23H2", "22631", "Intel Core i7-1265U", 12, 16384, "14 days, 22:10"),
				"network_interfaces": ifaces("10.0.3.32"),
				"installed_software": winSW(
					[2]string{"Microsoft 365 Apps for Enterprise", "16.0.17425"},
					[2]string{"7-Zip", "23.01"},
				),
				"disk_usage":         winDisks([3]any{"C:", 512000, 124800}),
				"firewall_av_status": winFirewall(false, true, true),
			},
		},
		{
			Name: "WIN-ENG01", Platform: "windows", Group: "eng", Tags: []string{"laptop"},
			LastCooked: now, age: 70 * day,
			Facts: map[string]map[string]any{
				"system_summary":     windowsSummary("Microsoft Windows 11 Pro", "23H2", "22631", "Intel Core i9-13900H", 20, 32768, "0 days, 9:45"),
				"network_interfaces": ifaces("10.0.2.101"),
				"installed_software": winSW(
					[2]string{"Visual Studio Code", "1.89.1"},
					[2]string{"Docker Desktop", "4.29.0"},
					[2]string{"Slack", "4.38.125"},
					[2]string{"Zoom Workplace", "6.1.0"},
					[2]string{"JetBrains GoLand 2024.1", "241.14494.238"},
					[2]string{"Webex", "44.6.0"},
					// Shadow AI: OpenAI's official Windows desktop app.
					[2]string{"ChatGPT", "1.2024.112"},
				),
				"disk_usage":         winDisks([3]any{"C:", 1024000, 402100}),
				"firewall_av_status": winFirewall(true, true, true),
				"browser_extensions": exts(
					ext("chrome", "jsmith/Default", "cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin", "1.58.0", 3, []string{"storage", "tabs", "webNavigation", "webRequest"}, []string{"<all_urls>"}, true),
					ext("chrome", "jsmith/Default", "bmnlcjabgnpnenekpadlanbbkooimhnj", "Honey: Automatic Coupons", "16.4.2", 3, []string{"tabs", "cookies", "webRequest", "storage"}, []string{"<all_urls>"}, true),
					ext("chrome", "jsmith/Default", "dbepggeogbaibhgnhhndojpepiihcmeb", "Vimium", "2.1.2", 3, []string{"tabs", "storage"}, []string{"<all_urls>"}, true),
					ext("edge", "jsmith/Default", "nkbihfbeogaeaoehlefnkodbefgpgknn", "Crypto Wallet Helper", "0.9.1", 2, []string{"tabs", "clipboardRead", "nativeMessaging"}, []string{"<all_urls>"}, false),
				),
			},
		},
		{
			Name: "WIN-HR01", Platform: "windows", Group: "hr", Tags: []string{"desktop"},
			LastCooked: now.Add(-4 * day), age: 300 * day,
			Facts: map[string]map[string]any{
				"system_summary":     windowsSummary("Microsoft Windows 10 Enterprise", "22H2", "19045", "Intel Core i5-8500", 6, 8192, "40 days, 1:30"),
				"network_interfaces": ifaces("10.0.3.21"),
				"installed_software": winSW(
					[2]string{"Microsoft 365 Apps for Enterprise", "16.0.17231"},
					[2]string{"Zoom Workplace", "6.1.0"},
					[2]string{"Microsoft Teams", "24165.1414"},
					[2]string{"Adobe Acrobat DC (64-bit)", "24.002.20857"},
					[2]string{"TeamViewer", "15.55.3"},
				),
				"tls_certificates": certsFact(
					certItem("3A5F9C1E2B7D4A6F8C0E1D2B3A4C5D6E7F8A9B0C", "CN=WIN-HR01.corp.example.com", "CN=Example Corp Issuing CA 01", now.Add(300*day)),
				),
				"disk_usage":         winDisks([3]any{"C:", 256000, 61200}),
				"firewall_av_status": winFirewall(false, true, true),
				"browser_extensions": exts(
					ext("chrome", "hr-desk/Default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "PDF Converter Pro", "3.0.4", 2, []string{"tabs", "webRequest", "webRequestBlocking", "history"}, []string{"<all_urls>"}, true),
					ext("chrome", "hr-desk/Default", "ghbmnnjooekpmoecnnnilnnbdlolhkhi", "Google Docs Offline", "1.80.1", 3, []string{"storage", "alarms"}, []string{"https://docs.google.com/*"}, true),
				),
			},
		},
		{
			Name: "mac-eng01", Platform: "darwin", Group: "eng", Tags: []string{"laptop"},
			LastCooked: now, age: 80 * day,
			Facts: map[string]map[string]any{
				"system_summary":     darwinSummary("macOS", "15.6", "24.6.0", "Apple M3 Pro", 12, 18432, "5 days, 2:10"),
				"network_interfaces": ifaces("10.0.2.120"),
			},
		},
		{
			Name: "mac-eng02", Platform: "darwin", Group: "eng", Tags: []string{"laptop"},
			LastCooked: now, age: 45 * day,
			Facts: map[string]map[string]any{
				"system_summary":     darwinSummary("macOS", "14.4.1", "23.4.0", "Apple M2", 8, 16384, "1 day, 19:05"),
				"network_interfaces": ifaces("10.0.2.121"),
			},
		},
		{
			Name: "mac-design01", Platform: "darwin", Group: "design", Tags: []string{"laptop"},
			LastCooked: now, age: 30 * day,
			Facts: map[string]map[string]any{
				"system_summary":     darwinSummary("macOS", "15.6", "24.6.0", "Apple M3 Max", 16, 36864, "0 days, 6:50"),
				"network_interfaces": ifaces("10.0.5.40"),
				"browser_extensions": exts(
					ext("chrome", "aparker/Default", "gfbliohnnapiefjpjlpjnehglfpaknnc", "ColorZilla", "4.0", 3, []string{"storage", "activeTab"}, nil, true),
					ext("chrome", "aparker/Default", "hoklmmgfnpapgjgcpechhaamimifchmp", "WhatFont", "2.1.4", 3, []string{"activeTab"}, nil, true),
					ext("brave", "aparker/Default", "ohmgcmklopdilgcfglpbkbamjlbfmfnh", "Grammarly-style Writing Aid", "14.1", 3, []string{"tabs", "scripting", "storage"}, []string{"<all_urls>"}, true),
				),
			},
		},
	}
}

// demoSoftwareRules seeds one deny rule -- always-enforced regardless of
// scope, so it can't accidentally switch on fleet-wide allowlist
// enforcement the way an "allow" rule would (see
// internal/allowlist.Evaluate's doc comment) -- matching the vsftpd
// package on api01.prod. This is a generic allowlist violation,
// deliberately distinct from the shadow-AI detections above, to
// demonstrate both categories in the compliance/allowlist UI at once.
func demoSoftwareRules() []model.SoftwareRule {
	return []model.SoftwareRule{
		{Name: "Ban vsftpd (deprecated, unencrypted FTP)", Kind: "deny", Match: "vsftpd*"},
	}
}

// demoPolicyRules seeds a few model.Rule policies the background
// evaluator (internal/evaluator) will pick up on its next tick. The one
// with AutoRemediate set also sets RequireApproval, so instead of
// queuing an action no demo agent will ever execute, it parks a
// proposal in the approvals queue -- which is the change-control flow
// worth showing anyway.
func demoPolicyRules() []model.Rule {
	return []model.Rule{
		{Name: "Prod posture floor", Group: "prod", Kind: "score_below", Threshold: 80},
		{Name: "Fleet-wide vulnerability watch", Kind: "vulnerabilities_found"},
		{Name: "Reporting freshness", Kind: "stale"},
		{Name: "Stale hosts: apply pending updates", Kind: "stale", AutoRemediate: "apply-updates", RequireApproval: true},
	}
}

// demoDiscoveredAssets seeds a few network-discovery sightings
// (model.DiscoveredAsset) -- things a cmd/discover sweep found that
// aren't enrolled Muster hosts at all, the "what else is on this
// network" visibility gap discovery closes.
func demoDiscoveredAssets() []model.DiscoveredAsset {
	return []model.DiscoveredAsset{
		{
			Address: "10.0.4.55", OpenPorts: []int{22, 80},
			Banners:   map[string]string{"22": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9", "80": "nginx/1.18.0 (Ubuntu)"},
			ScannedBy: "seed-demo", ScannedCIDR: "10.0.4.0/24",
		},
		{
			Address: "10.0.4.91", OpenPorts: []int{3389},
			Banners:   map[string]string{"3389": "Microsoft Terminal Services"},
			ScannedBy: "seed-demo", ScannedCIDR: "10.0.4.0/24",
		},
		{
			Address: "10.0.4.12", OpenPorts: []int{9100, 515},
			Banners:   map[string]string{"9100": "HP LaserJet M479 JetDirect"},
			ScannedBy: "seed-demo", ScannedCIDR: "10.0.4.0/24",
		},
	}
}
