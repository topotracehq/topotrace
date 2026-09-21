/*******************************************************************************
 * @file         main.go
 * @brief        Command demoagent is a minimal stand-in for a real Muster agent: it tars+gzips a directory of already-captured text files and pushes them to the ingest daemon over the MUSTER1 protocol.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command demoagent is a minimal stand-in for a real Muster agent: it
// tars+gzips a directory of already-captured text files and pushes them
// to the ingest daemon over the MUSTER1 protocol. This is a test/demo
// client, not a real agent -- per the project's current scope, real
// per-platform agents (the things that would actually run `cat
// /proc/cpuinfo` etc. on a managed host) are a later, separate piece of
// work. This just proves the ingest -> cook -> store -> API path end to
// end without needing one yet.
//
//	go run ./cmd/demoagent -addr localhost:9090 -platform linux -host demo01 -dir ./testdata/linux-demo-host
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

func main() {
	addr := flag.String("addr", "localhost:9090", "ingest daemon address")
	platform := flag.String("platform", "linux", "platform name")
	host := flag.String("host", "demo01", "host name to report as")
	dir := flag.String("dir", "./testdata/linux-demo-host", "directory of capture files to package and send")
	token := flag.String("token", "", "shared secret to send, matching the server's -auth-token if it has one; empty sends the no-token sentinel")
	flag.Parse()

	tok := *token
	if tok == "" {
		tok = "-"
	}

	payload, err := packDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packing capture dir:", err)
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dialing ingest daemon:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "MUSTER1 %s %s %s %d\n", *platform, *host, tok, payload.Len())
	if _, err := conn.Write(payload.Bytes()); err != nil {
		fmt.Fprintln(os.Stderr, "sending payload:", err)
		os.Exit(1)
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "reading reply:", err)
		os.Exit(1)
	}
	fmt.Print(reply)
}

// packDir tars+gzips every regular file directly inside dir (non-recursive
// -- Muster's capture contract is a flat set of files per snapshot).
func packDir(dir string) (*bytes.Buffer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: e.Name(),
			Mode: 0o644,
			Size: int64(len(data)),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}
