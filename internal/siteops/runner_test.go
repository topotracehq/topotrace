/*******************************************************************************
 * @file         runner_test.go
 * @brief        Tests for the TopoTrace siteops package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package siteops

import (
	"context"
	"strings"
	"testing"
)

func TestWorkerRejectsUnapprovedTargetsBeforeNetwork(t *testing.T) {
	c := Config{AllowedCIDRs: []string{"192.0.2.0/24"}}
	j := Job{Name: "scan", WorkerID: "site", Kind: "scan", CIDR: "198.51.100.0/24", Ports: []int{22}}
	if _, e := Run(context.Background(), c, Task{Job: j}); e == nil {
		t.Fatal("scan outside allowlist accepted")
	}
	j.CIDR = "0.0.0.0/0"
	if e := j.Validate(); e == nil {
		t.Fatal("unbounded scan accepted")
	}
}
func TestInstallerSeparatesPreflightAndInstall(t *testing.T) {
	j := Job{Name: "deploy", WorkerID: "site", Kind: "deploy", Platform: "linux", Profile: "local", TopoTraceHost: "topotrace.test", TopoTracePort: 9090, Pilot: 1, Targets: []Target{{Address: "192.0.2.1", Host: "test"}}, Phase: "preflight"}
	task := Task{Job: j, Target: j.Targets[0]}
	s, e := InstallScript(task)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(s, "mkdir ") || strings.Contains(s, "enable --now") {
		t.Fatal("preflight mutates host")
	}
	task.Job.Phase = "pilot"
	task.Token = strings.Repeat("a", 43)
	s, e = InstallScript(task)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"umask 077", "test ! -e /opt/topotrace-site-agent", "--host-name test", "start --no-block"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing install control", v)
		}
	}
	task.Target.Host = "bad; command"
	if _, e = InstallScript(task); e == nil {
		t.Fatal("command injection accepted")
	}
	task.Target.Host = "test"
	task.Job.Platform = "windows"
	s, e = InstallScript(task)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"SetAccessRuleProtection", "SYSTEM", "Start-ScheduledTask"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing Windows control", v)
		}
	}
}
