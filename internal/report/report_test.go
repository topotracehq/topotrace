/*******************************************************************************
 * @file         report_test.go
 * @brief        Tests for the Muster report package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package report

import (
	"context"
	"strings"
	"testing"
	"time"

	"muster/internal/aiquery"
	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/vuln"
)

func sample() Data {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	inputs := []compliance.Input{
		{Host: model.Host{Name: "a", Platform: "linux", Group: "prod", LastCooked: now}, Posture: policy.PostureResult{Score: 90}},
		{Host: model.Host{Name: "b", Platform: "windows", LastCooked: now}, Posture: policy.PostureResult{Score: 50}, Stale: true,
			VulnFindings: []vuln.Finding{{Package: "bash", Version: "4.3", CVE: "CVE-2014-6271", Severity: "critical", Description: "Shellshock"}}},
	}
	audit := []model.AuditEntry{{ID: "au1", Actor: "master", Action: "x", Detail: "d, with \"quotes\"", CreatedAt: now}}
	return Build(inputs, nil, audit, now)
}

func TestBuildAggregates(t *testing.T) {
	d := sample()
	if d.TotalHosts != 2 || d.AvgPosture != 70 || d.Stale != 1 || d.WithVulns != 1 || len(d.Vulns) != 1 {
		t.Fatalf("%+v", d)
	}
	if d.Hosts[0].Host != "b" {
		t.Fatalf("riskiest host should sort first, got %+v", d.Hosts)
	}
}

func TestCSVExports(t *testing.T) {
	d := sample()
	for _, name := range Names {
		out, err := CSV(d, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) < 2 {
			t.Fatalf("%s: expected header + rows, got %q", name, out)
		}
	}
	audit, _ := CSV(d, "audit")
	if !strings.Contains(string(audit), `"d, with ""quotes"""`) {
		t.Fatalf("audit csv should quote fields: %s", audit)
	}
	if _, err := CSV(d, "nope"); err == nil {
		t.Fatal("unknown export should error")
	}
}

func TestHTMLRenders(t *testing.T) {
	out, err := HTML(sample())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"Fleet posture report", "CVE-2014-6271", "average posture score", "with &#34;quotes&#34;"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in report html", want)
		}
	}
}

func TestTemplateSummary(t *testing.T) {
	d := sample()
	s, err := ExecutiveSummary(context.Background(), aiquery.Config{}, d)
	if err != nil || s.Source != "template" {
		t.Fatalf("%+v %v", s, err)
	}
	for _, want := range []string{"managing 2 hosts", "most in need of attention are b", "Recommended first step: patch the 1 host"} {
		if !strings.Contains(s.Text, want) {
			t.Fatalf("summary missing %q:\n%s", want, s.Text)
		}
	}
}
