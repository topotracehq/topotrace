/*******************************************************************************
 * @file         graph_test.go
 * @brief        Tests for the Muster graph package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package graph

import (
	"testing"

	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/policy"
)

func iface(addrs ...string) model.Fact {
	items := []any{}
	for _, a := range addrs {
		items = append(items, map[string]any{"interface": "eth0", "family": "inet", "address": a})
	}
	return model.Fact{Category: "network_interfaces", Data: map[string]any{"items": items}}
}

func TestBuild(t *testing.T) {
	inputs := []compliance.Input{
		{Host: model.Host{Name: "web01", Group: "prod"}, Posture: policy.PostureResult{Score: 100}},
		{Host: model.Host{Name: "db01", Group: "prod"}, Posture: policy.PostureResult{Score: 50}},
		{Host: model.Host{Name: "laptop", Group: "eng"}, Posture: policy.PostureResult{Score: 90}},
	}
	ifaces := map[string]model.Fact{
		"web01": iface("127.0.0.1", "10.0.1.10/24"),
		"db01":  iface("10.0.1.20"),
	}
	assets := []model.DiscoveredAsset{
		{Address: "10.0.1.20", OpenPorts: []int{5432}, ScannedCIDR: "10.0.1.0/24"},
		{Address: "10.0.4.12", OpenPorts: []int{9100}, ScannedCIDR: "10.0.4.0/24"},
	}
	g := Build(inputs, ifaces, assets)
	byID := map[string]Node{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	if byID["net:10.0.1.0/24"].Members != 3 || byID["group:eng"].Members != 1 || byID["net:10.0.4.0/24"].Members != 1 {
		t.Fatalf("hubs: %+v", g.Nodes)
	}
	if byID["host:web01"].Sub != "10.0.1.10" || byID["host:laptop"].Sub != "group eng" {
		t.Fatalf("subs: %+v %+v", byID["host:web01"], byID["host:laptop"])
	}
	sameHost := 0
	for _, e := range g.Edges {
		if e.Kind == "same-host" && e.From == "asset:10.0.1.20" && e.To == "host:db01" {
			sameHost++
		}
	}
	if sameHost != 1 {
		t.Fatalf("expected the discovered db01 address to link to the host: %+v", g.Edges)
	}
	for _, n := range g.Nodes {
		if n.X <= 0 || n.Y <= 0 || n.X >= float64(g.Width) || n.Y >= float64(g.Height) {
			t.Fatalf("node off canvas: %+v", n)
		}
	}
}
