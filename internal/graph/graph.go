/*******************************************************************************
 * @file         graph.go
 * @brief        Package graph builds the network/asset relationship picture the dashboard draws: managed hosts and discovered-but-unmanaged assets as nodes, grouped by the subnet they sit on (from network_interfaces facts and discovery sweeps' CIDRs) an...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package graph builds the network/asset relationship picture the
// dashboard draws: managed hosts and discovered-but-unmanaged assets
// as nodes, grouped by the subnet they sit on (from network_interfaces
// facts and discovery sweeps' CIDRs) and, for hosts with no reported
// interface, by their board group -- so "what's on the 10.0.4.0/24
// network that we don't manage, next to what we do" is one picture
// instead of two lists. Layout is computed here too (deterministic,
// no physics), so the client only draws.
package graph

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"

	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/risk"
)

// Node is one drawable thing.
type Node struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"` // "hub" (subnet or group), "host", "asset"
	Label    string  `json:"label"`
	Sub      string  `json:"sub,omitempty"`   // second line: IP / ports / group
	Level    string  `json:"level,omitempty"` // risk level for hosts; "unknown" for assets
	Score    int     `json:"score,omitempty"`
	Href     string  `json:"href,omitempty"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Members  int     `json:"members,omitempty"`
	Platform string  `json:"platform,omitempty"`
}

// Edge joins a node to its hub, or a discovered asset to the managed
// host it turned out to be.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "member", "same-host"
}

// Graph is the whole picture plus the canvas size it was laid out for.
type Graph struct {
	Nodes  []Node `json:"nodes"`
	Edges  []Edge `json:"edges"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// HostAddresses pulls IPv4 addresses out of a network_interfaces fact,
// skipping loopback.
func HostAddresses(fact model.Fact, ok bool) []string {
	if !ok {
		return nil
	}
	var list []map[string]any
	switch t := fact.Data["items"].(type) {
	case []map[string]any:
		list = t
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				list = append(list, m)
			}
		}
	}
	var out []string
	for _, m := range list {
		addr, _ := m["address"].(string)
		addr = strings.SplitN(addr, "/", 2)[0]
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// subnetOf returns the /24 an IPv4 address sits in.
func subnetOf(addr string) string {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// Build assembles the graph. inputs carry each managed host's signals
// (for the risk level); interfaces maps host name -> its
// network_interfaces fact (absent is fine).
func Build(inputs []compliance.Input, interfaces map[string]model.Fact, assets []model.DiscoveredAsset) Graph {
	type member struct {
		node Node
	}
	hubs := map[string][]Node{} // hub id -> member nodes
	hubKind := map[string]string{}
	var edges []Edge
	hostByAddr := map[string]string{}

	for _, in := range inputs {
		r := risk.Compute(in)
		n := Node{ID: "host:" + in.Host.Name, Kind: "host", Label: in.Host.Name, Level: r.Level, Score: r.Score,
			Href: "#/host/" + in.Host.Name, Platform: in.Host.Platform}
		f, ok := interfaces[in.Host.Name]
		addrs := HostAddresses(f, ok)
		hubID := ""
		if len(addrs) > 0 {
			n.Sub = addrs[0]
			hubID = "net:" + subnetOf(addrs[0])
			hubKind[hubID] = "subnet"
			for _, a := range addrs {
				hostByAddr[a] = in.Host.Name
			}
		} else if in.Host.Group != "" {
			n.Sub = "group " + in.Host.Group
			hubID = "group:" + in.Host.Group
			hubKind[hubID] = "group"
		} else {
			n.Sub = "ungrouped"
			hubID = "group:(none)"
			hubKind[hubID] = "group"
		}
		hubs[hubID] = append(hubs[hubID], n)
	}
	for _, a := range assets {
		n := Node{ID: "asset:" + a.Address, Kind: "asset", Label: a.Address, Level: "unknown"}
		ports := make([]string, 0, len(a.OpenPorts))
		for _, p := range a.OpenPorts {
			ports = append(ports, fmt.Sprint(p))
		}
		if len(ports) > 0 {
			n.Sub = "ports " + strings.Join(ports, ", ")
		}
		hubID := "net:" + a.ScannedCIDR
		if a.ScannedCIDR == "" {
			hubID = "net:" + subnetOf(a.Address)
		}
		if hubID == "net:" {
			hubID = "net:(unknown)"
		}
		hubKind[hubID] = "subnet"
		hubs[hubID] = append(hubs[hubID], n)
		if h, ok := hostByAddr[a.Address]; ok || a.Known {
			target := h
			if target == "" {
				target = a.Address
			}
			edges = append(edges, Edge{From: n.ID, To: "host:" + target, Kind: "same-host"})
			n.Level = "known"
		}
	}

	// layout: hubs on a ring, members on a smaller ring around each hub
	hubIDs := make([]string, 0, len(hubs))
	for id := range hubs {
		hubIDs = append(hubIDs, id)
	}
	sort.Strings(hubIDs)
	g := Graph{Width: 960, Height: 700, Nodes: []Node{}, Edges: []Edge{}}
	cx, cy := float64(g.Width)/2, float64(g.Height)/2
	ringR := 210.0
	if len(hubIDs) == 1 {
		ringR = 0
	}
	for i, id := range hubIDs {
		angle := 2 * math.Pi * float64(i) / float64(len(hubIDs))
		hx, hy := cx+ringR*math.Cos(angle), cy+ringR*math.Sin(angle)
		members := hubs[id]
		sort.Slice(members, func(a, b int) bool { return members[a].Label < members[b].Label })
		hub := Node{ID: id, Kind: "hub", Label: strings.TrimPrefix(strings.TrimPrefix(id, "net:"), "group:"), Sub: hubKind[id], X: hx, Y: hy, Members: len(members)}
		g.Nodes = append(g.Nodes, hub)
		mr := 62.0 + 9*float64(len(members))
		if mr > 120 {
			mr = 120
		}
		for j, m := range members {
			ma := angle + 2*math.Pi*float64(j)/float64(len(members)) + math.Pi/float64(len(members))
			m.X, m.Y = hx+mr*math.Cos(ma), hy+mr*math.Sin(ma)
			g.Nodes = append(g.Nodes, m)
			g.Edges = append(g.Edges, Edge{From: m.ID, To: id, Kind: "member"})
		}
	}
	g.Edges = append(g.Edges, edges...)
	return g
}
