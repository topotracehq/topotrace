/*******************************************************************************
 * @file         visibility_demo.go
 * @brief        Part of the TopoTrace api module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"muster/internal/agenthealth"
	"muster/internal/model"
	"muster/internal/store"
	"muster/internal/store/memstore"
)

type demoVisibilityStore struct {
	store.Store
	now time.Time
}

// The normal store deliberately stamps scan receipt time. Supply historical
// sightings only for this disposable demo store, without changing live storage.
func (d demoVisibilityStore) ListDiscoveredAssets(ctx context.Context) ([]model.DiscoveredAsset, error) {
	assets, err := d.Store.ListDiscoveredAssets(ctx)
	for i := range assets {
		assets[i].DiscoveredAt = d.now.Add(-72 * time.Hour)
		assets[i].LastSeenAt = d.now.Add(-10 * time.Minute)
		if assets[i].Address == "192.0.2.100" {
			assets[i].LastSeenAt = d.now.Add(-48 * time.Hour)
		}
	}
	return assets, err
}

// Each request gets a disposable store. No production facts, actions, audit
// events, or notifications are written, and timestamps stay useful on demo day.
func visibilityDemo(now time.Time) (store.Store, error) {
	st, err := memstore.New("")
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	names := []string{"demo-web-01", "demo-db-01", "demo-laptop-01", "demo-branch-01", "demo-new-01", "demo-legacy-01"}
	ages := []time.Duration{5 * time.Minute, 12 * time.Minute, 3 * time.Hour, 49 * time.Hour, 0, 20 * time.Minute}
	for i, name := range names {
		last := now.Add(-ages[i])
		if i == 4 {
			last = time.Time{}
		}
		if err := st.UpsertHost(ctx, model.Host{Name: name, Platform: "linux", FirstSeen: now.Add(-30 * 24 * time.Hour), LastCooked: last}); err != nil {
			return nil, err
		}
		if i == 4 {
			continue
		}
		put := func(category string, data map[string]any, at time.Time) error {
			_, err := st.UpsertFact(ctx, model.Fact{Host: name, Category: category, Data: data, CookedAt: at})
			return err
		}
		facts := map[string]map[string]any{
			"system_summary":      {"os": "Ubuntu", "distribution_version": "22.04"},
			"installed_software":  {"count": 2, "items": []map[string]any{{"name": "nginx", "version": "1.24.0"}, {"name": "openssl", "version": "3.0.12"}}},
			"firewall_av_status":  {"ufw_status": "active"},
			"patch_update_status": {"count": 0},
			"running_services":    {"nginx": "active"},
			"network_interfaces":  {"items": []map[string]any{{"address": fmt.Sprintf("192.0.2.%d/24", 10+i)}}},
		}
		for category, data := range facts {
			if err := put(category, data, last.Add(-48*time.Hour)); err != nil {
				return nil, err
			}
			if err := put(category, data, last); err != nil {
				return nil, err
			}
		}
		switch i {
		case 0:
			if err := put("system_summary", map[string]any{"os": "Ubuntu", "distribution_version": "24.04"}, last.Add(-time.Hour)); err != nil {
				return nil, err
			}
			if err := put("installed_software", map[string]any{"count": 2, "items": []map[string]any{{"name": "nginx", "version": "1.26.2"}, {"name": "openssl", "version": "3.0.15"}}}, last); err != nil {
				return nil, err
			}
		case 1:
			if err := put("running_services", map[string]any{"nginx": "failed"}, last); err != nil {
				return nil, err
			}
			if err := put("patch_update_status", map[string]any{"count": 12}, last); err != nil {
				return nil, err
			}
		case 2:
			if err := put("firewall_av_status", map[string]any{"ufw_status": "inactive"}, last); err != nil {
				return nil, err
			}
			if err := put("installed_software", facts["installed_software"], now.Add(-48*time.Hour)); err != nil {
				return nil, err
			}
		}
		if i == 5 {
			continue
		}
		record := agenthealth.Record{Host: name, Path: "tcp", Checkins: 42, LastCheckin: last, Intervals: []float64{1800, 1800, 1800}}
		if i == 1 {
			record.Failures = 3
			record.LastFailure = now.Add(-2 * time.Minute)
			record.LastFailureAt = "Collector payload could not be parsed (sample)"
		}
		data, _ := json.Marshal(record)
		if err := st.PutDocument(ctx, model.Document{Kind: agenthealth.Kind, ID: name, Data: data}); err != nil {
			return nil, err
		}
	}
	for i, address := range []string{"192.0.2.10", "192.0.2.80", "192.0.2.90", "192.0.2.100"} {
		last := now.Add(-10 * time.Minute)
		if i == 3 {
			last = now.Add(-48 * time.Hour)
		}
		a, err := st.UpsertDiscoveredAsset(ctx, model.DiscoveredAsset{Address: address, OpenPorts: []int{22, 443}, ScannedBy: "demo-scanner", ScannedCIDR: "192.0.2.0/24", DiscoveredAt: now.Add(-72 * time.Hour), LastSeenAt: last})
		if err != nil {
			return nil, err
		}
		if i == 2 || i == 3 {
			review := assetReview{State: "unauthorized", Reason: "Sample: unapproved remote-access appliance", Actor: "demo-security", UpdatedAt: now.Add(-time.Hour)}
			if i == 3 {
				review.State = "approved"
				review.Reason = "Sample: approved office printer"
			}
			data, _ := json.Marshal(review)
			if err := st.PutDocument(ctx, model.Document{Kind: assetReviewKind, ID: a.ID, Data: data}); err != nil {
				return nil, err
			}
		}
	}
	return demoVisibilityStore{Store: st, now: now}, nil
}
