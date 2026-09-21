/*******************************************************************************
 * @file         preferences.go
 * @brief        Part of the Muster webhook module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"muster/internal/store"
	"time"
)

const PreferencesKind = "notification_preferences"

type Preferences struct {
	QuietEnabled          bool   `json:"quiet_enabled"`
	QuietStart            int    `json:"quiet_start"`
	QuietEnd              int    `json:"quiet_end"`
	Timezone              string `json:"timezone"`
	DigestMinutes         int    `json:"digest_minutes"`
	EscalationDelayHours  int    `json:"escalation_delay_hours"`
	EscalationRepeatHours int    `json:"escalation_repeat_hours"`
}

func (p Preferences) Validate() error {
	if p.QuietStart < 0 || p.QuietStart > 23 || p.QuietEnd < 0 || p.QuietEnd > 23 || p.QuietEnabled && p.QuietStart == p.QuietEnd {
		return fmt.Errorf("quiet hours must be distinct whole hours from 0 through 23")
	}
	if p.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil {
		return fmt.Errorf("unknown timezone")
	}
	if p.DigestMinutes != 0 && (p.DigestMinutes < 15 || p.DigestMinutes > 1440) {
		return fmt.Errorf("digest interval must be 0 (immediate) or 15–1440 minutes")
	}
	if p.EscalationDelayHours < 0 || p.EscalationDelayHours > 720 || p.EscalationRepeatHours < 0 || p.EscalationRepeatHours > 720 {
		return fmt.Errorf("escalation hours must be 0–720")
	}
	return nil
}
func LoadPreferences(ctx context.Context, st store.Store) (Preferences, error) {
	p := Preferences{Timezone: "UTC"}
	if st == nil {
		return p, nil
	}
	d, ok, err := st.GetDocument(ctx, PreferencesKind, "global")
	if err != nil || !ok {
		return p, err
	}
	err = json.Unmarshal(d.Data, &p)
	if err == nil {
		err = p.Validate()
	}
	return p, err
}

// NextAllowed walks UTC instants so repeated/missing local hours at DST are safe.
func (p Preferences) NextAllowed(at time.Time) time.Time {
	if !p.QuietEnabled {
		return at
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		return at.Add(time.Hour)
	}
	for i := 0; i < 26*60; i++ {
		h := at.In(loc).Hour()
		quiet := h >= p.QuietStart && h < p.QuietEnd
		if p.QuietStart > p.QuietEnd {
			quiet = h >= p.QuietStart || h < p.QuietEnd
		}
		if !quiet {
			return at
		}
		at = at.Truncate(time.Minute).Add(time.Minute)
	}
	return at
}
func (p Preferences) Due(now time.Time) time.Time {
	at := now
	if p.DigestMinutes > 0 {
		d := time.Duration(p.DigestMinutes) * time.Minute
		at = now.Truncate(d).Add(d)
	}
	return p.NextAllowed(at)
}
