/*******************************************************************************
 * @file         diff.go
 * @brief        Part of the TopoTrace store module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package store

import (
	"fmt"
	"sort"
	"time"

	"muster/internal/model"
)

// Diff walks two fact data maps and records an Add/Remove/Update change per
// leaf field that differs. Nested maps are walked recursively so a category
// whose data has a sub-object still gets field-level change records rather
// than one opaque "the whole category changed" entry.
//
// Shared by every Store implementation (memstore, pgstore, ...) so that
// "what changed since last cook" means the same thing regardless of which
// backend is storing the result.
func Diff(host, category string, oldData, newData map[string]any) []model.Change {
	var out []model.Change
	walkDiff(host, category, "", oldData, newData, &out)
	return out
}

func walkDiff(host, category, path string, oldData, newData map[string]any, out *[]model.Change) {
	seen := make(map[string]bool)

	keys := make([]string, 0, len(oldData)+len(newData))
	for k := range oldData {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range newData {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		fieldPath := key
		if path != "" {
			fieldPath = path + "." + key
		}
		oldVal, hadOld := oldData[key]
		newVal, hasNew := newData[key]

		switch {
		case hadOld && !hasNew:
			*out = append(*out, model.Change{
				Host: host, Category: category, Field: fieldPath,
				OldValue: fmt.Sprintf("%v", oldVal), Action: "remove",
			})
		case !hadOld && hasNew:
			*out = append(*out, model.Change{
				Host: host, Category: category, Field: fieldPath,
				NewValue: fmt.Sprintf("%v", newVal), Action: "add",
			})
		default:
			oldMap, oldIsMap := oldVal.(map[string]any)
			newMap, newIsMap := newVal.(map[string]any)
			if oldIsMap && newIsMap {
				walkDiff(host, category, fieldPath, oldMap, newMap, out)
				continue
			}
			if fmt.Sprintf("%v", oldVal) != fmt.Sprintf("%v", newVal) {
				*out = append(*out, model.Change{
					Host: host, Category: category, Field: fieldPath,
					OldValue: fmt.Sprintf("%v", oldVal),
					NewValue: fmt.Sprintf("%v", newVal),
					Action:   "update",
				})
			}
		}
	}
}

// WithTimestamp stamps every change with at, defaulting to now (UTC) when
// at is the zero value -- e.g. when a cook run didn't set Fact.CookedAt.
func WithTimestamp(changes []model.Change, at time.Time) []model.Change {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	for i := range changes {
		changes[i].ChangedAt = at
	}
	return changes
}
