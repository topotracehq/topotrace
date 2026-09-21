/*******************************************************************************
 * @file         health.go
 * @brief        Part of the TopoTrace webhook module.
 * @project      TopoTrace
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"muster/internal/model"
	"time"
)

const HealthKind = "notification_success"

type Success struct {
	Sink string    `json:"sink"`
	At   time.Time `json:"at"`
}

func (d *Dispatcher) recordSuccess(sink string) {
	if d.store == nil {
		return
	}
	b, _ := json.Marshal(Success{Sink: sink, At: d.now()})
	hash := sha256.Sum256([]byte(sink))
	if err := d.store.PutDocument(context.Background(), model.Document{Kind: HealthKind, ID: hex.EncodeToString(hash[:]), Data: b}); err != nil {
		d.log.Error("recording notification health", "err", err)
	}
}
