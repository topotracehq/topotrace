package license

import (
	"context"
	"encoding/json"
	"testing"

	"topotrace/internal/directory"
	"topotrace/internal/model"
	"topotrace/internal/store/memstore"
)

func TestActiveSeatsCountsOnlyActiveUsers(t *testing.T) {
	ctx := context.Background()
	st, err := memstore.New("")
	if err != nil {
		t.Fatalf("memstore.New: %v", err)
	}

	if _, err := directory.Upsert(ctx, st, directory.User{Email: "a@example.com", Role: "admin", Active: true}); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if _, err := directory.Upsert(ctx, st, directory.User{Email: "b@example.com", Role: "readonly", Active: true}); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if _, err := directory.Upsert(ctx, st, directory.User{Email: "c@example.com", Role: "readonly", Active: false}); err != nil {
		t.Fatalf("upsert c: %v", err)
	}

	active, err := ActiveSeats(ctx, st)
	if err != nil {
		t.Fatalf("ActiveSeats: %v", err)
	}
	if active != 2 {
		t.Fatalf("active = %d, want 2", active)
	}
}

func TestRecordSnapshotThenHistory(t *testing.T) {
	ctx := context.Background()
	st, err := memstore.New("")
	if err != nil {
		t.Fatalf("memstore.New: %v", err)
	}

	if _, err := directory.Upsert(ctx, st, directory.User{Email: "a@example.com", Role: "admin", Active: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	snap, err := RecordSnapshot(ctx, st, 10)
	if err != nil {
		t.Fatalf("RecordSnapshot: %v", err)
	}
	if snap.ActiveUsers != 1 || snap.LicensedSeats != 10 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	hist, err := History(ctx, st, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history len = %d, want 1", len(hist))
	}
	if hist[0].Date != snap.Date {
		t.Fatalf("history date = %s, want %s", hist[0].Date, snap.Date)
	}
}

func TestRecordSnapshotSameDayOverwrites(t *testing.T) {
	ctx := context.Background()
	st, err := memstore.New("")
	if err != nil {
		t.Fatalf("memstore.New: %v", err)
	}

	if _, err := RecordSnapshot(ctx, st, 5); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if _, err := directory.Upsert(ctx, st, directory.User{Email: "new@example.com", Role: "admin", Active: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	snap2, err := RecordSnapshot(ctx, st, 5)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if snap2.ActiveUsers != 1 {
		t.Fatalf("second snapshot active = %d, want 1", snap2.ActiveUsers)
	}

	hist, err := History(ctx, st, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history len = %d, want 1 (same-day snapshot should overwrite)", len(hist))
	}
}

func TestHistoryOrderedNewestFirstAndCapped(t *testing.T) {
	ctx := context.Background()
	st, err := memstore.New("")
	if err != nil {
		t.Fatalf("memstore.New: %v", err)
	}

	dates := []string{"2026-01-01", "2026-01-02", "2026-01-03"}
	for _, d := range dates {
		snap := Snapshot{Date: d, ActiveUsers: 1, LicensedSeats: 5}
		data, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: d, Data: data}); err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	hist, err := History(ctx, st, 2)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history len = %d, want 2", len(hist))
	}
	if hist[0].Date != "2026-01-03" || hist[1].Date != "2026-01-02" {
		t.Fatalf("unexpected order: %+v", hist)
	}
}

func TestNearLimitAndAlertMessage(t *testing.T) {
	if NearLimit(8, 10, NearLimitThresholdPct) {
		t.Fatalf("8/10 should not be near limit at 90%%")
	}
	if !NearLimit(9, 10, NearLimitThresholdPct) {
		t.Fatalf("9/10 should be near limit at 90%%")
	}
	if NearLimit(5, 0, NearLimitThresholdPct) {
		t.Fatalf("unconfigured licensed seats should never be near limit")
	}
	if msg := AlertMessage(9, 10, NearLimitThresholdPct); msg == "" {
		t.Fatalf("expected a non-empty alert message at 9/10")
	}
	if msg := AlertMessage(11, 10, NearLimitThresholdPct); msg == "" {
		t.Fatalf("expected a non-empty alert message when over limit")
	}
	if msg := AlertMessage(5, 10, NearLimitThresholdPct); msg != "" {
		t.Fatalf("expected no alert message at 5/10, got %q", msg)
	}
}
