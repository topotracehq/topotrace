package history

import (
	"context"
	"testing"
	"time"

	"muster/internal/store/memstore"
)

func TestRecordAndGet(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := Record(ctx, st, "h1", Point{At: now.Add(time.Duration(i) * time.Minute), Posture: 80 + i, Compliance: 100}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Get(ctx, st, "h1")
	if err != nil || len(s.Points) != 3 || s.Points[2].Posture != 82 {
		t.Fatalf("Get: %+v err=%v", s, err)
	}
	if s, _ := Get(ctx, st, "nope"); len(s.Points) != 0 || s.Host != "nope" {
		t.Fatalf("unknown host should give an empty series, got %+v", s)
	}
	all, _ := All(ctx, st)
	if len(all) != 1 || all[0].Host != "h1" {
		t.Fatalf("All: %+v", all)
	}
}

func TestThinKeepsRecentFullResolution(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var pts []Point
	for i := 0; i < 1000; i++ {
		pts = append(pts, Point{At: base.Add(time.Duration(i) * 5 * time.Minute)})
	}
	out := thin(pts, 400)
	if len(out) > 400 {
		t.Fatalf("thin left %d points, want <= 400", len(out))
	}
	if !out[len(out)-1].At.Equal(pts[len(pts)-1].At) {
		t.Fatal("newest point must survive thinning")
	}
	// the newest 200 (max/2) are untouched
	for i := 1; i <= 200; i++ {
		if !out[len(out)-i].At.Equal(pts[len(pts)-i].At) {
			t.Fatalf("recent point %d was thinned", i)
		}
	}
}

func TestFleetRollupAndMTTR(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	// h1: compliant, then falls out for 2 days, then recovers.
	h1 := Series{Host: "h1", Points: []Point{
		{At: now.Add(-6 * day), Posture: 90, Compliance: 100},
		{At: now.Add(-5 * day), Posture: 60, Compliance: 80, Vulns: 1},
		{At: now.Add(-4 * day), Posture: 60, Compliance: 80, Vulns: 1},
		{At: now.Add(-3 * day), Posture: 90, Compliance: 100},
		{At: now.Add(-1 * day), Posture: 90, Compliance: 100},
	}}
	// h2: falls out and never recovers.
	h2 := Series{Host: "h2", Points: []Point{
		{At: now.Add(-6 * day), Posture: 90, Compliance: 100},
		{At: now.Add(-2 * day), Posture: 40, Compliance: 60, Stale: true},
		{At: now.Add(-1 * day), Posture: 40, Compliance: 60, Stale: true},
	}}
	all := []Series{h1, h2}

	buckets := FleetRollup(all, now, 7*day, day)
	if len(buckets) == 0 {
		t.Fatal("expected buckets")
	}
	last := buckets[len(buckets)-1]
	if last.Hosts != 2 || last.AvgPosture != 65 || last.AvgCompliance != 80 || last.StaleHosts != 1 {
		t.Fatalf("last bucket: %+v", last)
	}

	m := TimeToRemediate(all, now, 30*day)
	if m.Resolved != 1 || m.StillOpen != 1 {
		t.Fatalf("mttr: %+v", m)
	}
	if m.MeanHours != 48 || m.MedianHours != 48 {
		t.Fatalf("expected 48h mean/median, got %+v", m)
	}
	if m.OldestOpenHrs != 48 {
		t.Fatalf("expected oldest open 48h, got %v", m.OldestOpenHrs)
	}
}
