package baseline

import (
	"context"
	"testing"

	"muster/internal/model"
	"muster/internal/store/memstore"
)

func sw(rows ...[2]string) map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{"name": r[0], "version": r[1]})
	}
	return map[string]any{"count": len(items), "items": items}
}

func TestCaptureCompareDelete(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	st.UpsertHost(ctx, model.Host{Name: "h", Platform: "linux"})
	st.UpsertFact(ctx, model.Fact{Host: "h", Category: "installed_software", Data: sw([2]string{"nginx", "1.24"}, [2]string{"curl", "8.5"})})
	st.UpsertFact(ctx, model.Fact{Host: "h", Category: "firewall_av_status", Data: map[string]any{"ufw_status": "active"}})

	if _, err := Capture(ctx, st, "nope", "master", "", nil); err == nil {
		t.Fatal("capturing a host with no facts should fail")
	}
	b, err := Capture(ctx, st, "h", "master", "golden image v3", nil)
	if err != nil || len(b.Facts) != 2 || b.CapturedBy != "master" {
		t.Fatalf("capture: %+v err=%v", b, err)
	}
	rep, err := Compare(ctx, st, "h")
	if err != nil || !rep.HasBaseline || rep.Drifted {
		t.Fatalf("fresh baseline should not drift: %+v err=%v", rep, err)
	}

	// drift: nginx upgraded, curl removed, vim added, firewall off, new category ignored
	st.UpsertFact(ctx, model.Fact{Host: "h", Category: "installed_software", Data: sw([2]string{"nginx", "1.26"}, [2]string{"vim", "9.1"})})
	st.UpsertFact(ctx, model.Fact{Host: "h", Category: "firewall_av_status", Data: map[string]any{"ufw_status": "inactive"}})
	st.UpsertFact(ctx, model.Fact{Host: "h", Category: "listening_ports", Data: map[string]any{"count": 1}})
	rep, _ = Compare(ctx, st, "h")
	if !rep.Drifted || len(rep.Drift) != 4 || rep.ByCategory["installed_software"] != 3 || rep.ByCategory["firewall_av_status"] != 1 {
		t.Fatalf("drift: %+v", rep)
	}
	actions := map[string]string{}
	for _, d := range rep.Drift {
		actions[d.Field] = d.Action
	}
	if actions["curl"] != "remove" || actions["vim"] != "add" || actions["nginx.version"] != "update" || actions["ufw_status"] != "update" {
		t.Fatalf("unexpected drift fields: %+v", actions)
	}

	all, _ := All(ctx, st)
	if len(all) != 1 || all[0].Host != "h" {
		t.Fatalf("All: %+v", all)
	}
	if err := Delete(ctx, st, "h"); err != nil {
		t.Fatal(err)
	}
	rep, _ = Compare(ctx, st, "h")
	if rep.HasBaseline {
		t.Fatal("baseline should be gone")
	}
}

func TestDiffDataHandlesGenericSlices(t *testing.T) {
	old := map[string]any{"count": 1, "items": []any{map[string]any{"name": "a", "version": "1"}}}
	now := map[string]any{"count": 1, "items": []any{map[string]any{"name": "a", "version": "2"}}}
	d := DiffData("x", old, now)
	if len(d) != 1 || d[0].Field != "a.version" || d[0].NewValue != "2" {
		t.Fatalf("%+v", d)
	}
}
