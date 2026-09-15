package pgstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// testDSN returns the Postgres connection string to test against, or
// skips the test. Point MUSTER_TEST_POSTGRES_DSN at a scratch database --
// these tests create and drop their own tables at the start of each run,
// so don't point it at anything with data you care about.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MUSTER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MUSTER_TEST_POSTGRES_DSN not set; skipping pgstore integration tests")
	}
	return dsn
}

// newTestStore opens a Store against a clean slate: it drops and
// recreates the three tables so every test starts from an empty database,
// then closes the connection pool on test cleanup.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	dsn := testDSN(t)

	prep, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New (prep): %v", err)
	}
	if _, err := prep.db.ExecContext(ctx, `DROP TABLE IF EXISTS changes, facts, hosts CASCADE`); err != nil {
		prep.Close()
		t.Fatalf("resetting schema: %v", err)
	}
	prep.Close()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUpsertAndGetHost(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, ok, err := s.GetHost(ctx, "h1"); err != nil || ok {
		t.Fatalf("GetHost on empty store: ok=%v err=%v", ok, err)
	}

	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost (insert): %v", err)
	}
	h, ok, err := s.GetHost(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("GetHost: ok=%v err=%v", ok, err)
	}
	if h.Platform != "linux" || h.FirstSeen.IsZero() {
		t.Fatalf("unexpected host after insert: %+v", h)
	}
	firstSeen := h.FirstSeen

	// Re-upsert with a LastCooked timestamp and no FirstSeen -- FirstSeen
	// must stick, matching memstore's semantics.
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux", LastCooked: now}); err != nil {
		t.Fatalf("UpsertHost (update): %v", err)
	}
	h, ok, err = s.GetHost(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("GetHost after update: ok=%v err=%v", ok, err)
	}
	if !h.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen changed on update: got %v, want %v", h.FirstSeen, firstSeen)
	}
	if !h.LastCooked.Equal(now) {
		t.Fatalf("LastCooked not updated: got %v, want %v", h.LastCooked, now)
	}
}

func TestListHostsSorted(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"zebra", "apple", "mango"} {
		if err := s.UpsertHost(ctx, model.Host{Name: name, Platform: "linux"}); err != nil {
			t.Fatalf("UpsertHost(%s): %v", name, err)
		}
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}
	want := []string{"apple", "mango", "zebra"}
	for i, h := range hosts {
		if h.Name != want[i] {
			t.Fatalf("hosts not sorted: got %v, want %v", namesOf(hosts), want)
		}
	}
}

func namesOf(hosts []model.Host) []string {
	out := make([]string, len(hosts))
	for i, h := range hosts {
		out[i] = h.Name
	}
	return out
}

func TestUpsertFactTracksChanges(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	changes, err := s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Ubuntu", "num_cpus": float64(2)},
	})
	if err != nil {
		t.Fatalf("UpsertFact (initial): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes on first report, got %v", changes)
	}

	changes, err = s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Fedora", "num_cpus": float64(2), "memory_mb": float64(4096)},
	})
	if err != nil {
		t.Fatalf("UpsertFact (update): %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d: %v", len(changes), changes)
	}

	fact, ok, err := s.GetFact(ctx, "h1", "system_summary")
	if err != nil || !ok {
		t.Fatalf("GetFact: ok=%v err=%v", ok, err)
	}
	if fact.Data["distribution"] != "Fedora" {
		t.Fatalf("stored fact not updated: %v", fact.Data)
	}
}

func TestQueryMatchesSubstringCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})
	_ = s.UpsertHost(ctx, model.Host{Name: "h2", Platform: "linux"})
	if _, err := s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Ubuntu 22.04"},
	}); err != nil {
		t.Fatalf("UpsertFact h1: %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{
		Host: "h2", Category: "system_summary",
		Data: map[string]any{"distribution": "Fedora 39"},
	}); err != nil {
		t.Fatalf("UpsertFact h2: %v", err)
	}

	matches, err := s.Query(ctx, "system_summary", "distribution", "ubuntu")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(matches) != 1 || matches[0].Host != "h1" {
		t.Fatalf("expected 1 match on h1, got %v", matches)
	}
}

func TestQueryReturnsEmptySliceNotNil(t *testing.T) {
	// Same regression this project's memstore already guards against:
	// json.Marshal(nil slice) is `null`, which breaks the web UI's
	// `matches.map(...)` on an empty search result.
	ctx := context.Background()
	s := newTestStore(t)

	matches, err := s.Query(ctx, "system_summary", "distribution", "nonexistent")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if matches == nil {
		t.Fatal("Query returned nil slice, want non-nil empty slice")
	}

	facts, err := s.ListFacts(ctx, "no-such-host")
	if err != nil {
		t.Fatalf("ListFacts: %v", err)
	}
	if facts == nil {
		t.Fatal("ListFacts returned nil slice, want non-nil empty slice")
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if hosts == nil {
		t.Fatal("ListHosts returned nil slice, want non-nil empty slice")
	}
}

// QueryLikeMetacharacters is a literal substring match (matching
// memstore's strings.Contains), not a glob -- a host whose data contains
// a literal "%" shouldn't turn into an accidental wildcard.
func TestQueryEscapesLikeMetacharacters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})
	if _, err := s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"note": "100% disk free"},
	}); err != nil {
		t.Fatalf("UpsertFact: %v", err)
	}

	matches, err := s.Query(ctx, "system_summary", "note", "100%")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected literal '100%%' to match, got %d results", len(matches))
	}

	matches, err = s.Query(ctx, "system_summary", "note", "100x")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no results for a pattern that isn't actually present, got %d", len(matches))
	}
}

func TestSetHostGroupAndTags(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.SetHostGroup(ctx, "no-such-host", "prod"); !errors.Is(err, store.ErrHostNotFound) {
		t.Fatalf("SetHostGroup on unknown host: got %v, want ErrHostNotFound", err)
	}

	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	h, err := s.SetHostGroup(ctx, "h1", "prod")
	if err != nil {
		t.Fatalf("SetHostGroup: %v", err)
	}
	if h.Group != "prod" {
		t.Fatalf("SetHostGroup didn't stick: %+v", h)
	}

	h, err = s.SetHostTags(ctx, "h1", []string{"needs-patching", "east-dc"})
	if err != nil {
		t.Fatalf("SetHostTags: %v", err)
	}
	if len(h.Tags) != 2 || h.Tags[0] != "needs-patching" {
		t.Fatalf("SetHostTags didn't stick: %+v", h)
	}

	// A re-cook (UpsertHost, as the pipeline calls it, with no Group/Tags
	// set) must not clobber the group/tags an operator assigned -- the
	// hosts table's group_name/tags columns are outside UpsertHost's
	// INSERT/ON CONFLICT SET column lists entirely.
	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost (re-cook): %v", err)
	}
	h, _, err = s.GetHost(ctx, "h1")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Group != "prod" || len(h.Tags) != 2 {
		t.Fatalf("re-cook clobbered group/tags: %+v", h)
	}
}

func TestListChanges(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})
	_ = s.UpsertHost(ctx, model.Host{Name: "h2", Platform: "linux"})

	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"distribution": "Ubuntu"}}); err != nil {
		t.Fatalf("UpsertFact h1 (initial): %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"distribution": "Fedora"}}); err != nil {
		t.Fatalf("UpsertFact h1 (update): %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h2", Category: "system_summary", Data: map[string]any{"distribution": "Ubuntu"}}); err != nil {
		t.Fatalf("UpsertFact h2 (initial): %v", err)
	}

	changes, err := s.ListChanges(ctx, "h1", 0)
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if len(changes) != 1 || changes[0].Field != "distribution" {
		t.Fatalf("expected 1 change for h1, got %v", changes)
	}

	none, err := s.ListChanges(ctx, "no-such-host", 0)
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("expected non-nil empty slice for unknown host, got %v", none)
	}
}

func TestListChangesRespectsLimit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})

	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"a": "1", "b": "1", "c": "1"}}); err != nil {
		t.Fatalf("UpsertFact (initial): %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"a": "2", "b": "2", "c": "2"}}); err != nil {
		t.Fatalf("UpsertFact (update): %v", err)
	}

	changes, err := s.ListChanges(ctx, "h1", 2)
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected limit=2 to cap results at 2, got %d", len(changes))
	}
}
