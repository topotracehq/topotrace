package policy

import (
	"muster/internal/model"
	"testing"
	"time"
)

func TestCoverageDistinguishesMissingStaleAndFresh(t *testing.T) {
	now := time.Now().UTC()
	facts := map[string]model.Fact{
		"system_summary":     {Data: map[string]any{"os": "Linux"}, CookedAt: now},
		"installed_software": {Data: map[string]any{"count": 0, "items": []any{}}, CookedAt: now.Add(-25 * time.Hour)},
		"firewall_av_status": {Data: map[string]any{"ufw_status": "permission denied"}, CookedAt: now},
	}
	c := CollectionCoverage("linux", facts, now)
	if c.Percent != 25 || c.Verified != 1 || c.Evidence[1].State != "outdated" || c.Evidence[2].State != "unknown" || c.Evidence[3].CollectedAt != nil {
		t.Fatalf("wrong coverage: %+v", c)
	}
	// A recent host check-in cannot refresh an old category.
	p := ComputePostureAt("linux", facts, false, now)
	if p.Score != 100 || p.Coverage.Percent != 25 {
		t.Fatalf("coverage must qualify the score: %+v", p)
	}
}
func TestWindowsHotfixesDoNotProvePendingUpdates(t *testing.T) {
	now := time.Now().UTC()
	facts := map[string]model.Fact{
		"firewall_av_status":  {Data: map[string]any{"Domain_enabled": "True", "Private_enabled": "True", "Public_enabled": "False"}, CookedAt: now},
		"patch_update_status": {Data: map[string]any{"count": 0, "items": []any{}}, CookedAt: now},
	}
	c := CollectionCoverage("windows", facts, now)
	if c.Evidence[2].State != "verified" || c.Evidence[3].State != "unknown" {
		t.Fatalf("wrong Windows coverage: %+v", c)
	}
	delete(facts["firewall_av_status"].Data, "Domain_enabled")
	if CollectionCoverage("windows", facts, now).Verified != 0 {
		t.Fatal("partial profiles must not be verified")
	}
}
func TestInvalidAndBoundaryEvidenceTimes(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		at   time.Time
		want string
	}{{time.Time{}, "unknown"}, {now.Add(time.Hour), "unknown"}, {now.Add(-24 * time.Hour), "verified"}, {now.Add(-24*time.Hour - time.Second), "outdated"}} {
		c := CollectionCoverage("linux", map[string]model.Fact{"system_summary": {Data: map[string]any{"os": "Linux"}, CookedAt: tc.at}}, now)
		if c.Evidence[0].State != tc.want {
			t.Fatalf("%v: got %s want %s", tc.at, c.Evidence[0].State, tc.want)
		}
	}
}
