package operations

import (
	"context"
	"muster/internal/agenthealth"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/store"
	"strings"
	"time"
)

type PreflightHost struct {
	Host     string   `json:"host"`
	Ready    bool     `json:"ready"`
	Blockers []string `json:"blockers"`
	Warnings []string `json:"warnings"`
}
type PreflightResult struct {
	Ready     bool            `json:"ready"`
	Hosts     []PreflightHost `json:"hosts"`
	Impact    string          `json:"impact"`
	Rollback  string          `json:"rollback"`
	CheckedAt time.Time       `json:"checked_at"`
}

func Preflight(ctx context.Context, st store.Store, p Plan, now time.Time) (PreflightResult, error) {
	out := PreflightResult{Ready: true, Hosts: []PreflightHost{}, CheckedAt: now, Impact: "Restarting the selected service can interrupt active connections and dependent applications. Only the pilot runs until you promote the remaining devices.", Rollback: p.RollbackInstructions}
	plans, err := List[Plan](ctx, st, PlanKind)
	if err != nil {
		return out, err
	}
	for _, name := range p.Hosts {
		c := PreflightHost{Host: name, Ready: true, Blockers: []string{}, Warnings: []string{}}
		h, found, err := st.GetHost(ctx, name)
		if err != nil {
			return out, err
		}
		if !found {
			c.Blockers = append(c.Blockers, "Device is no longer in inventory")
		}
		if h.LastCooked.IsZero() || policy.IsStale(h.LastCooked, now) || h.LastCooked.After(now.Add(5*time.Minute)) {
			c.Blockers = append(c.Blockers, "A device report within 24 hours is required")
		}
		health, err := agenthealth.Get(ctx, st, name, now)
		if err != nil {
			return out, err
		}
		if health.State == "failing" || health.State == "late" {
			c.Blockers = append(c.Blockers, "Agent reporting is "+health.State)
		}
		facts, err := st.ListFacts(ctx, name)
		if err != nil {
			return out, err
		}
		by := map[string]model.Fact{}
		for _, f := range facts {
			by[f.Category] = f
		}
		f, ok := by["running_services"]
		serviceFound := false
		if !ok || f.CookedAt.IsZero() || policy.IsStale(f.CookedAt, now) || f.CookedAt.After(now.Add(5*time.Minute)) {
			c.Blockers = append(c.Blockers, "A current service inventory is required")
		} else {
			for _, row := range Items(f.Data["items"]) {
				n, _ := row["name"].(string)
				if strings.EqualFold(strings.TrimSuffix(n, ".service"), strings.TrimSuffix(p.Arg, ".service")) {
					serviceFound = true
					if row["active_state"] != "active" && row["status"] != "Running" {
						c.Warnings = append(c.Warnings, "Service is currently not running")
					}
				}
			}
			if !serviceFound {
				c.Blockers = append(c.Blockers, "Selected service is absent from current inventory")
			}
		}
		if policy.CollectionCoverage(h.Platform, by, now).Percent < 100 {
			c.Warnings = append(c.Warnings, "Some security evidence is missing or outdated")
		}
		actions, err := st.ListActions(ctx, name)
		if err != nil {
			return out, err
		}
		own := map[string]bool{}
		for _, slot := range p.Actions {
			own[slot.ActionID] = true
		}
		for _, a := range actions {
			if a.Status == "" && !own[a.ID] {
				allowed, err := DeliveryAllowed(ctx, st, a, now)
				if err != nil {
					return out, err
				}
				if allowed || a.Delivered {
					c.Blockers = append(c.Blockers, "Another action is pending or awaiting a result")
					break
				}
			}
		}
		for _, other := range plans {
			if other.ID == p.ID || other.Cancelled || other.Status == "completed" || !other.WindowEnd.After(p.WindowStart) || !p.WindowEnd.After(other.WindowStart) {
				continue
			}
			for _, host := range other.Hosts {
				if host == name {
					c.Blockers = append(c.Blockers, "Another scheduled change overlaps this device's window")
					break
				}
			}
		}
		if !p.BackupConfirmed {
			c.Blockers = append(c.Blockers, "Confirm that backups and a recovery path have been checked")
		}
		if len(strings.TrimSpace(p.RollbackInstructions)) < 10 {
			c.Blockers = append(c.Blockers, "Provide recovery instructions of at least 10 characters")
		}
		c.Ready = len(c.Blockers) == 0
		out.Ready = out.Ready && c.Ready
		out.Hosts = append(out.Hosts, c)
	}
	return out, nil
}
