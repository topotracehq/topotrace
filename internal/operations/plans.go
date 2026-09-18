package operations

import (
	"context"
	"fmt"
	"time"

	"muster/internal/model"
	"muster/internal/remediate"
	"muster/internal/store"
)

type PlanAction struct {
	Host      string    `json:"host"`
	ActionID  string    `json:"action_id"`
	StartedAt time.Time `json:"started_at"`
}
type Plan struct {
	RequirePreflight     bool         `json:"require_preflight"`
	BackupConfirmed      bool         `json:"backup_confirmed"`
	RollbackInstructions string       `json:"rollback_instructions"`
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	Hosts                []string     `json:"hosts"`
	Verb                 string       `json:"verb"`
	Arg                  string       `json:"arg"`
	PilotCount           int          `json:"pilot_count"`
	WindowStart          time.Time    `json:"window_start"`
	WindowEnd            time.Time    `json:"window_end"`
	Promoted             bool         `json:"promoted"`
	Cancelled            bool         `json:"cancelled"`
	CreatedBy            string       `json:"created_by"`
	Actions              []PlanAction `json:"actions"`
	Status               string       `json:"status"`
}

func (p Plan) Validate(ctx context.Context, st store.Store, now time.Time) error {
	if len(p.RollbackInstructions) > 4000 {
		return fmt.Errorf("recovery instructions must be under 4,000 characters")
	}
	if p.Name == "" || len(p.Name) > 200 || len(p.Hosts) == 0 || len(p.Hosts) > 100 {
		return fmt.Errorf("name and 1–100 hosts are required")
	}
	if p.PilotCount < 1 || p.PilotCount > len(p.Hosts) {
		return fmt.Errorf("pilot count must be between 1 and the host count")
	}
	if p.WindowStart.IsZero() || !p.WindowEnd.After(p.WindowStart) || !p.WindowEnd.After(now) || p.WindowEnd.Sub(p.WindowStart) > 24*time.Hour {
		return fmt.Errorf("provide a future maintenance window of at most 24 hours")
	}
	seen := map[string]bool{}
	for _, host := range p.Hosts {
		if seen[host] {
			return fmt.Errorf("duplicate host %q", host)
		}
		seen[host] = true
		h, ok, err := st.GetHost(ctx, host)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("unknown host %q", host)
		}
		if err := remediate.Validate(h.Platform, p.Verb, p.Arg); err != nil {
			return err
		}
		if !remediate.Verbs[p.Verb].Implemented {
			return fmt.Errorf("action is not implemented")
		}
	}
	return nil
}

func PlanChecks(ctx context.Context, st store.Store, p Plan, now time.Time) ([]Verification, error) {
	out := []Verification{}
	for _, slot := range p.Actions {
		actions, err := st.ListActions(ctx, slot.Host)
		if err != nil {
			return nil, err
		}
		facts, err := st.ListFacts(ctx, slot.Host)
		if err != nil {
			return nil, err
		}
		byCategory := map[string]model.Fact{}
		for _, f := range facts {
			byCategory[f.Category] = f
		}
		v := Verification{Host: slot.Host, State: "dispatch_uncertain", Detail: "Dispatch was interrupted; inspect action history before creating another change"}
		for _, a := range actions {
			if a.ID == slot.ActionID {
				v = Verify(a, byCategory, now)
				break
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func PilotVerified(ctx context.Context, st store.Store, p Plan, now time.Time) (bool, error) {
	v, err := PlanChecks(ctx, st, p, now)
	if err != nil {
		return false, err
	}
	if len(v) < p.PilotCount {
		return false, nil
	}
	for _, check := range v[:p.PilotCount] {
		if check.State != "verified" {
			return false, nil
		}
	}
	return true, nil
}

// AdvancePlans is called with Mu held. A durable intent precedes each queue
// write; interrupted dispatch is held for inspection, never retried blindly.
func AdvancePlans(ctx context.Context, st store.Store, now time.Time) error {
	plans, err := List[Plan](ctx, st, PlanKind)
	if err != nil {
		return err
	}
	for _, p := range plans {
		if p.Cancelled {
			continue
		}
		if now.Before(p.WindowStart) {
			continue
		}
		if !now.Before(p.WindowEnd) {
			if p.Status != "completed" {
				p.Status = "window_closed"
				checks, err := PlanChecks(ctx, st, p, now)
				if err != nil {
					return err
				}
				complete := len(checks) == len(p.Hosts)
				for _, check := range checks {
					if check.State != "verified" {
						complete = false
					}
				}
				if complete {
					p.Status = "completed"
				}
			}
			if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
				return err
			}
			continue
		}
		limit := p.PilotCount
		if p.Promoted {
			if len(p.Actions) < len(p.Hosts) {
				verified, err := PilotVerified(ctx, st, p, now)
				if err != nil {
					return err
				}
				if !verified {
					p.Status = "needs_attention"
					if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
						return err
					}
					continue
				}
			}
			limit = len(p.Hosts)
		}
		uncertain := false
		for _, a := range p.Actions {
			if a.ActionID == "" {
				uncertain = true
			}
		}
		if uncertain {
			continue
		}
		blocked := false
		for len(p.Actions) < limit {
			i := len(p.Actions)
			if p.RequirePreflight {
				single := p
				single.Hosts = []string{p.Hosts[i]}
				check, err := Preflight(ctx, st, single, now)
				if err != nil {
					return err
				}
				if !check.Ready {
					p.Status = "preflight_blocked"
					if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
						return err
					}
					blocked = true
					break
				}
			}
			p.Actions = append(p.Actions, PlanAction{Host: p.Hosts[i], StartedAt: now})
			p.Status = "dispatching"
			if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
				return err
			}
			a, err := st.QueueAction(ctx, p.Hosts[i], p.Verb, p.Arg)
			if err != nil {
				return err
			}
			p.Actions[i].ActionID = a.ID
			if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
				return err
			}
		}
		if blocked {
			continue
		}
		p.Status = "pilot_running"
		if p.Promoted {
			p.Status = "rollout_running"
		}
		checks, err := PlanChecks(ctx, st, p, now)
		if err != nil {
			return err
		}
		all := len(checks) == limit
		for _, v := range checks {
			if v.State != "verified" {
				all = false
			}
			if v.State == "failed" || v.State == "timed_out" {
				p.Status = "needs_attention"
			}
		}
		if all {
			p.Status = "awaiting_promotion"
			if limit == len(p.Hosts) {
				p.Status = "completed"
			}
		}
		if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
			return err
		}
	}
	return nil
}

// DeliveryAllowed enforces a plan's window at actual agent check-in, not only
// when queued. Cancellation stops undelivered work; already sent work cannot be recalled.
func DeliveryAllowed(ctx context.Context, st store.Store, a model.Action, now time.Time) (bool, error) {
	plans, err := List[Plan](ctx, st, PlanKind)
	if err != nil {
		return false, err
	}
	for _, p := range plans {
		for _, slot := range p.Actions {
			if slot.ActionID == a.ID {
				return !p.Cancelled && !now.Before(p.WindowStart) && now.Before(p.WindowEnd), nil
			}
			if slot.ActionID == "" && a.Host == slot.Host && a.Verb == p.Verb && a.Arg == p.Arg && !a.QueuedAt.Before(slot.StartedAt) {
				return false, nil
			}
		}
	}
	return true, nil
}
