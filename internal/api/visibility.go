package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"muster/internal/agenthealth"
	"muster/internal/graph"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/policy"
	"muster/internal/store"
)

const assetReviewKind = "asset_review"

type assetReview struct {
	State     string    `json:"state"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	UpdatedAt time.Time `json:"updated_at"`
}
type visibleAgent struct {
	agenthealth.Status
	Coverage policy.Coverage `json:"coverage"`
}
type visibleAsset struct {
	model.DiscoveredAsset
	State       string       `json:"state"`
	MatchedHost string       `json:"matched_host,omitempty"`
	Stale       bool         `json:"stale"`
	Review      *assetReview `json:"review,omitempty"`
}
type visibilityResult struct {
	Scenario            string                   `json:"scenario,omitempty"`
	Story               string                   `json:"story,omitempty"`
	Before              *operations.Verification `json:"before,omitempty"`
	After               *operations.Verification `json:"after,omitempty"`
	Demo                bool                     `json:"demo"`
	GeneratedAt         time.Time                `json:"generated_at"`
	Agents              []visibleAgent           `json:"agents"`
	Changes             []model.Change           `json:"changes"`
	Assets              []visibleAsset           `json:"assets"`
	DiscoveryRestricted bool                     `json:"discovery_restricted"`
	HistoryLimited      bool                     `json:"history_limited"`
}

// This endpoint joins existing evidence; it never runs a network scan or action.
func (s *Server) handleVisibility(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	now := time.Now().UTC()
	st := s.Store
	demo := r.URL.Query().Get("demo") == "1"
	hosts, err := s.scopedHosts(r)
	if demo {
		st, err = visibilityDemo(now)
		if err == nil {
			hosts, err = st.ListHosts(r.Context())
		}
	}
	if err != nil {
		s.writeError(w, 500, "loading visibility data")
		return
	}
	result, err := buildVisibility(r, st, hosts, now, !demo && s.keyScope(r) != "")
	if err != nil {
		s.writeError(w, 500, "loading visibility evidence")
		return
	}
	result.Demo = demo
	if demo {
		result.Scenario = r.URL.Query().Get("scenario")
		switch result.Scenario {
		case "", "overview":
			result.Scenario = "overview"
		case "unauthorized":
			result.Story = "A new address appears in discovery. An operator verifies it is not approved and records the decision. Review classification does not block the device."
			for i := range result.Assets {
				if result.Assets[i].Address == "192.0.2.80" {
					result.Assets[i].State = "unauthorized"
					result.Assets[i].Review = &assetReview{State: "unauthorized", Reason: "Sample: newly detected unapproved device", Actor: "demo-security", UpdatedAt: now}
				}
			}
		case "failed_change", "recovery":
			a := model.Action{ID: "demo-restart", Host: "demo-web-01", Verb: "restart-service", Arg: "nginx", QueuedAt: now.Add(-20 * time.Minute), Delivered: true, DeliveredAt: now.Add(-19 * time.Minute), ReportedAt: now.Add(-18 * time.Minute), Status: "fail", Detail: "Sample: service restart failed; dependency unavailable"}
			before := operations.Verify(a, nil, now)
			after := before
			result.Story = "The pilot restart failed. Stop the rollout, inspect dependencies, and follow the recorded recovery instructions before attempting another change."
			if result.Scenario == "recovery" {
				a.Status = "ok"
				after = operations.Verify(a, map[string]model.Fact{"running_services": {Host: a.Host, Category: "running_services", CookedAt: now.Add(-time.Minute), Data: map[string]any{"items": []map[string]any{{"name": "nginx", "active_state": "active"}}}}}, now)
				result.Story = "After the operator restores the dependency, the restart succeeds. A newer service report confirms recovery; the original failure remains visible for comparison."
			}
			result.Before = &before
			result.After = &after
		default:
			s.writeError(w, 400, "unknown demo scenario")
			return
		}
	}
	s.writeJSON(w, 200, result)
}

func buildVisibility(r *http.Request, st store.Store, hosts []model.Host, now time.Time, restricted bool) (visibilityResult, error) {
	out := visibilityResult{GeneratedAt: now, Agents: []visibleAgent{}, Changes: []model.Change{}, Assets: []visibleAsset{}, DiscoveryRestricted: restricted}
	addresses := map[string]string{}
	for _, h := range hosts {
		facts, err := st.ListFacts(r.Context(), h.Name)
		if err != nil {
			return out, err
		}
		byCategory := map[string]model.Fact{}
		addresses[strings.ToLower(h.Name)] = h.Name
		for _, f := range facts {
			byCategory[f.Category] = f
			if f.Category == "network_interfaces" && !f.CookedAt.IsZero() && !f.CookedAt.After(now.Add(5*time.Minute)) && now.Sub(f.CookedAt) <= 24*time.Hour {
				for _, ip := range graph.HostAddresses(f, true) {
					addresses[ip] = h.Name
				}
			}
		}
		health, err := agenthealth.Get(r.Context(), st, h.Name, now)
		if err != nil {
			return out, err
		}
		if health.LastCheckin.IsZero() && health.Failures == 0 && !h.LastCooked.IsZero() {
			health.LastCheckin = h.LastCooked
			health.State, health.Detail = "unknown", "Inventory exists, but agent reporting cadence has not been recorded"
			if now.Sub(h.LastCooked) > 24*time.Hour {
				health.State, health.Detail = "missing", "No inventory received in over 24 hours; agent cadence unknown"
			}
		}
		out.Agents = append(out.Agents, visibleAgent{Status: health, Coverage: policy.CollectionCoverage(h.Platform, byCategory, now)})
		changes, err := st.ListChanges(r.Context(), h.Name, 101)
		if err != nil {
			return out, err
		}
		if len(changes) > 100 {
			changes = changes[:100]
			out.HistoryLimited = true
		}
		out.Changes = append(out.Changes, changes...)
	}
	sort.SliceStable(out.Changes, func(i, j int) bool { return out.Changes[i].ChangedAt.After(out.Changes[j].ChangedAt) })
	if len(out.Changes) > 1000 {
		out.Changes = out.Changes[:1000]
		out.HistoryLimited = true
	}
	rank := map[string]int{"failing": 0, "missing": 1, "late": 2, "never": 3, "unknown": 4, "healthy": 5}
	sort.SliceStable(out.Agents, func(i, j int) bool { return rank[out.Agents[i].State] < rank[out.Agents[j].State] })
	// Discovery has no ownership scope. Do not expose global addresses to group keys.
	if restricted {
		return out, nil
	}
	assets, err := st.ListDiscoveredAssets(r.Context())
	if err != nil {
		return out, err
	}
	for _, a := range assets {
		v := visibleAsset{DiscoveredAsset: a, State: "needs_review", Stale: a.LastSeenAt.IsZero() || now.Sub(a.LastSeenAt) > 24*time.Hour}
		if host := addresses[strings.ToLower(a.Address)]; host != "" {
			v.State, v.MatchedHost = "managed", host
		}
		doc, found, err := st.GetDocument(r.Context(), assetReviewKind, a.ID)
		if err != nil {
			return out, err
		}
		if found {
			var review assetReview
			if err := json.Unmarshal(doc.Data, &review); err != nil {
				return out, err
			}
			v.Review = &review
			if v.State != "managed" {
				v.State = review.State
			}
		}
		out.Assets = append(out.Assets, v)
	}
	return out, nil
}

func (s *Server) handleAssetReview(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	if s.keyScope(r) != "" {
		s.writeError(w, 403, "Discovery review requires an unscoped administrator")
		return
	}
	var review assetReview
	if !s.workflowBody(w, r, &review) {
		return
	}
	review.Reason = strings.TrimSpace(review.Reason)
	if (review.State != "approved" && review.State != "unauthorized" && review.State != "needs_review") || len(review.Reason) < 3 || len(review.Reason) > 1000 {
		s.writeError(w, 400, "Choose approved, unauthorized, or needs_review and provide a reason (3–1000 characters)")
		return
	}
	assets, err := s.Store.ListDiscoveredAssets(r.Context())
	if err != nil {
		s.writeError(w, 500, "loading discovered devices")
		return
	}
	found := false
	for _, a := range assets {
		if a.ID == r.PathValue("id") {
			found = true
			break
		}
	}
	if !found {
		s.writeError(w, 404, "discovered device not found")
		return
	}
	review.Actor, review.UpdatedAt = actor, time.Now().UTC()
	data, _ := json.Marshal(review)
	if err := s.Store.PutDocument(r.Context(), model.Document{Kind: assetReviewKind, ID: r.PathValue("id"), Data: data}); err != nil {
		s.writeError(w, 500, "saving device review")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "asset-review", r.PathValue("id"), review.State+": "+review.Reason); err != nil {
		s.log().Error("recording device review audit", "err", err)
	}
	s.writeJSON(w, 200, review)
}
