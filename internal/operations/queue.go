package operations

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"muster/internal/alerts"
	"muster/internal/compliance"
	"muster/internal/policy"
	"muster/internal/risk"
	"muster/internal/store"
)

type WorkItem struct {
	ID             string          `json:"id"`
	Host           string          `json:"host"`
	Kind           string          `json:"kind"`
	Title          string          `json:"title"`
	Evidence       string          `json:"evidence"`
	Recommendation string          `json:"recommendation"`
	Risk           int             `json:"risk"`
	Coverage       policy.Coverage `json:"coverage"`
	Assignment     Assignment      `json:"assignment"`
	Exception      *Exception      `json:"exception,omitempty"`
	Overdue        bool            `json:"overdue"`
	ApprovalID     string          `json:"approval_id,omitempty"`
	Status         string          `json:"status"`
}

func FindingID(host, kind, detail string) string {
	sum := sha256.Sum256([]byte(host + "\x00" + kind + "\x00" + detail))
	return fmt.Sprintf("finding:%x", sum[:16])
}

func Queue(ctx context.Context, st store.Store, inputs []compliance.Input, now time.Time) ([]WorkItem, error) {
	state, err := alerts.Load(ctx, st)
	if err != nil {
		return nil, err
	}
	approvals, err := alerts.ListApprovals(ctx, st)
	if err != nil {
		return nil, err
	}
	assignments, err := List[Assignment](ctx, st, AssignmentKind)
	if err != nil {
		return nil, err
	}
	exceptions, err := List[Exception](ctx, st, ExceptionKind)
	if err != nil {
		return nil, err
	}
	owners := map[string]Assignment{}
	for _, a := range assignments {
		owners[a.ID] = a
	}
	ex := map[string]Exception{}
	for _, e := range exceptions {
		if now.Before(e.ExpiresAt) {
			ex[e.ID] = e
		}
	}
	out := []WorkItem{}
	for _, in := range inputs {
		h := in.Host
		score := risk.Compute(in).Score
		add := func(id, kind, title, evidence, recommendation string) {
			item := WorkItem{ID: id, Host: h.Name, Kind: kind, Title: title, Evidence: evidence, Recommendation: recommendation, Risk: score, Coverage: in.Posture.Coverage, Status: "open"}
			item.Assignment = owners["host:"+h.Name]
			if a, ok := owners[id]; ok {
				item.Assignment = a
			}
			item.Overdue = item.Assignment.Overdue(now)
			if e, ok := ex[id]; ok && e.Host == h.Name {
				item.Exception = &e
				item.Status = "accepted_until_expiry"
				item.Overdue = false
			}
			for _, a := range approvals {
				if a.ID == id {
					item.ApprovalID = a.ID
					if item.Exception == nil {
						item.Status = "awaiting_approval"
					}
				}
			}
			out = append(out, item)
		}
		for _, v := range state.List() {
			if v.Host == h.Name {
				add(v.Key, v.Kind, v.RuleName, v.Reason, "Review the policy evidence; approve a proposed action only after checking its effect.")
			}
		}
		for _, v := range in.VulnFindings {
			add(FindingID(h.Name, "vulnerability", v.CVE+":"+v.Package), "vulnerability", v.CVE+" · "+v.Package, fmt.Sprintf("Installed %s; severity %s. %s", v.Version, v.Severity, v.Description), "Validate the finding against vendor guidance and plan a supported upgrade during maintenance.")
		}
		for _, finding := range in.Posture.Findings {
			add(FindingID(h.Name, "posture", finding), "posture", finding, "Observed posture deduction; consult the host's source facts.", "Inspect the relevant setting or agent check-in and correct the cause.")
		}
		for _, e := range in.Posture.Coverage.Evidence {
			if e.State != "verified" {
				add(FindingID(h.Name, "evidence", e.Category), "evidence", e.Label+": "+e.State, e.Detail, "Check collector support and permissions, then collect a fresh report.")
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Exception == nil) != (out[j].Exception == nil) {
			return out[i].Exception == nil
		}
		if out[i].Overdue != out[j].Overdue {
			return out[i].Overdue
		}
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
