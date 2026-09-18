package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"muster/internal/baseline"
	"muster/internal/compliance"
	"muster/internal/history"
	"muster/internal/model"
	"muster/internal/signals"
	"muster/internal/store"
)

// seedHistory backfills 30 days of daily score-history points per host
// (see internal/history), ending at each host's real current scores so
// the trend line on the Fleet tab lands exactly where the live numbers
// are. Earlier points are synthetic: a plausible climb from a worse
// starting score, with a few hosts given a deliberate "fell out of
// compliance, then got fixed" dip partway through so the
// time-to-remediate rollup has real spans to measure instead of showing
// zeros on a fresh demo. Deterministic (fixed random seed) so the demo
// looks the same every time it's reseeded.
func seedHistory(ctx context.Context, st store.Store, hosts []model.Host, now time.Time) (int, error) {
	rules, err := st.ListSoftwareRules(ctx)
	if err != nil {
		return 0, err
	}
	rng := rand.New(rand.NewSource(42))
	day := 24 * time.Hour
	const days = 30
	written := 0
	for i, h := range hosts {
		in, err := signals.Gather(ctx, st, h, rules, nil)
		if err != nil {
			return written, fmt.Errorf("gathering signals for %s: %w", h.Name, err)
		}
		curPosture := in.Posture.Score
		curComp := compliance.Baseline.Evaluate(in).Score
		curVulns := len(in.VulnFindings)

		// Starting point 30 days ago: somewhat worse than today, so the
		// fleet trend reads as "improving," which is the story a demo
		// wants to tell about a security program that's working.
		startPosture := clamp(curPosture-10-rng.Intn(15), 20, 100)

		// Every other host gets a mid-window incident: several days of a
		// failing check that then clears -- a closed remediation span,
		// which is what time-to-remediate actually measures.
		incidentStart, incidentLen := -1, 0
		if i%2 == 1 {
			incidentStart = 8 + rng.Intn(10)
			incidentLen = 1 + rng.Intn(5)
		}

		s := history.Series{Host: h.Name}
		for d := days; d >= 0; d-- {
			at := now.Add(-time.Duration(d) * day)
			progress := float64(days-d) / float64(days)
			posture := int(float64(startPosture) + progress*float64(curPosture-startPosture) + float64(rng.Intn(5)-2))
			// Compliance holds at today's value across the window (a check
			// either passes or it doesn't -- it doesn't drift the way the
			// posture score does); only the incident dips below move it.
			comp := curComp
			vulns := 0
			if curVulns > 0 && progress > 0.5 {
				vulns = curVulns
			}
			inIncident := incidentStart >= 0 && days-d >= incidentStart && days-d < incidentStart+incidentLen
			if inIncident {
				comp = clamp(comp-20, 0, 80)
				posture = clamp(posture-15, 0, 100)
				vulns++
			}
			if d == 0 {
				posture, comp, vulns = curPosture, curComp, curVulns
			}
			s.Points = append(s.Points, history.Point{
				At: at, Posture: clamp(posture, 0, 100), Compliance: clamp(comp, 0, 100),
				Vulns: vulns, Stale: d == 0 && in.Stale,
			})
		}
		for _, p := range s.Points {
			if err := history.Record(ctx, st, h.Name, p); err != nil {
				return written, fmt.Errorf("recording history for %s: %w", h.Name, err)
			}
		}
		written += len(s.Points)
	}
	return written, nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// seedBaselines captures a golden baseline for a few hosts and then
// nudges one of them away from it, so the drift feature has something
// to show on a fresh demo: web01.prod matches its baseline exactly;
// api01.prod's baseline was taken when its firewall was on, vsftpd
// wasn't installed, and curl was one release older -- exactly the kind
// of "who changed this box" story config-drift detection exists for.
func seedBaselines(ctx context.Context, st store.Store) (int, error) {
	n := 0
	if _, err := baseline.Capture(ctx, st, "web01.prod", "seed-tool", "golden image 2026-09 (web tier)", nil); err != nil {
		return n, err
	}
	n++

	// api01.prod: write the "golden" version of two categories first,
	// capture, then restore the real (drifted) current facts.
	cur, ok, err := st.GetFact(ctx, "api01.prod", "installed_software")
	if err != nil || !ok {
		return n, fmt.Errorf("api01.prod installed_software: ok=%v err=%v", ok, err)
	}
	curFW, _, _ := st.GetFact(ctx, "api01.prod", "firewall_av_status")
	golden := sw(
		[3]string{"curl", "7.68.0-1ubuntu2.20", "amd64"},
		[3]string{"libcurl4", "7.68.0-1ubuntu2.20", "amd64"},
		[3]string{"python3", "3.8.10-0ubuntu1.13", "amd64"},
	)
	if _, err := st.UpsertFact(ctx, model.Fact{Host: "api01.prod", Category: "installed_software", Data: golden, CookedAt: cur.CookedAt}); err != nil {
		return n, err
	}
	if _, err := st.UpsertFact(ctx, model.Fact{Host: "api01.prod", Category: "firewall_av_status", Data: linuxFirewall("active"), CookedAt: cur.CookedAt}); err != nil {
		return n, err
	}
	if _, err := baseline.Capture(ctx, st, "api01.prod", "seed-tool", "golden image 2026-09 (api tier)", nil); err != nil {
		return n, err
	}
	n++
	if _, err := st.UpsertFact(ctx, cur); err != nil {
		return n, err
	}
	if _, err := st.UpsertFact(ctx, curFW); err != nil {
		return n, err
	}
	return n, nil
}
