// Package verdict turns findings into alerts.
//
// Probes report evidence; this package owns the policy: aggregation per
// target, band thresholds, suppression during learning, and the user's accept
// list. Keeping policy here is what lets the scoring table be recalibrated
// without touching a probe.
package verdict

import (
	"sort"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// Band is the severity of an aggregated score. Bands, not raw scores, decide
// whether a person is interrupted.
type Band int

const (
	Info Band = iota
	Low
	Medium
	High
	Critical
)

// Thresholds from SDD 7.4.
func BandOf(score int) Band {
	switch {
	case score >= 80:
		return Critical
	case score >= 60:
		return High
	case score >= 40:
		return Medium
	case score >= 20:
		return Low
	default:
		return Info
	}
}

func (b Band) String() string {
	switch b {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	}
	return "info"
}

// Alert is one target's aggregated verdict.
type Alert struct {
	Target   string
	Score    int
	Band     Band
	Findings []probe.Finding
	// Suppressed explains why this alert was held back, empty when it was not.
	Suppressed string
}

// Result is one evaluation pass.
type Result struct {
	Alerts []Alert
	// Held are alerts suppressed by learning or by the accept list. They are
	// kept so `check` and `doctor` can show what was withheld and why: a
	// detector that hides its own suppressions is impossible to trust.
	Held []Alert
}

// Max returns the highest band among the surfaced alerts.
func (r Result) Max() Band {
	m := Info
	for _, a := range r.Alerts {
		if a.Band > m {
			m = a.Band
		}
	}
	return m
}

// Evaluate aggregates findings by target and applies suppression policy.
func Evaluate(findings []probe.Finding, cc probe.CompareCtx) Result {
	byTarget := map[string][]probe.Finding{}
	seen := map[string]bool{}

	for _, f := range findings {
		// A zero score is the deliberate way to turn a vector off: set its
		// weight to 0 in config and it stops mattering. Without this it still
		// became a score-0 Info alert that notification sinks delivered, so
		// "tune it to zero" did not actually silence it. This is the documented
		// escape hatch for a rule whose residual false positives a particular
		// network cannot tolerate.
		if f.Score == 0 {
			continue
		}
		h := f.Hash()
		// Dedup identical evidence inside a single pass: two probes reporting
		// the same condition must not double the score.
		if seen[h] {
			continue
		}
		seen[h] = true
		if cc.IsAccepted(h) {
			continue
		}
		target := f.Target
		if target == "" {
			target = "network"
		}
		byTarget[target] = append(byTarget[target], f)
	}

	var res Result
	for target, fs := range byTarget {
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Score > fs[j].Score })
		score := 0
		for _, f := range fs {
			score += f.Score
		}
		a := Alert{Target: target, Score: score, Band: BandOf(score), Findings: fs}
		// During the learning window only Critical surfaces: a fresh profile
		// disagrees with everything, and alerting on that trains the user to
		// ignore the product.
		if cc.Learning && a.Band < Critical {
			a.Suppressed = "learning window"
			res.Held = append(res.Held, a)
			continue
		}
		res.Alerts = append(res.Alerts, a)
	}

	sortAlerts(res.Alerts)
	sortAlerts(res.Held)
	return res
}

func sortAlerts(as []Alert) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Score != as[j].Score {
			return as[i].Score > as[j].Score
		}
		return as[i].Target < as[j].Target
	})
}
