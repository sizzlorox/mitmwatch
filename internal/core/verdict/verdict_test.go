package verdict

import (
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc() probe.CompareCtx { return probe.CompareCtx{Config: config.Defaults()} }

func f(vector, target string, score int, ev map[string]string) probe.Finding {
	if ev == nil {
		ev = map[string]string{"k": vector}
	}
	return probe.Finding{Probe: "t", Vector: vector, Target: target, Score: score, Evidence: ev}
}

func TestBandThresholds(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  Band
	}{{0, Info}, {19, Info}, {20, Low}, {39, Low}, {40, Medium},
		{59, Medium}, {60, High}, {79, High}, {80, Critical}, {500, Critical}} {
		if got := BandOf(tc.score); got != tc.want {
			t.Errorf("BandOf(%d) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

func TestScoresAggregatePerTarget(t *testing.T) {
	res := Evaluate([]probe.Finding{
		f("a/one", "github.com", 70, nil),
		f("a/two", "github.com", 35, nil),
		f("a/one", "other.com", 10, map[string]string{"k": "other"}),
	}, cc())

	if len(res.Alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(res.Alerts))
	}
	// Highest score first.
	if res.Alerts[0].Target != "github.com" || res.Alerts[0].Score != 105 {
		t.Fatalf("got %s=%d, want github.com=105", res.Alerts[0].Target, res.Alerts[0].Score)
	}
	if res.Alerts[0].Band != Critical {
		t.Errorf("band = %v, want Critical", res.Alerts[0].Band)
	}
	if res.Max() != Critical {
		t.Errorf("Max() = %v, want Critical", res.Max())
	}
}

// Two probes reporting the same condition must not double the score.
func TestIdenticalEvidenceIsDeduped(t *testing.T) {
	same := map[string]string{"root": "CN=X"}
	res := Evaluate([]probe.Finding{
		f("a/one", "github.com", 50, same),
		f("a/one", "github.com", 50, same),
	}, cc())
	if len(res.Alerts) != 1 || res.Alerts[0].Score != 50 {
		t.Fatalf("got score %d across %d alerts, want a single 50", res.Alerts[0].Score, len(res.Alerts))
	}
}

func TestLearningWindowHoldsEverythingBelowCritical(t *testing.T) {
	c := cc()
	c.Learning = true
	res := Evaluate([]probe.Finding{
		f("a/high", "a.com", 70, nil),
		f("a/crit", "b.com", 90, nil),
	}, c)

	if len(res.Alerts) != 1 || res.Alerts[0].Target != "b.com" {
		t.Fatalf("surfaced %v, want only the critical b.com", res.Alerts)
	}
	if len(res.Held) != 1 || res.Held[0].Target != "a.com" {
		t.Fatalf("held %v, want a.com", res.Held)
	}
	// Suppressed findings must remain visible as suppressed. A detector that
	// silently withholds cannot be trusted about what it did not find.
	if res.Held[0].Suppressed == "" {
		t.Error("held alert does not say why it was held")
	}
}

func TestAcceptedFindingsAreDropped(t *testing.T) {
	finding := f("a/one", "github.com", 90, nil)
	c := cc()
	c.Accepted = func(h string) bool { return h == finding.Hash() }

	res := Evaluate([]probe.Finding{finding}, c)
	if len(res.Alerts) != 0 || len(res.Held) != 0 {
		t.Fatalf("accepted finding still surfaced: %v / %v", res.Alerts, res.Held)
	}
}

func TestEmptyTargetBecomesNetwork(t *testing.T) {
	res := Evaluate([]probe.Finding{f("a/one", "", 50, nil)}, cc())
	if len(res.Alerts) != 1 || res.Alerts[0].Target != "network" {
		t.Fatalf("got %v, want a single alert targeting \"network\"", res.Alerts)
	}
}

func TestNoFindingsIsQuiet(t *testing.T) {
	res := Evaluate(nil, cc())
	if len(res.Alerts) != 0 || len(res.Held) != 0 || res.Max() != Info {
		t.Fatalf("empty input produced %v / %v / %v", res.Alerts, res.Held, res.Max())
	}
}

// A finding tuned to weight 0 is the documented off switch. It must not survive
// as a score-0 Info alert that notification sinks would still deliver.
func TestZeroScoreFindingIsDropped(t *testing.T) {
	res := Evaluate([]probe.Finding{
		f("a/off", "host", 0, nil),
		f("a/on", "host", 50, nil),
	}, cc())
	if len(res.Alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 - the zero-score finding should be gone", len(res.Alerts))
	}
	if res.Alerts[0].Score != 50 {
		t.Errorf("score = %d, want 50; a zero-score finding leaked in", res.Alerts[0].Score)
	}
}
