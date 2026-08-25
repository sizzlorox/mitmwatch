package main

import (
	"context"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// fakeProbe lets the merge be tested without running real observations.
type fakeProbe struct {
	name string
	iv   time.Duration
}

func (f fakeProbe) Name() string            { return f.name }
func (f fakeProbe) Interval() time.Duration { return f.iv }
func (f fakeProbe) Observe(context.Context, probe.Inputs) (probe.Snapshot, error) {
	return probe.Snapshot{}, nil
}
func (f fakeProbe) Compare(_, _ probe.Snapshot, _ probe.CompareCtx) []probe.Finding { return nil }

func find(probeName, vector string, score int) probe.Finding {
	return probe.Finding{Probe: probeName, Vector: vector, Target: "network", Score: score,
		Identity: map[string]string{"k": vector}}
}

// The bug this guards: the sensor ran only the due probes and judged that
// subset as the whole world, so a persistent finding from a probe absent this
// cycle vanished - its cooldown forgotten, its dashboard card greened, its
// score never summed with another probe's.
func TestMergeKeepsFindingsFromProbesThatDidNotRun(t *testing.T) {
	e := &env{}
	tls := fakeProbe{name: "tls", iv: 5 * time.Minute}
	arp := fakeProbe{name: "arp", iv: 2 * time.Minute}

	// Cycle 1: both run. tls has a finding, arp is clean.
	e.erroredThisPass = nil
	got := e.mergeFindings([]probe.Probe{tls, arp}, []probe.Finding{find("tls", "tls/private-root", 70)})
	if len(got) != 1 {
		t.Fatalf("cycle 1: got %d findings, want 1", len(got))
	}

	// Cycle 2: only arp is due (2m < 5m). tls did not run and returns nothing.
	// Its finding must survive.
	e.erroredThisPass = nil
	got = e.mergeFindings([]probe.Probe{arp}, nil)
	if len(got) != 1 || got[0].Vector != "tls/private-root" {
		t.Fatalf("cycle 2: the tls finding was dropped because tls was not due: %v", got)
	}
}

// A probe that ran and found nothing must clear its old findings - otherwise a
// resolved condition alerts forever.
func TestMergeClearsWhenAProbeRunsClean(t *testing.T) {
	e := &env{}
	arp := fakeProbe{name: "arp", iv: 2 * time.Minute}

	e.mergeFindings([]probe.Probe{arp}, []probe.Finding{find("arp", "arp/gateway-mac-changed", 60)})
	// Next cycle arp runs and finds nothing.
	e.erroredThisPass = nil
	got := e.mergeFindings([]probe.Probe{arp}, nil)
	if len(got) != 0 {
		t.Fatalf("a cleared condition survived a clean run: %v", got)
	}
}

// A probe that ERRORED must keep its previous findings, not clear them: an
// error is "could not look", not "all clear".
func TestMergeKeepsFindingsWhenAProbeErrors(t *testing.T) {
	e := &env{}
	arp := fakeProbe{name: "arp", iv: 2 * time.Minute}

	e.mergeFindings([]probe.Probe{arp}, []probe.Finding{find("arp", "arp/gateway-mac-changed", 60)})
	// Next cycle arp errored (pass set erroredThisPass, returned no findings).
	e.erroredThisPass = map[string]bool{"arp": true}
	got := e.mergeFindings([]probe.Probe{arp}, nil)
	if len(got) != 1 {
		t.Fatalf("an errored probe cleared its findings, reading 'could not look' as 'all clear': %v", got)
	}
}

// A finding older than 2x the probe's interval is dropped, so a condition that
// vanished with the probe (rather than being observed clean) does not linger.
func TestMergeAgesOutStaleFindings(t *testing.T) {
	e := &env{recent: map[string]recentFindings{
		"clock": {at: time.Now().Add(-31 * time.Minute), ttl: 30 * time.Minute,
			findings: []probe.Finding{find("clock", "clock/drift-major", 50)}},
	}}
	// A cycle where nothing relevant ran.
	got := e.mergeFindings(nil, nil)
	if len(got) != 0 {
		t.Fatalf("a stale finding past its ttl survived: %v", got)
	}
}

// The summing case: two probes scoring the same target must aggregate, which is
// only possible if both are present in the union.
func TestMergeUnionAllowsCrossProbeSumming(t *testing.T) {
	e := &env{}
	tls := fakeProbe{name: "tls", iv: 5 * time.Minute}
	clock := fakeProbe{name: "clock", iv: 15 * time.Minute}

	e.mergeFindings([]probe.Probe{tls}, []probe.Finding{find("tls", "tls/shared-leaf-key", 75)})
	e.erroredThisPass = nil
	got := e.mergeFindings([]probe.Probe{clock}, []probe.Finding{find("clock", "clock/drift-major", 50)})

	total := 0
	for _, f := range got {
		if f.Target == "network" {
			total += f.Score
		}
	}
	if total != 125 {
		t.Fatalf("cross-probe scores on one target summed to %d, want 125 (75+50)", total)
	}
}

// The advisor's verification: an accepted finding in the union must not
// re-alert before its TTL expires. verdict.Evaluate filters accepted findings,
// but the union is the path that changed, so prove it end to end.
func TestAcceptedFindingInUnionDoesNotAlert(t *testing.T) {
	e := &env{}
	arp := fakeProbe{name: "arp", iv: 2 * time.Minute}
	finding := find("arp", "arp/gateway-mac-changed", 60)

	union := e.mergeFindings([]probe.Probe{arp}, []probe.Finding{finding})
	if len(union) != 1 {
		t.Fatalf("union = %d, want 1", len(union))
	}

	// The user accepts it. A later cycle where arp did not run keeps it in the
	// union, but Evaluate must drop it.
	accepted := map[string]bool{finding.Hash(): true}
	cc := probe.CompareCtx{Config: configDefaults(), Accepted: func(h string) bool { return accepted[h] }}

	e.erroredThisPass = nil
	union = e.mergeFindings([]probe.Probe{}, nil) // nothing ran; finding still current
	res := verdictEvaluate(union, cc)
	if len(res.Alerts) != 0 {
		t.Fatalf("an accepted finding in the union still alerted: %v", res.Alerts)
	}
}

func configDefaults() *config.Config { return config.Defaults() }
func verdictEvaluate(fs []probe.Finding, cc probe.CompareCtx) verdict.Result {
	return verdict.Evaluate(fs, cc)
}
