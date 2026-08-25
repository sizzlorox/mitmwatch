package main

import (
	"errors"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc() probe.CompareCtx { return probe.CompareCtx{Config: config.Defaults()} }

// The deadlock this replaced: freezing on any High finding meant a persistent
// condition could never enter the baseline, so every rule that asks "has this
// been stable?" was unreachable. tls/private-root scores 70, so a managed
// laptop behind a corporate proxy never recorded its own corporate root, and
// the softening written for exactly that laptop could never fire.
func TestPersistentStateDoesNotFreezeTheBaseline(t *testing.T) {
	fs := []probe.Finding{{
		Probe: "tls", Vector: "tls/private-root", Target: "github.com", Score: 70,
		Identity: map[string]string{"root_subject": "CN=Corp Root"},
	}, {
		Probe: "tls", Vector: "tls/no-sct", Target: "github.com", Score: 35,
	}}
	if freezes(fs, cc()) {
		t.Fatal("a persistent state froze the baseline; the stable-root comparison " +
			"that reads the baseline can then never succeed")
	}
}

// The property that must survive: something that just appeared must not be
// absorbed, or the next pass treats the attack as normal.
func TestNewChangeFreezesTheBaseline(t *testing.T) {
	fs := []probe.Finding{{
		Probe: "truststore", Vector: "truststore/root-added", Target: "Attacker CA",
		Score: 80, Change: true,
		Identity: map[string]string{"sha256": "deadbeef"},
	}}
	if !freezes(fs, cc()) {
		t.Fatal("a newly added certificate authority was absorbed into the baseline; " +
			"the next pass would see it as one that was always there")
	}
}

// "This was me" has to reach the baseline. Otherwise the snapshot stays frozen
// for as long as the accepted condition lasts, and every later comparison is
// made against an ever-staler view.
func TestAcceptedChangeDoesNotFreeze(t *testing.T) {
	f := probe.Finding{
		Probe: "truststore", Vector: "truststore/root-added", Target: "Corp CA",
		Score: 80, Change: true,
		Identity: map[string]string{"sha256": "cafe"},
	}
	c := cc()
	c.Accepted = func(h string) bool { return h == f.Hash() }

	if freezes([]probe.Finding{f}, c) {
		t.Fatal("an accepted change still froze the baseline")
	}
}

// A change below High is ordinary drift - certificate rotation, an HSTS header
// coming and going - and absorbing it is the point of having a baseline.
func TestMinorChangeDoesNotFreeze(t *testing.T) {
	fs := []probe.Finding{{
		Probe: "tls", Vector: "tls/leaf-rotated", Target: "github.com",
		Score: 5, Change: true,
	}}
	if freezes(fs, cc()) {
		t.Fatal("routine certificate rotation froze the baseline")
	}
}

func TestNoFindingsDoesNotFreeze(t *testing.T) {
	if freezes(nil, cc()) {
		t.Fatal("a clean pass froze the baseline")
	}
}

// One unaccepted change among many states is enough to hold the snapshot back.
func TestOneChangeAmongStatesFreezes(t *testing.T) {
	fs := []probe.Finding{
		{Vector: "tls/private-root", Target: "a", Score: 70},
		{Vector: "tls/no-sct", Target: "a", Score: 35},
		{Vector: "truststore/root-added", Target: "New CA", Score: 80, Change: true,
			Identity: map[string]string{"sha256": "01"}},
	}
	if !freezes(fs, cc()) {
		t.Fatal("a root-added finding was outvoted by the state findings beside it")
	}
}

// A probe that could not look must never become the record of what is normal.
// Adopting an empty trust store makes the empty view the baseline, and then the
// next healthy read reports the entire real world as newly appeared - dozens of
// root-added findings at Critical, each of which then freezes the snapshot in
// turn.
func TestIncompleteObservationIsNotAdopted(t *testing.T) {
	snap, err := probe.Incomplete("truststore", map[string]any{"roots": nil},
		errors.New("read 0 roots: permission denied"))
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Degraded {
		t.Fatal("probe.Incomplete did not mark the snapshot degraded")
	}
	if adoptable(snap, nil, cc()) {
		t.Fatal("an incomplete observation was adopted as the baseline")
	}
	if snap.Err == "" {
		t.Error("the reason was lost, so the operator cannot tell why it did not look")
	}
}

// A complete observation with nothing alarming in it is exactly what should be
// adopted - otherwise the baseline never advances at all.
func TestCompleteQuietObservationIsAdopted(t *testing.T) {
	snap, err := probe.Encode("truststore", map[string]any{"roots": map[string]string{"a": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if !adoptable(snap, nil, cc()) {
		t.Fatal("a clean, complete observation was refused")
	}
}
