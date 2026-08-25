package truststore

import (
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc(t *testing.T) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: "unknown"}
}

func snap(t *testing.T, roots map[string]rootObs) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Roots: roots, Total: len(roots)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func vectors(fs []probe.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Vector] = f.Score
	}
	return out
}

// interceptor is the shape ESET's root has on the development machine: self
// signed, usable for server auth, absent from Mozilla's bundle, recent.
func interceptor(cn string, age time.Duration) rootObs {
	return rootObs{
		Subject: "CN=" + cn, CN: cn,
		NotBefore: time.Now().Add(-age), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		ServerAuth: true, InMozilla: false, SelfSigned: true,
		Stores: []string{`CurrentUser\Root`, `LocalMachine\Root`},
	}
}

func TestPublicRootsAreIgnored(t *testing.T) {
	r := interceptor("DigiCert Global Root G2", 30*24*time.Hour)
	r.InMozilla = true
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, map[string]rootObs{"k": r}), cc(t)); len(fs) != 0 {
		t.Fatalf("a Mozilla root was reported: %v", vectors(fs))
	}
}

// Windows ships a long tail of code-signing and timestamping roots that are
// absent from Mozilla's bundle. They cannot vouch for a website, so they are
// not evidence - this is what keeps the clean baseline at zero instead of 38.
func TestCodeSigningRootsAreIgnored(t *testing.T) {
	r := interceptor("Microsoft Root Certificate Authority 2011", 30*24*time.Hour)
	r.ServerAuth = false
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, map[string]rootObs{"k": r}), cc(t)); len(fs) != 0 {
		t.Fatalf("a non-serverAuth root was reported: %v", vectors(fs))
	}
}

func TestOldPrivateRootIsNotYoung(t *testing.T) {
	r := interceptor("Ancient Enterprise CA", maxAge+24*time.Hour)
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, map[string]rootObs{"k": r}), cc(t)); len(fs) != 0 {
		t.Fatalf("a root older than maxAge was reported: %v", vectors(fs))
	}
}

func TestYoungPrivateRootIsReportedAtFirstSight(t *testing.T) {
	r := interceptor("ESET SSL Filter CA", 240*24*time.Hour)
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, map[string]rootObs{"k": r}), cc(t))
	got := vectors(fs)
	if _, ok := got[vecYoungRoot]; !ok {
		t.Fatalf("want %s, got %v", vecYoungRoot, got)
	}
	if fs[0].Target != "ESET SSL Filter CA" {
		t.Errorf("target = %q, want the root's common name so it can be accepted on its own", fs[0].Target)
	}
	if fs[0].Evidence["stores"] == "" {
		t.Error("evidence must name the store, so a per-user injection is distinguishable")
	}
}

// The strongest signal: a root that was not there last time.
func TestRootAddedIsCritical(t *testing.T) {
	old := interceptor("Existing CA", 200*24*time.Hour)
	added := interceptor("Brand New CA", 1*time.Hour)

	base := snap(t, map[string]rootObs{"a": old})
	cur := snap(t, map[string]rootObs{"a": old, "b": added})

	got := vectors((Probe{}).Compare(base, cur, cc(t)))
	if got[vecRootAdded] < 80 {
		t.Fatalf("%s scored %d, want >= 80 (critical); got %v", vecRootAdded, got[vecRootAdded], got)
	}
}

// A root reported once as young must not also be reported as added, and vice
// versa: double-counting the same root would inflate the score.
func TestAddedRootIsNotAlsoReportedAsYoung(t *testing.T) {
	added := interceptor("Brand New CA", 1*time.Hour)
	base := snap(t, map[string]rootObs{})
	cur := snap(t, map[string]rootObs{"b": added})

	fs := (Probe{}).Compare(base, cur, cc(t))
	if len(fs) != 1 {
		t.Fatalf("got %d findings for one root: %v", len(fs), vectors(fs))
	}
	if fs[0].Vector != vecRootAdded {
		t.Errorf("got %s, want %s", fs[0].Vector, vecRootAdded)
	}
}

// An old root already in the baseline is quiet: it was either accepted or
// reported when it first appeared.
func TestKnownOldRootStaysQuiet(t *testing.T) {
	r := interceptor("Long-standing Corp CA", maxAge+time.Hour)
	base := snap(t, map[string]rootObs{"a": r})
	cur := snap(t, map[string]rootObs{"a": r})
	if fs := (Probe{}).Compare(base, cur, cc(t)); len(fs) != 0 {
		t.Fatalf("a known root was re-reported: %v", vectors(fs))
	}
}

func TestEmptySnapshotDoesNotPanic(t *testing.T) {
	if fs := (Probe{}).Compare(probe.Snapshot{}, probe.Snapshot{}, cc(t)); len(fs) != 0 {
		t.Fatalf("got %v", vectors(fs))
	}
}
