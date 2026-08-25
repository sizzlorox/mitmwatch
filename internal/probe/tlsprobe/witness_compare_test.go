package tlsprobe

import (
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// witnessView builds a WitnessView whose tls snapshot holds these host
// observations, with every host marked stable.
func witnessView(t *testing.T, hosts map[string]hostObs) probe.WitnessView {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	stable := map[string]bool{}
	for h := range hosts {
		stable[h] = true
	}
	return probe.NewWitnessView(true, true, false, "", time.Now(),
		map[string]probe.Snapshot{name: s}, stable)
}

func ctxW(t *testing.T, trust string, w probe.WitnessView) probe.CompareCtx {
	c := ctx(t, trust)
	c.Witness = w
	return c
}

// A clean host that both vantages agree on produces nothing new.
func TestWitnessAgreementIsSilent(t *testing.T) {
	host := clean("github.com", "aaa", "Sectigo")
	cur := snap(t, map[string]hostObs{"github.com": host})
	w := witnessView(t, map[string]hostObs{"github.com": host})
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)); len(fs) != 0 {
		t.Fatalf("agreeing vantages produced %v", vectors(fs))
	}
}

// SCTs present at the witness, absent here: the path-to-me interception signal.
func TestWitnessSCTUnloggedReplacesNoSCT(t *testing.T) {
	// Local: a chain that verifies to a public root but carries no SCTs.
	local := clean("github.com", "aaa", "Sectigo")
	local.SCTCount = 0
	local.OCSPStapled = false
	// Witness: same host, SCTs present.
	wit := clean("github.com", "bbb", "Sectigo")
	wit.SCTCount = 3

	cur := snap(t, map[string]hostObs{"github.com": local})
	w := witnessView(t, map[string]hostObs{"github.com": wit})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)))

	if _, ok := got[vecWitnessSCTUnlogged]; !ok {
		t.Fatalf("want %s, got %v", vecWitnessSCTUnlogged, got)
	}
	// It must REPLACE no-sct, not stack with it (35+50 would cross Critical).
	if _, ok := got[vecNoSCT]; ok {
		t.Errorf("both %s and %s fired; they must be mutually exclusive: %v",
			vecWitnessSCTUnlogged, vecNoSCT, got)
	}
}

// The honest exception: SCTs delivered by stapled OCSP rather than embedded. The
// sensor's embedded-SCT count is 0 but that is not interception.
func TestWitnessSCTUnloggedRespectsOCSPStapling(t *testing.T) {
	local := clean("github.com", "aaa", "Sectigo")
	local.SCTCount = 0
	local.OCSPStapled = true // honest: SCTs come via OCSP
	wit := clean("github.com", "bbb", "Sectigo")
	wit.SCTCount = 3

	cur := snap(t, map[string]hostObs{"github.com": local})
	w := witnessView(t, map[string]hostObs{"github.com": wit})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)))
	if _, ok := got[vecWitnessSCTUnlogged]; ok {
		t.Fatalf("fired on a host that staples OCSP - a false positive: %v", got)
	}
}

// Not stable yet: even a real divergence must wait for the confirm window, so a
// transient witness glitch cannot drive a finding.
func TestWitnessRulesWaitForStability(t *testing.T) {
	local := clean("github.com", "aaa", "Sectigo")
	local.SCTCount = 0
	wit := clean("github.com", "bbb", "Sectigo")
	wit.SCTCount = 3

	cur := snap(t, map[string]hostObs{"github.com": local})
	s, _ := probe.Encode(name, snapshot{Hosts: map[string]hostObs{"github.com": wit}})
	// Available but NOT stable.
	w := probe.NewWitnessView(true, true, false, "", time.Now(),
		map[string]probe.Snapshot{name: s}, map[string]bool{})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)))
	if _, ok := got[vecWitnessSCTUnlogged]; ok {
		t.Fatalf("fired before the host was confirmed stable: %v", got)
	}
	// Falls back to the local no-sct instead, which is correct.
	if _, ok := got[vecNoSCT]; !ok {
		t.Errorf("expected local no-sct fallback while unstable: %v", got)
	}
}

// The root-mismatch corroborator only fires ALONGSIDE a local private/untrusted
// root, and is weight 5 so it cannot manufacture a band.
func TestWitnessRootMismatchCorroborates(t *testing.T) {
	// Local: interceptor's private root, no SCTs. Witness: public root.
	local := hostObs{
		Host: "github.com", LeafSPKI: "x", IssuerCN: "Evil CA", IssuerO: "Evil", IssuerSPKI: "evilkey",
		RootSubject: "CN=Evil Root", RootInEmbedded: false, RootInSystem: sysYes,
		SCTCount: 0, Version: "TLS1.3",
	}
	wit := clean("github.com", "y", "Sectigo") // public, logged

	cur := snap(t, map[string]hostObs{"github.com": local})
	w := witnessView(t, map[string]hostObs{"github.com": wit})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)))

	if got[vecPrivateRoot] < 60 {
		t.Fatalf("local private-root did not fire: %v", got)
	}
	if _, ok := got[vecWitnessRootMismatch]; !ok {
		t.Fatalf("want %s alongside private-root: %v", vecWitnessRootMismatch, got)
	}
	if got[vecWitnessRootMismatch] > 9 {
		t.Errorf("corroborator weight is %d; must be small enough never to tip a band", got[vecWitnessRootMismatch])
	}
	// The realistic composition reaches Critical: private-root 70 + no-sct
	// replaced by witness-sct-unlogged 50 + mismatch 5.
	total := 0
	for _, s := range got {
		total += s
	}
	if total < 80 {
		t.Errorf("a corroborated interception scored %d, want Critical: %v", total, got)
	}
}

// It must NOT fire on an honest host that has no local root finding.
func TestWitnessRootMismatchNeedsALocalRootFinding(t *testing.T) {
	local := clean("github.com", "x", "Sectigo") // public root, no local finding
	wit := clean("github.com", "y", "DigiCert")  // different public root
	cur := snap(t, map[string]hostObs{"github.com": local})
	w := witnessView(t, map[string]hostObs{"github.com": wit})
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w))); got[vecWitnessRootMismatch] != 0 {
		t.Fatalf("fired without a local root finding - a benign cross-vantage root difference: %v", got)
	}
}

// The witness-distinct qualifier on shared-leaf-key: shared here, different keys
// outside. This is the case a public-root interceptor slips past locally.
func TestWitnessSharedLeafKey(t *testing.T) {
	// Two CDN hosts sharing ONE key locally - normally not a finding.
	shared := "one-interception-key"
	a := clean("cloudflare-dns.com", shared, "Cloudflare, Inc.")
	b := clean("registry.npmjs.org", shared, "Cloudflare, Inc.")
	cur := snap(t, map[string]hostObs{"cloudflare-dns.com": a, "registry.npmjs.org": b})

	// Witness sees them on DIFFERENT keys - impossible for one real shared cert.
	wa := clean("cloudflare-dns.com", "real-key-a", "Cloudflare, Inc.")
	wb := clean("registry.npmjs.org", "real-key-b", "Cloudflare, Inc.")
	w := witnessView(t, map[string]hostObs{"cloudflare-dns.com": wa, "registry.npmjs.org": wb})

	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w)))
	if _, ok := got[vecSharedLeafKey]; !ok {
		t.Fatalf("want %s when the witness sees distinct keys: %v", vecSharedLeafKey, got)
	}
}

// The genuine CDN case: shared key here AND shared key at the witness. One real
// certificate. Must stay silent.
func TestGenuineSharedCDNKeyStaysSilentWithWitness(t *testing.T) {
	shared := "one-real-cloudflare-key"
	a := clean("cloudflare-dns.com", shared, "Cloudflare, Inc.")
	b := clean("registry.npmjs.org", shared, "Cloudflare, Inc.")
	cur := snap(t, map[string]hostObs{"cloudflare-dns.com": a, "registry.npmjs.org": b})
	// Witness sees the SAME shared key.
	w := witnessView(t, map[string]hostObs{"cloudflare-dns.com": a, "registry.npmjs.org": b})

	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w))); len(got) != 0 {
		t.Fatalf("a genuine shared CDN cert produced findings with a witness present: %v", got)
	}
}

// Leaf rotation across vantages - the routine case the whole design is careful
// about - must NEVER produce a witness finding.
func TestWitnessLeafRotationIsSilent(t *testing.T) {
	local := clean("github.com", "sensor-sees-this-leaf", "Sectigo")
	wit := clean("github.com", "witness-sees-a-different-leaf", "Sectigo")
	cur := snap(t, map[string]hostObs{"github.com": local})
	w := witnessView(t, map[string]hostObs{"github.com": wit})
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", w))); len(got) != 0 {
		t.Fatalf("different leaves at the two vantages (routine CDN) produced %v", got)
	}
}

// witness/unreachable fires only when configured, down past grace, on its own
// target - and never sums with detection.
func TestWitnessUnreachable(t *testing.T) {
	down := probe.NewWitnessView(true, false, true, "connection refused", time.Time{}, nil, nil)
	cur := snap(t, map[string]hostObs{"github.com": clean("github.com", "x", "Sectigo")})
	fs := (Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", down))
	got := vectors(fs)
	if _, ok := got[vecWitnessUnreachable]; !ok {
		t.Fatalf("want %s, got %v", vecWitnessUnreachable, got)
	}
	for _, f := range fs {
		if f.Vector == vecWitnessUnreachable && f.Target != "witness" {
			t.Errorf("unreachable target = %q, want \"witness\" so it never sums with network findings", f.Target)
		}
	}
}

// Configured but not yet down-past-grace: no finding (a reboot must not alarm).
func TestWitnessDownWithinGraceIsSilent(t *testing.T) {
	down := probe.NewWitnessView(true, false, false /* not ReportDown yet */, "reconnecting", time.Time{}, nil, nil)
	cur := snap(t, map[string]hostObs{"github.com": clean("github.com", "x", "Sectigo")})
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", down))); got[vecWitnessUnreachable] != 0 {
		t.Fatalf("alarmed on a witness still within its reconnect grace: %v", got)
	}
}

// No witness configured at all: Compare is exactly phase 0.
func TestNoWitnessIsPhaseZero(t *testing.T) {
	cur := snap(t, map[string]hostObs{"github.com": clean("github.com", "x", "Sectigo")})
	none := probe.WitnessView{} // Configured:false
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctxW(t, "unknown", none))); len(got) != 0 {
		t.Fatalf("an unconfigured witness changed phase-0 behaviour: %v", got)
	}
}
