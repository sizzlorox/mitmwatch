package tlsprobe

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func ctx(t *testing.T, trust string) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: trust}
}

func snap(t *testing.T, hosts map[string]hostObs) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// clean is a host observation that should produce no findings at all.
func clean(host, spki, issuerO string) hostObs {
	return hostObs{
		Host: host, LeafSPKI: spki, IssuerCN: "Some Public CA", IssuerO: issuerO,
		RootSubject: "CN=" + issuerO + " Root", RootInEmbedded: true, RootInSystem: sysYes,
		SCTCount: 3, Version: "TLS1.3", ChainLen: 3,
	}
}

func vectors(fs []probe.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Vector] = f.Score
	}
	return out
}

func TestCleanNetworkIsSilent(t *testing.T) {
	cur := snap(t, map[string]hostObs{
		"github.com":     clean("github.com", "aaa", "Sectigo"),
		"www.google.com": clean("www.google.com", "bbb", "Google Trust Services"),
	})
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, ctx(t, "unknown")); len(fs) != 0 {
		t.Fatalf("clean network produced findings: %v", vectors(fs))
	}
}

// The ESET shape measured on the development machine: a private root signing
// every host with one shared key and no SCTs.
func TestLocalInterceptorIsCritical(t *testing.T) {
	const shared = "eset-shared-p256-key"
	obs := func(host string) hostObs {
		return hostObs{
			Host: host, LeafSPKI: shared,
			IssuerCN: "ESET SSL Filter CA", IssuerO: "ESET, spol. s r. o.",
			RootSubject: "CN=ESET SSL Filter CA", RootInEmbedded: false, RootInSystem: sysYes,
			SCTCount: 0, Version: "TLS1.3",
		}
	}
	cur := snap(t, map[string]hostObs{
		"github.com":     obs("github.com"),
		"www.google.com": obs("www.google.com"),
	})

	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctx(t, "unknown")))
	for _, want := range []string{vecSharedLeafKey, vecPrivateRoot, vecNoSCT} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	// Per host: private-root + no-sct must on its own reach critical.
	if got[vecPrivateRoot]+got[vecNoSCT] < 80 {
		t.Errorf("private-root + no-sct = %d, want >= 80 (critical)",
			got[vecPrivateRoot]+got[vecNoSCT])
	}
}

// The regression that matters: two Cloudflare-fronted hosts in the default pin
// list legitimately share a certificate. This must never be a finding.
func TestSharedCDNKeyIsNotAFinding(t *testing.T) {
	const shared = "one-legitimate-cloudflare-key"
	cur := snap(t, map[string]hostObs{
		"cloudflare-dns.com": clean("cloudflare-dns.com", shared, "Cloudflare, Inc."),
		"registry.npmjs.org": clean("registry.npmjs.org", shared, "Cloudflare, Inc."),
	})
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctx(t, "unknown"))); len(got) != 0 {
		t.Fatalf("a shared CDN certificate was reported: %v", got)
	}
}

// The same shared key IS a finding when the configured expectations say the
// hosts belong to different organisations.
func TestSharedKeyAcrossDifferentIssuerOrgs(t *testing.T) {
	const shared = "impossible-shared-key"
	cc := ctx(t, "unknown")
	cc.Config.TLS.ExpectIssuers = map[string]string{
		"github.com":     "Sectigo Limited",
		"www.google.com": "Google Trust Services",
	}
	cur := snap(t, map[string]hostObs{
		"github.com":     clean("github.com", shared, "Sectigo Limited"),
		"www.google.com": clean("www.google.com", shared, "Sectigo Limited"),
	})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, cc))
	if _, ok := got[vecSharedLeafKey]; !ok {
		t.Fatalf("want %s, got %v", vecSharedLeafKey, got)
	}
}

func TestWorkTrustDemotesAStablePrivateRoot(t *testing.T) {
	corp := hostObs{
		Host: "github.com", LeafSPKI: "x", IssuerCN: "Corp Proxy CA", IssuerO: "Corp",
		RootSubject: "CN=Corp Root", RootInEmbedded: false, RootInSystem: sysYes,
		SCTCount: 3, Version: "TLS1.3",
	}
	base := snap(t, map[string]hostObs{"github.com": corp})
	cur := snap(t, map[string]hostObs{"github.com": corp})

	full := vectors((Probe{}).Compare(base, cur, ctx(t, "unknown")))
	if full[vecPrivateRoot] < 60 {
		t.Fatalf("unknown-trust private root scored %d, want full weight", full[vecPrivateRoot])
	}
	work := vectors((Probe{}).Compare(base, cur, ctx(t, "work")))
	if work[vecPrivateRoot] >= 20 {
		t.Errorf("stable private root on a work profile scored %d, want informational", work[vecPrivateRoot])
	}
}

// A root that is new on a work profile keeps full weight: "work" excuses the
// managed CA that was already there, not one that just appeared.
func TestWorkTrustDoesNotExcuseANewRoot(t *testing.T) {
	before := clean("github.com", "x", "Sectigo")
	after := hostObs{
		Host: "github.com", LeafSPKI: "y", IssuerCN: "New Proxy CA", IssuerO: "Someone",
		RootSubject: "CN=Brand New Root", RootInEmbedded: false, RootInSystem: sysYes,
		SCTCount: 0, Version: "TLS1.3",
	}
	got := vectors((Probe{}).Compare(
		snap(t, map[string]hostObs{"github.com": before}),
		snap(t, map[string]hostObs{"github.com": after}),
		ctx(t, "work"),
	))
	if got[vecPrivateRoot] < 60 {
		t.Fatalf("new private root on a work profile scored %d, want full weight (%v)",
			got[vecPrivateRoot], got)
	}
}

// Certificate rotation is routine and must stay informational (decision D3).
func TestLeafRotationIsInformational(t *testing.T) {
	got := vectors((Probe{}).Compare(
		snap(t, map[string]hostObs{"github.com": clean("github.com", "old", "Sectigo")}),
		snap(t, map[string]hostObs{"github.com": clean("github.com", "new", "Sectigo")}),
		ctx(t, "unknown"),
	))
	if got[vecLeafRotated] >= 20 {
		t.Errorf("leaf rotation scored %d, want below the low band", got[vecLeafRotated])
	}
	if len(got) != 1 {
		t.Errorf("rotation alone produced %v, want only %s", got, vecLeafRotated)
	}
}

func TestSystemStoreUnavailableIsReportedNotGuessed(t *testing.T) {
	cur := snap(t, map[string]hostObs{"github.com": {
		Host: "github.com", LeafSPKI: "x", IssuerCN: "Unknown CA",
		RootSubject: "CN=?", RootInEmbedded: false, RootInSystem: sysUnavailable,
		SCTCount: 3, Version: "TLS1.3",
	}})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, ctx(t, "unknown")))
	if _, ok := got[vecSysUnavail]; !ok {
		t.Fatalf("want %s, got %v", vecSysUnavail, got)
	}
	for _, must := range []string{vecPrivateRoot, vecUntrustedRoot} {
		if _, ok := got[must]; ok {
			t.Errorf("%s was decided while the system store was unreadable", must)
		}
	}
}

func TestHandshakeFailureIsAFindingNotACrash(t *testing.T) {
	cur := snap(t, map[string]hostObs{
		"github.com": {Host: "github.com", Err: "dial tcp: i/o timeout"},
	})
	fs := (Probe{}).Compare(probe.Snapshot{}, cur, ctx(t, "unknown"))
	if len(fs) != 1 || fs[0].Vector != vecHandshake {
		t.Fatalf("got %v, want a single %s", vectors(fs), vecHandshake)
	}
	if !strings.Contains(fs[0].Evidence["error"], "timeout") {
		t.Errorf("evidence lost the underlying error: %v", fs[0].Evidence)
	}
}

// The private-root finding must stay acceptable across leaf rotation: an
// interceptor mints a fresh certificate constantly, and if that moved the hash
// the user could never silence a corporate proxy they already know about.
func TestPrivateRootAcceptSurvivesLeafRotation(t *testing.T) {
	obs := func(serial string) hostObs {
		return hostObs{
			Host: "github.com", LeafSPKI: "spki-" + serial, LeafSerial: serial,
			IssuerCN: "Corp Proxy CA", IssuerO: "Corp",
			RootSubject: "CN=Corp Root", RootInEmbedded: false, RootInSystem: sysYes,
			SCTCount: 3, Version: "TLS1.3",
		}
	}
	find := func(serial string) probe.Finding {
		fs := (Probe{}).Compare(probe.Snapshot{},
			snap(t, map[string]hostObs{"github.com": obs(serial)}), ctx(t, "unknown"))
		for _, f := range fs {
			if f.Vector == vecPrivateRoot {
				return f
			}
		}
		t.Fatalf("no %s finding", vecPrivateRoot)
		return probe.Finding{}
	}
	if a, b := find("01"), find("02"); a.Hash() != b.Hash() {
		t.Fatalf("hash moved with the leaf serial (%s -> %s); an accept would not hold",
			a.Hash(), b.Hash())
	}
}

// But a genuinely different root is a different finding.
func TestPrivateRootAcceptDoesNotCoverADifferentRoot(t *testing.T) {
	mk := func(root string) probe.Finding {
		fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, map[string]hostObs{"github.com": {
			Host: "github.com", LeafSPKI: "x", IssuerCN: "CA", IssuerO: "O",
			RootSubject: root, RootInEmbedded: false, RootInSystem: sysYes,
			SCTCount: 3, Version: "TLS1.3",
		}}), ctx(t, "unknown"))
		for _, f := range fs {
			if f.Vector == vecPrivateRoot {
				return f
			}
		}
		t.Fatal("no finding")
		return probe.Finding{}
	}
	if mk("CN=Corp Root").Hash() == mk("CN=Attacker Root").Hash() {
		t.Fatal("accepting the corporate root would silently accept an attacker's")
	}
}
