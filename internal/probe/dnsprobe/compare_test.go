package dnsprobe

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc(t *testing.T) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: "unknown"}
}

func snap(t *testing.T, s snapshot) probe.Snapshot {
	t.Helper()
	out, err := probe.Encode(name, s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func vectors(fs []probe.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Vector] = f.Score
	}
	return out
}

const ep = "https://cloudflare-dns.com/dns-query"

func TestAgreementIsSilent(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"one.one.one.one": {IPs: []string{"1.1.1.1"}}},
		DoH:    map[string]map[string]answer{ep: {"one.one.one.one": {IPs: []string{"1.1.1.1"}}}},
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("agreeing resolvers produced %v", vectors(fs))
	}
}

// The reason comparison is at prefix granularity: a CDN answers with different
// edges of the same network and that is not a hijack.
func TestDifferentEdgesOfTheSamePrefixAgree(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"cdn.example": {IPs: []string{"104.16.11.34"}}},
		DoH:    map[string]map[string]answer{ep: {"cdn.example": {IPs: []string{"104.16.11.200"}}}},
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("two addresses in one /24 were reported as disagreement: %v", vectors(fs))
	}
}

func TestDifferentNetworksDisagree(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"one.one.one.one": {IPs: []string{"10.0.4.1"}}},
		DoH:    map[string]map[string]answer{ep: {"one.one.one.one": {IPs: []string{"1.1.1.1"}}}},
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)))
	if got[vecDisagrees] < 40 {
		t.Fatalf("%s scored %d, want >= 40; got %v", vecDisagrees, got[vecDisagrees], got)
	}
}

// A local answer for a name that does not exist is the classic hijack.
func TestNXDomainTurnedIntoAnAddress(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"nope.invalid": {IPs: []string{"10.0.4.99"}}},
		DoH:    map[string]map[string]answer{ep: {"nope.invalid": {NXDomain: true}}},
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)))
	if _, ok := got[vecNXDomainToA]; !ok {
		t.Fatalf("want %s, got %v", vecNXDomainToA, got)
	}
}

// Both agreeing that a name does not exist is not a finding.
func TestBothSayNXDomain(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"nope.invalid": {NXDomain: true}},
		DoH:    map[string]map[string]answer{ep: {"nope.invalid": {NXDomain: true}}},
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("agreed NXDOMAIN produced %v", vectors(fs))
	}
}

// An unreachable comparison channel is said out loud, not silently skipped.
func TestUnreachableDoHIsReported(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"one.one.one.one": {IPs: []string{"1.1.1.1"}}},
		DoH:    map[string]map[string]answer{ep: {"one.one.one.one": {Err: "x509: certificate signed by unknown authority"}}},
		DoHErr: map[string]string{ep: "x509: certificate signed by unknown authority"},
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)))
	if _, ok := got[vecDoHUnreachable]; !ok {
		t.Fatalf("want %s, got %v", vecDoHUnreachable, got)
	}
	// The host itself must not also be reported as disagreeing: there was
	// nothing to compare against.
	if _, ok := got[vecDisagrees]; ok {
		t.Errorf("reported a disagreement with an endpoint that never answered: %v", got)
	}
}

func TestPrefixOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b []string
		want bool
	}{
		{[]string{"1.1.1.1"}, []string{"1.1.1.2"}, true},
		{[]string{"1.1.1.1"}, []string{"1.1.2.1"}, false},
		{[]string{"2606:4700::1"}, []string{"2606:4700::9999"}, true},
		{[]string{"2606:4700::1"}, []string{"2606:4800::1"}, false},
		{[]string{"1.1.1.1", "9.9.9.9"}, []string{"9.9.9.10"}, true},
		{nil, []string{"1.1.1.1"}, true}, // nothing comparable: do not invent a disagreement
		{[]string{"not-an-ip"}, []string{"1.1.1.1"}, true},
	} {
		if got := prefixOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("prefixOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

const ep2 = "https://dns.google/dns-query"

// Two endpoints must not double the score. Emitting one finding per endpoint
// made the band track DoH uptime rather than the evidence, and pushed the
// coarsest check through the learning window that is meant to hold it.
func TestTwoEndpointsDoNotDoubleTheScore(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"one.one.one.one": {IPs: []string{"10.0.4.1"}}},
		DoH: map[string]map[string]answer{
			ep:  {"one.one.one.one": {IPs: []string{"1.1.1.1"}}},
			ep2: {"one.one.one.one": {IPs: []string{"1.1.1.1"}}},
		},
	}
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t))
	if len(fs) != 1 {
		t.Fatalf("got %d findings for one hijacked host, want exactly 1: %v", len(fs), vectors(fs))
	}
	if want := config.Defaults().Weight(vecDisagrees); fs[0].Score != want {
		t.Errorf("score %d, want the weight-table value %d", fs[0].Score, want)
	}
	if !strings.Contains(fs[0].Evidence["checked_against"], "cloudflare") ||
		!strings.Contains(fs[0].Evidence["checked_against"], "google") {
		t.Errorf("evidence lost the per-endpoint detail: %q", fs[0].Evidence["checked_against"])
	}
}

// If the endpoints disagree with each other, they say nothing about whether
// this network is lying. Unanimity among reachable endpoints is the bar.
func TestSplitEndpointsDoNotAccuse(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"host.example": {IPs: []string{"1.1.1.1"}}},
		DoH: map[string]map[string]answer{
			ep:  {"host.example": {IPs: []string{"1.1.1.1"}}},     // agrees with local
			ep2: {"host.example": {IPs: []string{"203.0.113.9"}}}, // does not
		},
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("accused the local resolver while an endpoint agreed with it: %v", vectors(fs))
	}
}

// An endpoint that is down must not be able to turn a real hijack into a
// lesser one, nor be counted as agreement.
func TestOneEndpointDownStillReportsAtFullWeight(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"host.example": {IPs: []string{"10.0.4.1"}}},
		DoH: map[string]map[string]answer{
			ep:  {"host.example": {IPs: []string{"203.0.113.9"}}},
			ep2: {"host.example": {Err: "i/o timeout"}},
		},
		DoHErr: map[string]string{ep2: "i/o timeout"},
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t)))
	if got[vecDisagrees] != config.Defaults().Weight(vecDisagrees) {
		t.Fatalf("%s scored %d, want full table weight: %v", vecDisagrees, got[vecDisagrees], got)
	}
	if _, ok := got[vecDoHUnreachable]; !ok {
		t.Errorf("the down endpoint was not reported: %v", got)
	}
}

// Several endpoints down is still one finding about one channel.
func TestAllEndpointsDownIsOneFinding(t *testing.T) {
	s := snapshot{
		System: map[string]answer{"host.example": {IPs: []string{"1.1.1.1"}}},
		DoH:    map[string]map[string]answer{ep: {}, ep2: {}},
		DoHErr: map[string]string{ep: "x509: unknown authority", ep2: "i/o timeout"},
	}
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, s), cc(t))
	if len(fs) != 1 {
		t.Fatalf("got %d findings for two dead endpoints, want 1: %v", len(fs), vectors(fs))
	}
}
