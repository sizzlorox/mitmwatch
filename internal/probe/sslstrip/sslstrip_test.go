package sslstrip

import (
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc(t *testing.T) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: "unknown"}
}

func snap(t *testing.T, hosts map[string]hostObs) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Hosts: hosts})
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

const hsts = "max-age=31536000; includeSubdomains; preload"

func healthy(host string) hostObs {
	return hostObs{Host: host, HTTPStatus: 301, HTTPLocation: "https://" + host + "/", HSTS: hsts}
}

func TestRedirectingHostIsSilent(t *testing.T) {
	cur := snap(t, map[string]hostObs{"github.com": healthy("github.com")})
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc(t)); len(fs) != 0 {
		t.Fatalf("a healthy host produced %v", vectors(fs))
	}
}

// The false positive this probe shipped with: www.google.com answers plain
// http with 200 and sends no HSTS at all, so a naive rule reports it as
// stripped forever. It is a bad choice of host, not an attack.
func TestHostThatNeverSendsHSTSIsAConfigProblem(t *testing.T) {
	cur := snap(t, map[string]hostObs{"www.google.com": {
		Host: "www.google.com", HTTPStatus: 200, HTTPBodyLen: 65536, HSTS: "",
	}})
	got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, cc(t)))
	if _, ok := got[vecPlaintextBody]; ok {
		t.Errorf("reported a downgrade for a host that never claimed https: %v", got)
	}
	if _, ok := got[vecHostUnsuitable]; !ok {
		t.Fatalf("want %s, got %v", vecHostUnsuitable, got)
	}
	if got[vecHostUnsuitable] >= 20 {
		t.Errorf("a config problem scored %d, want informational", got[vecHostUnsuitable])
	}
}

func TestStrippedHostIsReported(t *testing.T) {
	base := snap(t, map[string]hostObs{"github.com": healthy("github.com")})
	cur := snap(t, map[string]hostObs{"github.com": {
		Host: "github.com", HTTPStatus: 200, HTTPBodyLen: 4096, HSTS: hsts,
	}})
	got := vectors((Probe{}).Compare(base, cur, cc(t)))
	if got[vecPlaintextBody] < 60 {
		t.Fatalf("%s scored %d, want >= 60; got %v", vecPlaintextBody, got[vecPlaintextBody], got)
	}
}

// A host that used to advertise HSTS and stopped is a real signal; absence at
// first sight is not.
func TestHSTSLossIsReportedButAbsenceIsNot(t *testing.T) {
	base := snap(t, map[string]hostObs{"github.com": healthy("github.com")})
	gone := hostObs{Host: "github.com", HTTPStatus: 301, HSTS: ""}
	cur := snap(t, map[string]hostObs{"github.com": gone})

	got := vectors((Probe{}).Compare(base, cur, cc(t)))
	if _, ok := got[vecNoHSTS]; !ok {
		t.Fatalf("want %s after losing the header, got %v", vecNoHSTS, got)
	}

	first := vectors((Probe{}).Compare(probe.Snapshot{}, cur, cc(t)))
	if _, ok := first[vecNoHSTS]; ok {
		t.Errorf("reported %s at first sight, which is a config problem not an attack: %v",
			vecNoHSTS, first)
	}
}

// A host that is simply unreachable must not be reported as unsuitable.
func TestUnreachableHostIsSilent(t *testing.T) {
	cur := snap(t, map[string]hostObs{"github.com": {
		Host: "github.com", HTTPErr: "i/o timeout", HTTPSErr: "i/o timeout",
	}})
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc(t)); len(fs) != 0 {
		t.Fatalf("an offline host produced %v", vectors(fs))
	}
}
