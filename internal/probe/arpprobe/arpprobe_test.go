package arpprobe

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const (
	router   = "00:11:32:c3:cb:d6" // Synology, the real gateway on the test LAN
	attacker = "dc:a6:32:11:22:33" // a Raspberry Pi answering for it
)

func cc(t *testing.T) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: "home"}
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

func quiet() snapshot {
	return snapshot{
		GatewayIP: "10.0.4.1", GatewayMAC: router,
		Neighbors: map[string]string{
			"10.0.4.1": router, "10.0.4.10": "88:ae:dd:65:bf:37", "10.0.4.48": "dc:a6:32:99:88:77",
		},
	}
}

func TestUnchangedNetworkIsSilent(t *testing.T) {
	s := quiet()
	if fs := (Probe{}).Compare(snap(t, s), snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("an unchanged network produced %v", vectors(fs))
	}
}

// The whole point of the probe.
func TestGatewayMACChangeIsHigh(t *testing.T) {
	before := quiet()
	after := quiet()
	after.GatewayMAC = attacker
	after.Neighbors["10.0.4.1"] = attacker

	fs := (Probe{}).Compare(snap(t, before), snap(t, after), cc(t))
	got := vectors(fs)
	if got[vecGatewayChanged] < 60 {
		t.Fatalf("%s scored %d, want >= 60: %v", vecGatewayChanged, got[vecGatewayChanged], got)
	}
	var f probe.Finding
	for _, c := range fs {
		if c.Vector == vecGatewayChanged {
			f = c
		}
	}
	if !f.Change {
		t.Error("a gateway MAC change must be marked Change, or the baseline absorbs it " +
			"and the attacker's address becomes the router on the next pass")
	}
	if !strings.Contains(f.Evidence["was"], router) || !strings.Contains(f.Evidence["now"], attacker) {
		t.Errorf("evidence must name both addresses: %v", f.Evidence)
	}
	if !strings.Contains(f.Evidence["now"], "Raspberry Pi") {
		t.Errorf("vendor hint missing, which is what makes the evidence readable: %q", f.Evidence["now"])
	}
	// The benign explanation has to be offered too, or the first false positive
	// destroys the user's trust in every later finding.
	if f.Evidence["benign_case"] == "" {
		t.Error("no benign explanation offered")
	}
}

// First sight has nothing to compare against and must not accuse anyone.
func TestFirstSightIsSilent(t *testing.T) {
	if fs := (Probe{}).Compare(probe.Snapshot{}, snap(t, quiet()), cc(t)); len(fs) != 0 {
		t.Fatalf("first observation produced %v", vectors(fs))
	}
}

// Moving to a different network is not an attack. The profile key changes with
// the gateway IP, but the probe must not accuse even if it is handed a stale
// baseline from elsewhere.
func TestDifferentGatewayIPIsNotAnAccusation(t *testing.T) {
	before := quiet()
	after := snapshot{
		GatewayIP: "192.168.1.1", GatewayMAC: attacker,
		Neighbors: map[string]string{"192.168.1.1": attacker},
	}
	if got := vectors((Probe{}).Compare(snap(t, before), snap(t, after), cc(t))); got[vecGatewayChanged] != 0 {
		t.Fatalf("accused a different network of spoofing: %v", got)
	}
}

// The artefact a spoofer leaves: its own address and the router's, one MAC.
func TestGatewayMACSharedWithAnotherHost(t *testing.T) {
	s := quiet()
	s.Neighbors["10.0.4.66"] = router // attacker still holds its own address

	got := vectors((Probe{}).Compare(snap(t, quiet()), snap(t, s), cc(t)))
	if got[vecGatewayShared] < 40 {
		t.Fatalf("%s scored %d, want >= 40: %v", vecGatewayShared, got[vecGatewayShared], got)
	}
}

// A router that resolves nowhere blinds the probe. Worth one informational
// line, never an accusation.
func TestUnresolvedGatewayIsInformational(t *testing.T) {
	after := quiet()
	after.GatewayMAC = ""
	after.Neighbors = map[string]string{}

	got := vectors((Probe{}).Compare(snap(t, quiet()), snap(t, after), cc(t)))
	if got[vecGatewayUnresolved] >= 20 {
		t.Errorf("%s scored %d, want informational", vecGatewayUnresolved, got[vecGatewayUnresolved])
	}
	if got[vecGatewayChanged] != 0 {
		t.Error("an unresolved gateway was reported as a MAC change")
	}
}

func TestVendorHint(t *testing.T) {
	for in, want := range map[string]string{
		"00:11:32:c3:cb:d6": "Synology",
		"dc:a6:32:11:22:33": "Raspberry Pi",
		"52:54:00:11:22:33": "QEMU/KVM",
		// Locally administered bit set: software pretending to be hardware.
		"7a:0d:75:19:48:84": "randomised",
		// Ordinary unknown vendor: say nothing rather than guess.
		"88:ae:dd:65:bf:37": "",
		"short":             "",
	} {
		got := vendorHint(in)
		if want == "" {
			if got != "" {
				t.Errorf("vendorHint(%q) = %q, want empty", in, got)
			}
			continue
		}
		if !strings.Contains(got, want) {
			t.Errorf("vendorHint(%q) = %q, want it to mention %q", in, got, want)
		}
	}
}

func TestEmptySnapshotsDoNotPanic(t *testing.T) {
	if fs := (Probe{}).Compare(probe.Snapshot{}, probe.Snapshot{}, cc(t)); len(fs) != 0 {
		t.Fatalf("got %v", vectors(fs))
	}
}

// What the wire shows that a neighbour table cannot: the table holds one winner
// per address, the wire holds the argument.
func TestTwoClaimantsForTheGatewayIsImpersonation(t *testing.T) {
	s := quiet()
	s.Captured = true
	s.Claims = map[string]map[string]int{
		"10.0.4.1": {router: 2, attacker: 47}, // the spoofer has to shout
	}
	got := vectors((Probe{}).Compare(snap(t, quiet()), snap(t, s), cc(t)))
	if got[vecImpersonation] < 60 {
		t.Fatalf("%s scored %d, want >= 60: %v", vecImpersonation, got[vecImpersonation], got)
	}
}

// The same argument about an address that is not the router is still worth
// reporting, but it is not an impersonation of the gateway.
func TestTwoClaimantsForAnotherAddressIsAConflict(t *testing.T) {
	s := quiet()
	s.Captured = true
	s.Claims = map[string]map[string]int{
		"10.0.4.50": {"aa:bb:cc:dd:ee:01": 3, "aa:bb:cc:dd:ee:02": 4},
	}
	got := vectors((Probe{}).Compare(snap(t, quiet()), snap(t, s), cc(t)))
	if _, ok := got[vecIPConflict]; !ok {
		t.Fatalf("want %s, got %v", vecIPConflict, got)
	}
	if _, ok := got[vecImpersonation]; ok {
		t.Error("a non-gateway conflict was reported as router impersonation")
	}
}

// One device announcing itself repeatedly is normal - every host does it on
// link-up. Only a contradiction is evidence.
func TestOneClaimantIsNeverAFinding(t *testing.T) {
	s := quiet()
	s.Captured = true
	s.Claims = map[string]map[string]int{
		"10.0.4.1":  {router: 30},
		"10.0.4.50": {"aa:bb:cc:dd:ee:01": 12},
	}
	if fs := (Probe{}).Compare(snap(t, quiet()), snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("unanimous claims produced %v", vectors(fs))
	}
}

// At tier 3 there are no claims at all. That must read as "did not listen",
// never as "listened and heard no argument".
func TestNoCaptureMeansNoWireFindings(t *testing.T) {
	s := quiet()
	s.Captured = false
	s.Claims = nil
	if fs := (Probe{}).Compare(snap(t, quiet()), snap(t, s), cc(t)); len(fs) != 0 {
		t.Fatalf("tier 3 produced wire findings: %v", vectors(fs))
	}
}

// The counts are the tell: a spoofer has to out-shout the device it is
// drowning out, so the evidence must lead with the loudest.
func TestClaimDescriptionLeadsWithTheLoudest(t *testing.T) {
	got := describeClaims(map[string]int{router: 2, attacker: 47})
	if !strings.HasPrefix(got, attacker) {
		t.Errorf("description = %q, want the busiest claimant first", got)
	}
	if !strings.Contains(got, "x47") || !strings.Contains(got, "x2") {
		t.Errorf("description lost the counts: %q", got)
	}
	if !strings.Contains(got, "Raspberry Pi") || !strings.Contains(got, "Synology") {
		t.Errorf("description lost the vendor hints: %q", got)
	}
}
