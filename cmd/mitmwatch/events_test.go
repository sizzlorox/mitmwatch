package main

import (
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func evEnv() *env {
	return &env{
		profile:         &baseline.Profile{},
		net:             osq.NetworkIdentity{GatewayIP: "192.0.2.1"},
		erroredThisPass: map[string]bool{},
	}
}

func resultWith(as ...verdict.Alert) verdict.Result { return verdict.Result{Alerts: as} }

func nameresAlert(target string) verdict.Alert {
	return verdict.Alert{
		Target: target, Band: verdict.High, Score: 70,
		Findings: []probe.Finding{{
			Probe: "nameres", Vector: "nameres/answers-everything", Score: 70,
			Target: target,
			Title:  "A device on your network is answering to names that are not its own",
			Evidence: map[string]string{
				"address":    target,
				"hardware":   "5c:52:30:11:22:33",
				"name_count": "5",
				"what_to_do": "disconnect what you do not recognise",
			},
		}},
	}
}

func lastOfKind(evs []baseline.Event, kind string) *baseline.Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == kind {
			return &evs[i]
		}
	}
	return nil
}

// The complaint this exists for. An alert clears, the card goes green, the
// alert card disappears, and the only thing left is a log line. That line has to
// still say which machine it was and what was actually seen.
func TestAClearedAlertStillSaysWhichDeviceAndWhatWasSeen(t *testing.T) {
	e := evEnv()
	e.profile.RecordDevices(when, []baseline.Device{{
		MAC: "dc:a6:32:11:22:33", Addrs: []string{"192.0.2.10"}, Name: "workshop-pc",
	}})

	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{nameresAlert("192.0.2.10")}})
	raised := lastOfKind(e.events, "alert")
	if raised == nil {
		t.Fatal("no alert event was recorded")
	}
	if raised.Device != "workshop-pc (192.0.2.10)" {
		t.Errorf("alert names the device as %q; the household cannot act on that", raised.Device)
	}
	if raised.Evidence["name_count"] != "5" || raised.Band != "high" {
		t.Errorf("alert event lost its evidence or band: %+v", raised)
	}
	if len(raised.Vectors) != 1 || raised.Vectors[0] != "nameres/answers-everything" {
		t.Errorf("alert event did not record which check fired: %v", raised.Vectors)
	}
	if len(raised.Hashes) != 1 || raised.Hashes[0] == "" {
		t.Error("alert event did not record the hash, which is what `baseline accept` takes")
	}

	// The condition stops.
	e.recordEvents(verdict.Result{})
	cleared := lastOfKind(e.events, "clear")
	if cleared == nil {
		t.Fatal("the alert cleared without a clear event")
	}
	if cleared.Device != "workshop-pc (192.0.2.10)" {
		t.Errorf("the clear entry says %q rather than naming the device", cleared.Device)
	}
	if cleared.Evidence["hardware"] != "5c:52:30:11:22:33" {
		t.Error("the clear entry dropped the evidence; all that is left of the alert is that it happened")
	}
	if cleared.Text == "Resolved: 192.0.2.10" {
		t.Error("the clear entry is still a bare address")
	}
}

// A finding that vanished because its probe went blind has not been resolved.
// Saying so is the failure this project names as its most repeated.
func TestAlertLostToABlindProbeIsStaleNotResolved(t *testing.T) {
	e := evEnv()
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{nameresAlert("192.0.2.10")}})

	e.erroredThisPass["nameres"] = true
	e.recordEvents(verdict.Result{})

	if lastOfKind(e.events, "clear") != nil {
		t.Fatal("a finding that disappeared because capture died was reported as resolved")
	}
	stale := lastOfKind(e.events, "stale")
	if stale == nil {
		t.Fatal("no stale event was recorded")
	}
	if stale.Text != "No longer being checked: A device on your network is answering to names that are not its own" {
		t.Errorf("stale text = %q", stale.Text)
	}
}

// The false-positive pair for the guard above: a genuine resolution must still
// be reported as one, or every alert would hang around forever.
func TestAlertThatGenuinelyStoppedIsReportedResolved(t *testing.T) {
	e := evEnv()
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{nameresAlert("192.0.2.10")}})

	// The probe ran fine this pass and found nothing.
	e.erroredThisPass["arp"] = true // a different probe failing must not matter
	e.recordEvents(verdict.Result{})

	if lastOfKind(e.events, "stale") != nil {
		t.Error("an unrelated probe's failure turned a real resolution into 'no longer being checked'")
	}
	if lastOfKind(e.events, "clear") == nil {
		t.Error("a condition that genuinely stopped was never reported as resolved")
	}
}

func TestEveryFindingOnATargetIsRecordedNotJustTheFirst(t *testing.T) {
	e := evEnv()
	a := nameresAlert("192.0.2.10")
	a.Findings = append(a.Findings, probe.Finding{
		Probe: "arp", Vector: "arp/gateway-mac-changed", Score: 60, Target: "192.0.2.10",
		Title: "Something else is claiming to be your router",
	})
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{a}})

	got := lastOfKind(e.events, "alert")
	if len(got.Vectors) != 2 || len(got.Hashes) != 2 {
		t.Fatalf("recorded %v / %v; two probes agreeing on one target is the interesting case, and each hash is separately acceptable",
			got.Vectors, got.Hashes)
	}
	// Both probes are remembered, so a later clear can ask whether either of
	// them went blind rather than only the first.
	if r := e.alerted["192.0.2.10"]; len(r.Probes) != 2 {
		t.Errorf("kept %v as the contributing probes", r.Probes)
	}
}

// The held list exists so that suppression is visible. A detector that hides
// its own suppressions cannot be trusted about anything else.
func TestHeldFindingsReachTheLog(t *testing.T) {
	e := evEnv()
	a := nameresAlert("192.0.2.10")
	a.Suppressed = "held back while learning this network"
	e.recordEvents(verdict.Result{Held: []verdict.Alert{a}})

	held := lastOfKind(e.events, "held")
	if held == nil {
		t.Fatal("a finding suppressed by the learning window left no trace in the log")
	}
	if held.Evidence["name_count"] != "5" {
		t.Error("the held entry dropped the evidence")
	}

	// And it is logged once, not on every cycle for the whole window.
	e.recordEvents(verdict.Result{Held: []verdict.Alert{a}})
	n := 0
	for _, ev := range e.events {
		if ev.Kind == "held" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the same held finding was logged %d times; the log would drown in it", n)
	}
}

// A card that greys out to say a check could not run, while the log beside it
// stays silent, is the page disagreeing with itself.
func TestACheckThatCouldNotRunReachesTheLog(t *testing.T) {
	e := evEnv()
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{{
		Target: "192.0.2.1", Band: verdict.Info, Score: 5,
		Findings: []probe.Finding{{
			Probe: "arp", Vector: "arp/gateway-unresolved", Score: 5,
			Title: "The router's hardware address could not be read",
		}},
	}}})
	if lastOfKind(e.events, "alert") == nil {
		t.Error("a check that stopped running was not recorded, while its card on the same page turns grey")
	}
}

// A routine Info finding - a certificate rotating - is not something that
// changed, and must not fill the log with entries that read as incidents.
func TestRoutineInfoFindingIsNotActivity(t *testing.T) {
	e := evEnv()
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{{
		Target: "github.com", Band: verdict.Info, Score: 5,
		Findings: []probe.Finding{{
			Probe: "tls", Vector: "tls/leaf-rotated", Score: 5,
			Title: "The certificate for github.com changed, from the same issuer",
		}},
	}}})
	if len(e.events) != 0 {
		t.Errorf("a routine certificate rotation was logged as activity: %+v", e.events)
	}
}

// The finding's evidence map outlives this call inside e.recent; a later cycle
// rewriting it must not silently rewrite what the log says happened.
func TestEvidenceIsCopiedNotAliased(t *testing.T) {
	e := evEnv()
	a := nameresAlert("192.0.2.10")
	e.recordEvents(verdict.Result{Alerts: []verdict.Alert{a}})

	a.Findings[0].Evidence["name_count"] = "999"
	if got := lastOfKind(e.events, "alert").Evidence["name_count"]; got != "5" {
		t.Errorf("the stored event changed to %q when the finding was mutated afterwards", got)
	}
}

func TestTheLogIsBounded(t *testing.T) {
	e := evEnv()
	for i := 0; i < baseline.MaxEvents+40; i++ {
		e.addEvent(baseline.Event{Kind: "system", Text: "tick"})
	}
	if len(e.events) > baseline.MaxEvents {
		t.Errorf("in-memory log grew to %d entries", len(e.events))
	}
	if e.eventsTotal != baseline.MaxEvents+40 {
		t.Errorf("total is %d; the page needs the real count to say what it is not showing", e.eventsTotal)
	}
}
