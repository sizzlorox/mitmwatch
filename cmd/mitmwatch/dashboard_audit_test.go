package main

import (
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/web"
)

func TestDashboardAuditLabelsFindingsAndTimings(t *testing.T) {
	e := &env{}
	alerts := []verdict.Alert{{
		Target: "example.com", Band: verdict.High,
		Findings: []probe.Finding{
			{Probe: "tls", Vector: "tls/witness-root-mismatch", Target: "example.com", Title: "Outside differs"},
			{Probe: "nameres", Vector: "nameres/answers-everything", Target: "192.0.2.5", Title: "Local name conflict"},
		},
	}}
	held := []verdict.Alert{{
		Target: "192.0.2.8", Band: verdict.Medium,
		Findings: []probe.Finding{{Probe: "arp", Vector: "arp/ip-conflict", Target: "192.0.2.8", Title: "Address conflict"}},
	}}
	findings := e.dashboardFindings(alerts, held)
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	byTitle := make(map[string]web.AuditFinding, len(findings))
	for _, finding := range findings {
		byTitle[finding.Title] = finding
	}
	if finding := byTitle["Outside differs"]; finding.Vantage != "Outside" || finding.Device != "example.com" {
		t.Errorf("outside finding was mislabelled: %#v", finding)
	}
	if finding := byTitle["Local name conflict"]; finding.Vantage != "Inside" || finding.Device != "192.0.2.5" {
		t.Errorf("inside finding was mislabelled: %#v", finding)
	}
	if !byTitle["Address conflict"].Held {
		t.Error("learning-held finding was not marked as held")
	}

	wv := probe.NewWitnessView(true, true, false, "", time.Now(), nil, nil,
		map[string]time.Duration{"tls": 250 * time.Millisecond}).
		WithCheckStatus(map[string]string{"tls": "complete"})
	checks := dashboardChecks(map[string]auditCheck{
		"arp": {duration: 12 * time.Millisecond, status: "complete", when: time.Now()},
	}, wv)
	if len(checks) != 2 || checks[0].Vantage != "Inside" || checks[1].Vantage != "Outside" {
		t.Fatalf("unexpected check timings: %#v", checks)
	}
	if checks[1].Duration != 250*time.Millisecond || checks[1].Status != "complete" {
		t.Errorf("outside timing lost its value or status: %#v", checks[1])
	}
}
