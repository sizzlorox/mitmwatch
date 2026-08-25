package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func sample() verdict.Alert {
	f := probe.Finding{
		Probe: "arp", Vector: "arp/gateway-mac-changed", Target: "10.0.4.1", Score: 60,
		Title:    "Something else is claiming to be your router",
		Identity: map[string]string{"was": "aa", "now": "bb"},
		Evidence: map[string]string{"what_to_do": "avoid logging in until this clears"},
	}
	return verdict.Alert{Target: "10.0.4.1", Score: 60, Band: verdict.High, Findings: []probe.Finding{f}}
}

func TestNtfyCarriesTitlePriorityAndAction(t *testing.T) {
	var gotBody, gotTitle, gotPriority string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotTitle, gotPriority = string(b), r.Header.Get("Title"), r.Header.Get("Priority")
	}))
	defer srv.Close()

	if err := (Ntfy{Topic: srv.URL, Client: srv.Client()}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotTitle, "claiming to be your router") {
		t.Errorf("title = %q, want the plain-language finding", gotTitle)
	}
	// Somebody woken by this needs an action, not a score.
	if !strings.Contains(gotBody, "avoid logging in") {
		t.Errorf("body lost the advice: %q", gotBody)
	}
	if gotPriority != "high" {
		t.Errorf("priority = %q, want high for a High band", gotPriority)
	}
}

func TestNtfyPriorityTracksBand(t *testing.T) {
	for band, want := range map[verdict.Band]string{
		verdict.Critical: "urgent", verdict.High: "high",
		verdict.Medium: "default", verdict.Low: "low", verdict.Info: "low",
	} {
		if got := ntfyPriority(band); got != want {
			t.Errorf("band %v -> %q, want %q", band, got, want)
		}
	}
}

func TestNtfyReportsHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := (Ntfy{Topic: srv.URL, Client: srv.Client()}).Send(context.Background(), sample()); err == nil {
		t.Fatal("a 500 was reported as success; the alert would be silently lost " +
			"and the cooldown would suppress the retry")
	}
}

func TestWebhookShapeIsStable(t *testing.T) {
	var got payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got) //nolint:errcheck
	}))
	defer srv.Close()

	if err := (Webhook{URL: srv.URL, Client: srv.Client()}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if got.Target != "10.0.4.1" || got.Band != "high" || got.Score != 60 {
		t.Errorf("envelope wrong: %+v", got)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	f := got.Findings[0]
	if f.Vector != "arp/gateway-mac-changed" || f.Hash == "" || f.Evidence["what_to_do"] == "" {
		t.Errorf("finding wrong: %+v", f)
	}
}

// A sink the user believes is active but is not means alerts vanish silently.
func TestMisconfiguredSinksAreErrorsNotWarnings(t *testing.T) {
	for name, mut := range map[string]func(*config.Config){
		"ntfy with no topic":  func(c *config.Config) { c.Alerts.Sinks = []string{"ntfy"} },
		"webhook with no url": func(c *config.Config) { c.Alerts.Sinks = []string{"webhook"} },
		"unknown sink":        func(c *config.Config) { c.Alerts.Sinks = []string{"carrier-pigeon"} },
	} {
		cfg := config.Defaults()
		mut(cfg)
		if _, err := Sinks(cfg, io.Discard); err == nil {
			t.Errorf("%s was accepted silently", name)
		}
	}
}

func TestConfiguredSinksAreBuilt(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Sinks = []string{"log", "ntfy", "webhook"}
	cfg.Alerts.NtfyTopic = "https://ntfy.example/topic"
	cfg.Alerts.Webhook = "https://example.invalid/hook"

	sinks, err := Sinks(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range sinks {
		names[s.Name()] = true
	}
	for _, want := range []string{"log", "ntfy", "webhook"} {
		if !names[want] {
			t.Errorf("sink %q was not built", want)
		}
	}
}

// The log is a record, and a record with gaps is not one - so it is always
// present even when the config does not name it.
func TestLogIsAlwaysPresent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Sinks = nil
	sinks, err := Sinks(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(sinks) != 1 || sinks[0].Name() != "log" {
		t.Fatalf("got %v, want just the log", sinks)
	}
}

func TestLogRendersEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := (Log{W: &buf}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"HIGH", "10.0.4.1", "arp/gateway-mac-changed", "what_to_do"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%s", want, out)
		}
	}
}
