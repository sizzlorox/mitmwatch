// Package alert delivers verdicts to the outside world.
//
// Delivery is where a detector earns or loses trust. A finding nobody sees is
// worth nothing; a finding somebody sees seven hundred times is worth less than
// nothing, because the next one is ignored too. Both failures are handled here
// rather than in the probes: probes report what is true, this decides who is
// told and how often.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
)

// Sink is one alert destination.
type Sink interface {
	Name() string
	Send(ctx context.Context, a verdict.Alert) error
}

// Log writes alerts as text. Always enabled, never rate limited: the log is the
// record, and a record with gaps is not one.
type Log struct{ W io.Writer }

func (l Log) Name() string { return "log" }

func (l Log) Send(_ context.Context, a verdict.Alert) error {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s  score=%d\n", strings.ToUpper(a.Band.String()), a.Target, a.Score)
	for _, f := range a.Findings {
		fmt.Fprintf(&b, "  %-28s %+4d  %s  (%s)\n", f.Vector, f.Score, f.Title, f.Hash())
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "      %-18s %s\n", k, f.Evidence[k])
		}
	}
	_, err := io.WriteString(l.W, b.String())
	return err
}

// Ntfy pushes to an ntfy topic.
//
// Chosen because it needs no account, no app registration and no API key: a URL
// is the whole configuration. For a tool a household installs once, anything
// requiring an account is a step at which people stop.
type Ntfy struct {
	Topic  string
	Client *http.Client
}

func (n Ntfy) Name() string { return "ntfy" }

func (n Ntfy) Send(ctx context.Context, a verdict.Alert) error {
	body := plainBody(a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.Topic, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", alertTitle(a))
	req.Header.Set("Priority", ntfyPriority(a.Band))
	req.Header.Set("Tags", ntfyTag(a.Band))
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := n.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // drain
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: http %d", resp.StatusCode)
	}
	return nil
}

func (n Ntfy) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func ntfyPriority(b verdict.Band) string {
	switch b {
	case verdict.Critical:
		return "urgent"
	case verdict.High:
		return "high"
	case verdict.Medium:
		return "default"
	}
	return "low"
}

func ntfyTag(b verdict.Band) string {
	switch b {
	case verdict.Critical:
		return "rotating_light"
	case verdict.High:
		return "warning"
	}
	return "mag"
}

// Webhook posts the alert as JSON, for anything that is not ntfy.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w Webhook) Name() string { return "webhook" }

// payload is the wire shape. Declared explicitly rather than marshalling the
// verdict types directly, so that an internal refactor cannot silently change
// somebody's integration.
type payload struct {
	Target   string    `json:"target"`
	Band     string    `json:"band"`
	Score    int       `json:"score"`
	Time     time.Time `json:"time"`
	Findings []struct {
		Probe    string            `json:"probe"`
		Vector   string            `json:"vector"`
		Score    int               `json:"score"`
		Title    string            `json:"title"`
		Hash     string            `json:"hash"`
		Evidence map[string]string `json:"evidence"`
	} `json:"findings"`
}

func (w Webhook) Send(ctx context.Context, a verdict.Alert) error {
	p := payload{Target: a.Target, Band: a.Band.String(), Score: a.Score, Time: time.Now().UTC()}
	for _, f := range a.Findings {
		p.Findings = append(p.Findings, struct {
			Probe    string            `json:"probe"`
			Vector   string            `json:"vector"`
			Score    int               `json:"score"`
			Title    string            `json:"title"`
			Hash     string            `json:"hash"`
			Evidence map[string]string `json:"evidence"`
		}{f.Probe, f.Vector, f.Score, f.Title, f.Hash(), f.Evidence})
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // drain
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: http %d", resp.StatusCode)
	}
	return nil
}

func alertTitle(a verdict.Alert) string {
	if len(a.Findings) > 0 {
		return a.Findings[0].Title
	}
	return strings.ToUpper(a.Band.String()) + " on " + a.Target
}

// plainBody is what a person reads on a phone screen. It leads with what to do,
// because somebody woken by this needs an action, not a score.
func plainBody(a verdict.Alert) string {
	var b strings.Builder
	for i, f := range a.Findings {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(f.Title)
		if act := f.Evidence["what_to_do"]; act != "" {
			b.WriteString("\n-> ")
			b.WriteString(act)
		}
	}
	fmt.Fprintf(&b, "\n\n%s on %s (score %d)", strings.ToUpper(a.Band.String()), a.Target, a.Score)
	return b.String()
}

// Sinks builds the configured destinations.
//
// An unknown or misconfigured name is an error rather than a warning. A sink the
// user believes is active but is not means alerts vanish silently, which is the
// one failure this package must never have.
func Sinks(cfg *config.Config, w io.Writer) ([]Sink, error) {
	out := []Sink{Log{W: w}}
	for _, name := range cfg.Alerts.Sinks {
		switch name {
		case "log":
			// always present
		case "ntfy":
			if cfg.Alerts.NtfyTopic == "" {
				return nil, fmt.Errorf("alert sink %q is enabled but [alerts] ntfy_topic is empty", name)
			}
			out = append(out, Ntfy{Topic: cfg.Alerts.NtfyTopic})
		case "webhook":
			if cfg.Alerts.Webhook == "" {
				return nil, fmt.Errorf("alert sink %q is enabled but [alerts] webhook is empty", name)
			}
			out = append(out, Webhook{URL: cfg.Alerts.Webhook})
		case "desktop":
			return nil, fmt.Errorf("alert sink %q is not implemented", name)
		default:
			return nil, fmt.Errorf("unknown alert sink %q", name)
		}
	}
	return out, nil
}
