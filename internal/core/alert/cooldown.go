package alert

import (
	"sort"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
)

// Cooldown decides whether a finding has been pushed recently enough to stay
// quiet about.
//
// The log sink never needed this: a log is a record, and a record with gaps is
// not one. A notification is the opposite - it interrupts a person, and the
// second identical interruption is worth less than the first. A resident sensor
// checking every two minutes with an active spoof underway would otherwise push
// seven hundred notifications a day about one fact, and by the second morning
// the household has muted the topic. That is a worse outcome than never having
// sent anything, because the muting also covers the next, different alert.
//
// So each finding is pushed, then held for Window, then pushed again - the
// repeat matters, because a condition that is still true at breakfast is worth
// re-stating - and cleared when it stops appearing. State lives in the profile
// beside the accept list, because a cooldown that resets whenever the process
// restarts is not a cooldown at all: the sensor restarts on every upgrade, and
// a crash loop would turn into a notification loop.
type Cooldown struct {
	// Window is how long the same finding stays quiet after being pushed.
	Window time.Duration
	// Sent maps a finding hash to when it was last delivered.
	Sent map[string]time.Time
	// Now is injectable for tests.
	Now func() time.Time
}

// DefaultWindow is deliberately long. Six hours means a persistent condition is
// re-stated about four times a day - enough that it cannot be forgotten, few
// enough that it is never noise.
const DefaultWindow = 6 * time.Hour

// NewCooldown restores from stored state, tolerating a nil map.
func NewCooldown(sent map[string]time.Time, window time.Duration) *Cooldown {
	if window <= 0 {
		window = DefaultWindow
	}
	if sent == nil {
		sent = map[string]time.Time{}
	}
	return &Cooldown{Window: window, Sent: sent, Now: time.Now}
}

func (c *Cooldown) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Filter returns the alerts that should actually be pushed, trimmed to the
// findings within them that are not in cooldown.
//
// An alert whose findings are all suppressed is dropped entirely rather than
// sent empty. The score is recomputed from what survives, so a notification
// never claims a severity built mostly from facts it is not showing.
func (c *Cooldown) Filter(alerts []verdict.Alert) []verdict.Alert {
	now := c.now()
	var out []verdict.Alert

	for _, a := range alerts {
		kept := a
		kept.Findings = nil
		score := 0
		for _, f := range a.Findings {
			h := f.Hash()
			if last, ok := c.Sent[h]; ok && now.Sub(last) < c.Window {
				continue
			}
			kept.Findings = append(kept.Findings, f)
			score += f.Score
		}
		if len(kept.Findings) == 0 {
			continue
		}
		kept.Score = score
		kept.Band = verdict.BandOf(score)
		out = append(out, kept)
	}
	return out
}

// Record marks these findings as delivered. Called only after a successful
// send: a push that failed must be retried, not suppressed.
func (c *Cooldown) Record(alerts []verdict.Alert) {
	now := c.now()
	for _, a := range alerts {
		for _, f := range a.Findings {
			c.Sent[f.Hash()] = now
		}
	}
}

// Forget drops state for findings that no longer appear, so a condition that
// clears and returns is announced again immediately rather than waiting out a
// window it started before it went away.
//
// live is every finding hash observed this pass, suppressed or not.
func (c *Cooldown) Forget(live map[string]bool) {
	for h := range c.Sent {
		if !live[h] {
			delete(c.Sent, h)
		}
	}
}

// Prune bounds the stored state. Without it a network that produces a slow
// drip of one-off findings grows the profile file forever.
func (c *Cooldown) Prune(max int) {
	if max <= 0 || len(c.Sent) <= max {
		return
	}
	type entry struct {
		hash string
		when time.Time
	}
	all := make([]entry, 0, len(c.Sent))
	for h, w := range c.Sent {
		all = append(all, entry{h, w})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].when.After(all[j].when) })
	for _, e := range all[max:] {
		delete(c.Sent, e.hash)
	}
}
