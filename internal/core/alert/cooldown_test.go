package alert

import (
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func finding(vector, target string, score int) probe.Finding {
	return probe.Finding{
		Probe: "t", Vector: vector, Target: target, Score: score,
		Identity: map[string]string{"k": vector + target},
	}
}

func alertOf(target string, fs ...probe.Finding) verdict.Alert {
	score := 0
	for _, f := range fs {
		score += f.Score
	}
	return verdict.Alert{Target: target, Score: score, Band: verdict.BandOf(score), Findings: fs}
}

func at(c *Cooldown, t time.Time) { c.Now = func() time.Time { return t } }

func TestFirstAlertIsDelivered(t *testing.T) {
	c := NewCooldown(nil, time.Hour)
	got := c.Filter([]verdict.Alert{alertOf("10.0.4.1", finding("arp/x", "10.0.4.1", 60))})
	if len(got) != 1 {
		t.Fatalf("a new finding was suppressed: %v", got)
	}
}

// The failure this exists to prevent: a two-minute sensor with an active spoof
// pushing seven hundred notifications a day about one fact.
func TestRepeatWithinWindowIsSuppressed(t *testing.T) {
	c := NewCooldown(nil, 6*time.Hour)
	start := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	at(c, start)

	a := []verdict.Alert{alertOf("10.0.4.1", finding("arp/x", "10.0.4.1", 60))}
	c.Record(c.Filter(a))

	for i := 1; i <= 180; i++ { // six hours at two-minute intervals
		at(c, start.Add(time.Duration(i)*2*time.Minute))
		if got := c.Filter(a); len(got) != 0 && time.Duration(i)*2*time.Minute < 6*time.Hour {
			t.Fatalf("pushed again after %v, inside the window", time.Duration(i)*2*time.Minute)
		}
	}
}

// A condition still true at breakfast is worth re-stating.
func TestRepeatAfterWindowIsDeliveredAgain(t *testing.T) {
	c := NewCooldown(nil, 6*time.Hour)
	start := time.Now()
	at(c, start)
	a := []verdict.Alert{alertOf("10.0.4.1", finding("arp/x", "10.0.4.1", 60))}
	c.Record(c.Filter(a))

	at(c, start.Add(6*time.Hour+time.Minute))
	if got := c.Filter(a); len(got) != 1 {
		t.Fatal("a condition that is still true was never re-stated")
	}
}

// A push that failed must be retried, not silenced for six hours.
func TestFailedDeliveryIsNotRecorded(t *testing.T) {
	c := NewCooldown(nil, time.Hour)
	a := []verdict.Alert{alertOf("10.0.4.1", finding("arp/x", "10.0.4.1", 60))}
	due := c.Filter(a)
	c.Record(nil) // delivery failed: nothing recorded

	if got := c.Filter(a); len(got) != len(due) {
		t.Fatal("a failed push was treated as delivered and suppressed")
	}
}

// An alert whose findings are all suppressed must be dropped, not sent empty.
func TestFullySuppressedAlertIsDropped(t *testing.T) {
	c := NewCooldown(nil, time.Hour)
	a := []verdict.Alert{alertOf("10.0.4.1", finding("arp/x", "10.0.4.1", 60))}
	c.Record(c.Filter(a))
	if got := c.Filter(a); len(got) != 0 {
		t.Fatalf("an empty alert was still sent: %v", got)
	}
}

// The score must be recomputed from what survives, or a notification claims a
// severity built mostly from facts it is not showing.
func TestScoreIsRecomputedFromSurvivingFindings(t *testing.T) {
	c := NewCooldown(nil, time.Hour)
	old := finding("arp/old", "10.0.4.1", 60)
	fresh := finding("arp/new", "10.0.4.1", 10)

	c.Record([]verdict.Alert{alertOf("10.0.4.1", old)})

	got := c.Filter([]verdict.Alert{alertOf("10.0.4.1", old, fresh)})
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(got))
	}
	if got[0].Score != 10 {
		t.Errorf("score = %d, want 10 - only the surviving finding", got[0].Score)
	}
	if got[0].Band != verdict.Info {
		t.Errorf("band = %v, want the band of what is actually shown", got[0].Band)
	}
	if len(got[0].Findings) != 1 || got[0].Findings[0].Vector != "arp/new" {
		t.Errorf("wrong findings survived: %v", got[0].Findings)
	}
}

// A condition that clears and returns is news again immediately, rather than
// waiting out a window it started before it went away.
func TestClearedConditionIsAnnouncedAgainOnReturn(t *testing.T) {
	c := NewCooldown(nil, 6*time.Hour)
	start := time.Now()
	at(c, start)
	f := finding("arp/x", "10.0.4.1", 60)
	a := []verdict.Alert{alertOf("10.0.4.1", f)}
	c.Record(c.Filter(a))

	// It goes away: no longer live.
	c.Forget(map[string]bool{})

	at(c, start.Add(time.Minute))
	if got := c.Filter(a); len(got) != 1 {
		t.Fatal("a condition that cleared and returned stayed silent")
	}
}

// While it is still live, forgetting must not reset the clock, or a persistent
// finding is pushed on every single pass.
func TestStillLiveFindingKeepsItsCooldown(t *testing.T) {
	c := NewCooldown(nil, 6*time.Hour)
	f := finding("arp/x", "10.0.4.1", 60)
	a := []verdict.Alert{alertOf("10.0.4.1", f)}
	c.Record(c.Filter(a))

	c.Forget(map[string]bool{f.Hash(): true})
	if got := c.Filter(a); len(got) != 0 {
		t.Fatal("a still-live finding had its cooldown reset")
	}
}

// State bounded, newest kept: a slow drip of one-off findings must not grow the
// profile file forever.
func TestPruneKeepsTheNewest(t *testing.T) {
	c := NewCooldown(nil, time.Hour)
	base := time.Now()
	for i := 0; i < 20; i++ {
		c.Sent[string(rune('a'+i))] = base.Add(time.Duration(i) * time.Minute)
	}
	c.Prune(5)
	if len(c.Sent) != 5 {
		t.Fatalf("kept %d entries, want 5", len(c.Sent))
	}
	if _, ok := c.Sent[string(rune('a'+19))]; !ok {
		t.Error("the newest entry was pruned")
	}
	if _, ok := c.Sent["a"]; ok {
		t.Error("the oldest entry survived")
	}
}

func TestNilStateAndZeroWindowAreSafe(t *testing.T) {
	c := NewCooldown(nil, 0)
	if c.Window != DefaultWindow {
		t.Errorf("window = %v, want the default", c.Window)
	}
	c.Prune(0)
	c.Forget(nil)
	if got := c.Filter(nil); got != nil {
		t.Errorf("filtering nothing produced %v", got)
	}
}
