package web

import (
	"strings"
	"testing"
	"time"
)

// The invariant the package comment promises, made a test. A panic while
// rendering - from any of the wire-supplied text this page carries - must not
// leave the read lock held. State.Update is called synchronously from the sensor
// cycle, so a leaked read lock stops the detector, and one page load would do
// it. net/http recovers the panic per connection, so nothing else would show.
func TestAPanicWhileRenderingDoesNotLeakTheLock(t *testing.T) {
	s := NewState()
	func() {
		defer func() { _ = recover() }()
		//nolint:errcheck // the panic is the point
		s.execLocked(func(any) error { return nil }, func() any { panic("boom") })
	}()

	done := make(chan struct{})
	go func() {
		s.Update(Update{Network: "home", When: time.Now()})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a panic during render left the read lock held; the sensor cycle would block on it forever")
	}
}

// Events are the only untrusted render path that had no escaping guard, and
// enriched entries carry device names and evidence values straight off the wire.
func TestActivityPageEscapesEventTextAndEvidence(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(), EventsTotal: 1,
		Events: []Event{{
			When: time.Now(), Kind: "clear", Text: "<script>alert(1)</script>",
			Device: "<img src=x onerror=alert(2)>", Target: "10.0.4.5", Band: "high",
			Vectors:  []string{"nameres/answers-everything"},
			Evidence: map[string]string{"names": "<script>alert(3)</script>"},
		}},
	})
	code, body, _ := get(t, Handler(s), "/activity")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, bad := range []string{"<script>alert(1)</script>", "<img src=x onerror=", "<script>alert(3)</script>"} {
		if strings.Contains(body, bad) {
			t.Fatalf("%q from the wire was rendered unescaped", bad)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the values were neither escaped nor present; check they are actually rendered")
	}
	// Every evidence key, never a curated subset: a subset is how the escaping
	// guard above quietly stops guarding anything.
	if !strings.Contains(body, "names") || !strings.Contains(body, "nameres/answers-everything") {
		t.Error("the activity page dropped the evidence, or the vector that names what was found")
	}
}

// The complaint this change answers. A cleared alert leaves nothing but a log
// line, and that line has to say which machine and what was seen.
func TestActivityPageNamesTheDeviceOfAClearedAlert(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(), EventsTotal: 1,
		Events: []Event{{
			When: time.Now(), Kind: "clear",
			Text:     "A device answering to names that are not its own - resolved",
			Device:   "workshop-pc (10.0.4.112)",
			Band:     "high",
			Evidence: map[string]string{"hardware": "5c:52:30:11:22:33", "name_count": "5"},
		}},
	})
	_, body, _ := get(t, Handler(s), "/activity")
	for _, want := range []string{"workshop-pc (10.0.4.112)", "5c:52:30:11:22:33", "name_count", "high"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page cannot answer \"which device, and what was it\": missing %q", want)
		}
	}
}

// A log that has been cut off must not read as a network on which nothing else
// happened.
func TestTruncatedLogSaysHowMuchIsNotShown(t *testing.T) {
	s := NewState()
	var evs []Event
	for i := 0; i < 40; i++ {
		evs = append(evs, Event{When: time.Now(), Kind: "system", Text: "tick"})
	}
	// The sensor hands over everything it still holds; the panel shows twelve.
	s.Update(Update{Network: "home", When: time.Now(), Events: evs, EventsTotal: len(evs)})
	_, body, _ := get(t, Handler(s), "/")
	if !strings.Contains(body, "The other 28") {
		t.Error("the home panel showed 12 of 40 entries without saying what it was not showing")
	}
	if strings.Contains(body, "not kept") {
		t.Error("nothing had been dropped, but the page said older entries are not kept")
	}

	// And once the retained window fills, the count it claims must be the count
	// it can actually show.
	s.Update(Update{Network: "home", When: time.Now(), Events: evs, EventsTotal: 500})
	_, body, _ = get(t, Handler(s), "/")
	if !strings.Contains(body, "500 recorded in all") || !strings.Contains(body, "not kept") {
		t.Error("the page claimed a complete log while holding 40 of 500 entries")
	}
	_, act, _ := get(t, Handler(s), "/activity")
	if !strings.Contains(act, "The newest 40 of 500") {
		t.Error("the activity page claimed 500 entries while rendering 40")
	}
}

func TestDeviceThatIsGoneIsShownWithWhenItWasLastHere(t *testing.T) {
	s := NewState()
	now := time.Now()
	s.Update(Update{
		Network: "home", When: now,
		Devices: []Device{
			{IP: "10.0.4.5", MAC: "dc:a6:32:11:22:33", Name: "printer",
				FirstSeen: now.Add(-72 * time.Hour), LastSeen: now, Present: true},
			{IP: "10.0.4.9", MAC: "b8:27:eb:11:22:33", Name: "laptop",
				FirstSeen: now.Add(-96 * time.Hour), LastSeen: now.Add(-30 * time.Hour)},
		},
	})
	_, body, _ := get(t, Handler(s), "/")
	if !strings.Contains(body, "laptop") {
		t.Fatal("a device that is no longer connected vanished from the list; that is what history is for")
	}
	if !strings.Contains(body, "class=\"gone\"") {
		t.Error("a device that is no longer here is not distinguishable from one that is")
	}
	// The old page stamped every row with the profile's own creation time, so
	// every device claimed the same age.
	if !strings.Contains(body, "3 days ago") || !strings.Contains(body, "4 days ago") {
		t.Error("device rows do not carry their own first-seen time")
	}
}

func TestZeroTimestampsDoNotRenderAsTheZeroTime(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(),
		Devices: []Device{{IP: "10.0.4.5", MAC: "dc:a6:32:11:22:33"}},
	})
	_, body, _ := get(t, Handler(s), "/devices")
	if strings.Contains(body, "0001-01-01") || strings.Contains(body, "1970-01-01") {
		t.Error("a device with no recorded timestamp rendered as the zero time")
	}
}

// Sensor and viewer clocks differ; this project ships a clock probe because that
// drift is real. It used to read "in under a minute ago".
func TestAFutureTimestampReadsAsJustNow(t *testing.T) {
	s := NewState()
	ahead := time.Now().Add(2 * time.Hour)
	s.Update(Update{
		Network: "home", When: time.Now(),
		Devices: []Device{{IP: "10.0.4.5", MAC: "dc:a6:32:11:22:33", FirstSeen: ahead, LastSeen: ahead}},
	})
	_, body, _ := get(t, Handler(s), "/")
	if !strings.Contains(body, "just now") {
		t.Error("a timestamp ahead of the viewer's clock did not render as just now")
	}
}

func TestEmptyActivityPageSaysWhyItIsEmpty(t *testing.T) {
	code, body, _ := get(t, Handler(NewState()), "/activity")
	if code != 200 || !strings.Contains(body, "Nothing has been recorded") {
		t.Errorf("empty activity page = %d, and does not say why it is empty", code)
	}
}

// Ordering is load-bearing and had no test: the sensor appends oldest-first, and
// both views must show newest-first. Getting it backwards puts "Sensor started"
// at the top of a log whose whole job is to answer "what happened last".
func TestBothViewsShowTheNewestEntryFirst(t *testing.T) {
	s := NewState()
	base := time.Now().Add(-time.Hour)
	var evs []Event
	for i := 0; i < 20; i++ {
		evs = append(evs, Event{
			When: base.Add(time.Duration(i) * time.Minute),
			Kind: "system", Text: "entry-" + string(rune('a'+i)),
		})
	}
	// As the sensor stores them: oldest first.
	s.Update(Update{Network: "home", When: time.Now(), Events: evs, EventsTotal: len(evs)})

	for _, path := range []string{"/", "/activity"} {
		_, body, _ := get(t, Handler(s), path)
		newest := strings.Index(body, "entry-t")
		older := strings.Index(body, "entry-s")
		if newest < 0 || older < 0 {
			t.Fatalf("%s did not render the newest entries at all", path)
		}
		if newest > older {
			t.Errorf("%s lists the log oldest-first; the newest thing that happened is at the bottom", path)
		}
	}

	// And the home panel keeps the newest, not the first twelve.
	_, home, _ := get(t, Handler(s), "/")
	if strings.Contains(home, "entry-a") {
		t.Error("the home panel truncated to the OLDEST entries; it must keep the most recent")
	}
	// The full page keeps everything.
	_, all, _ := get(t, Handler(s), "/activity")
	if !strings.Contains(all, "entry-a") {
		t.Error("the activity page dropped the oldest entry; it is the full log")
	}
}
