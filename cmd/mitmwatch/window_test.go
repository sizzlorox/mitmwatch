package main

import (
	"testing"
	"time"
)

// The daemon's whole justification is time on the wire. Its doc comment
// promised a longer window than the one-shot check and nothing implemented it,
// so both commands listened for five seconds - a 4% duty cycle, which misses
// anything that happens once rather than repeatedly.
func TestSensorListensForMostOfItsCycle(t *testing.T) {
	const (
		tick  = 2 * time.Minute
		floor = 5 * time.Second // the one-shot default
	)
	w := sensorWindow(tick, floor)

	if w <= floor {
		t.Fatalf("sensor window is %s, no better than the one-shot %s - the daemon buys nothing", w, floor)
	}
	if duty := float64(w) / float64(tick); duty < 0.5 {
		t.Errorf("listening %s of every %s is a %.0f%% duty cycle; a one-off DHCP offer or "+
			"router advertisement lands in the gap", w, tick, duty*100)
	}
	// It must still leave room for the probes that do not read the wire, and
	// for the profile write, or a pass overruns its own interval.
	if w >= tick {
		t.Errorf("window %s leaves no headroom inside a %s cycle", w, tick)
	}
}

func TestSensorWindowNeverShorterThanConfigured(t *testing.T) {
	// An operator who asked for a long one-shot window must not be given less
	// by the daemon.
	if w := sensorWindow(30*time.Second, 45*time.Second); w != 45*time.Second {
		t.Errorf("window %s is shorter than the configured %s", w, 45*time.Second)
	}
	// And a tick shorter than the headroom must not produce a negative window.
	if w := sensorWindow(10*time.Second, 5*time.Second); w < 5*time.Second {
		t.Errorf("window %s is not positive for a short tick", w)
	}
}

// A capture socket held open for an hour is its own problem: nothing drains for
// that long, and a pass that never ends never reports.
func TestSensorWindowIsCapped(t *testing.T) {
	if w := sensorWindow(6*time.Hour, 5*time.Second); w > 5*time.Minute {
		t.Errorf("window %s is uncapped for a very long interval", w)
	}
}

// The buffer has to grow with the window or a longer listen turns into more
// dropped frames rather than more evidence - which would be the same
// silence-looks-like-success failure in a new place.
func TestFrameBufferScalesWithTheWindow(t *testing.T) {
	short := frameBuffer(5 * time.Second)
	long := frameBuffer(90 * time.Second)

	if long <= short {
		t.Errorf("buffer did not grow with the window: %d at 5s, %d at 90s", short, long)
	}
	// Measured on a real segment: roughly twenty multicast and ARP frames a
	// second. A 90s window must hold well over that.
	if want := 90 * 20; long < want {
		t.Errorf("buffer %d holds less than the %d frames a busy 90s window produces", long, want)
	}
	if short < 2048 {
		t.Errorf("buffer %d fell below the floor for a short window", short)
	}
	if huge := frameBuffer(2 * time.Hour); huge > 16384 {
		t.Errorf("buffer %d is unbounded for a long window", huge)
	}
}
