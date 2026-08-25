package capture

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
)

func TestFanoutDeliversToEveryConsumer(t *testing.T) {
	src := make(chan frame.Frame, 4)
	f := NewFanout(src)
	a := f.Subscribe("arp", 8)
	b := f.Subscribe("dhcp", 8)

	for i := 0; i < 3; i++ {
		src <- frame.Frame{Data: []byte{byte(i)}}
	}
	close(src)
	f.Run(context.Background())

	for name, ch := range map[string]<-chan frame.Frame{"arp": a, "dhcp": b} {
		n := 0
		for range ch {
			n++
		}
		if n != 3 {
			t.Errorf("%s received %d frames, want 3", name, n)
		}
	}
}

// The isolation property: a probe that stops reading loses its own frames and
// nobody else's. Without it one slow consumer stalls the reader, the kernel
// ring overflows, and every probe silently misses evidence.
func TestSlowConsumerDoesNotStarveTheOthers(t *testing.T) {
	src := make(chan frame.Frame)
	f := NewFanout(src)
	fast := f.Subscribe("fast", 64)
	f.Subscribe("slow", 1) // never read

	go f.Run(context.Background())

	const sent = 32
	go func() {
		for i := 0; i < sent; i++ {
			src <- frame.Frame{Data: []byte{byte(i)}}
		}
		close(src)
	}()

	got := 0
	for range fast {
		got++
	}
	if got != sent {
		t.Fatalf("the fast consumer received %d of %d frames; a slow peer cost it evidence", got, sent)
	}
	if d := f.Dropped(); d["slow"] == 0 {
		t.Error("the slow consumer's losses were not counted, so they would never be reported")
	}
	if d := f.Dropped(); d["fast"] != 0 {
		t.Errorf("the fast consumer was charged with %d drops it did not have", d["fast"])
	}
}

// Closing the source must terminate every reader, or a probe ranging over its
// channel blocks until the process dies.
func TestSourceCloseClosesAllConsumers(t *testing.T) {
	src := make(chan frame.Frame)
	f := NewFanout(src)
	ch := f.Subscribe("arp", 4)
	go f.Run(context.Background())
	close(src)

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("received a frame from a closed source")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer channel never closed; a probe would block forever")
	}
}

func TestContextCancelClosesConsumers(t *testing.T) {
	src := make(chan frame.Frame) // never closed
	f := NewFanout(src)
	ch := f.Subscribe("arp", 4)
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("unexpected frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not release the consumers")
	}
}

// Subscribing late must not hand back a channel that looks idle. A probe
// reading nothing has to be able to tell "no traffic" from "not subscribed".
func TestLateSubscribeReturnsAClosedChannel(t *testing.T) {
	src := make(chan frame.Frame)
	f := NewFanout(src)
	go f.Run(context.Background())
	time.Sleep(20 * time.Millisecond)

	ch := f.Subscribe("late", 4)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("late subscriber received a frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late Subscribe returned a channel that never closes, which reads as an idle network")
	}
	close(src)
}

func TestSubscribeIsIdempotent(t *testing.T) {
	f := NewFanout(make(chan frame.Frame))
	if f.Subscribe("arp", 4) != f.Subscribe("arp", 4) {
		t.Error("subscribing twice under one name produced two channels; one would never be read")
	}
	if got := f.Consumers(); len(got) != 1 || got[0] != "arp" {
		t.Errorf("Consumers() = %v", got)
	}
}

// A nil source is what tier 3 hands over. It must terminate cleanly rather than
// block forever.
func TestNilSourceTerminates(t *testing.T) {
	f := NewFanout(nil)
	ch := f.Subscribe("arp", 4)
	done := make(chan struct{})
	go func() { f.Run(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run never returned for a nil source")
	}
	if _, ok := <-ch; ok {
		t.Error("nil source produced a frame")
	}
}

// Concurrent subscribers and delivery must not race. Run with -race.
func TestConcurrentDelivery(t *testing.T) {
	src := make(chan frame.Frame)
	f := NewFanout(src)
	names := []string{"arp", "dhcp", "nameres", "nd"}
	chans := make([]<-chan frame.Frame, len(names))
	for i, n := range names {
		chans[i] = f.Subscribe(n, 128)
	}
	go f.Run(context.Background())

	var wg sync.WaitGroup
	for _, ch := range chans {
		wg.Add(1)
		go func(ch <-chan frame.Frame) {
			defer wg.Done()
			for range ch {
			}
		}(ch)
	}
	for i := 0; i < 500; i++ {
		src <- frame.Frame{Data: []byte{byte(i)}}
	}
	close(src)
	wg.Wait()
}
