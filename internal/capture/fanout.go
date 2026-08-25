package capture

import (
	"context"
	"sort"
	"sync"

	"github.com/sizzlorox/mitmwatch/internal/frame"
)

// Fanout copies one frame stream to several consumers.
//
// There is exactly one capture socket, and several probes need to see the same
// traffic: arp wants ARP, dhcp wants UDP 67/68, name resolution wants the
// multicast ports. Opening a socket each would multiply the kernel's work and
// give each probe a different, unreconcilable view of the same instant.
//
// Every subscriber gets its own buffered channel and is isolated from the
// others: a probe that stops reading loses its own frames and nobody else's.
// That isolation is the point. Without it one slow consumer stalls the reader,
// the kernel ring overflows, and every probe silently misses evidence - which
// looks exactly like a quiet network.
type Fanout struct {
	src <-chan frame.Frame

	mu      sync.Mutex
	outs    map[string]chan frame.Frame
	dropped map[string]uint64
	started bool
	closed  bool
}

// NewFanout wraps a source stream. Subscribe before calling Run.
func NewFanout(src <-chan frame.Frame) *Fanout {
	return &Fanout{
		src:     src,
		outs:    map[string]chan frame.Frame{},
		dropped: map[string]uint64{},
	}
}

// Subscribe returns the channel a named consumer should read.
//
// buf is how far behind that consumer may fall before it starts losing frames.
// Subscribing after Run has started returns a closed channel rather than one
// that silently never fills: a probe reading nothing must not be able to
// mistake it for an idle network.
func (f *Fanout) Subscribe(name string, buf int) <-chan frame.Frame {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started {
		ch := make(chan frame.Frame)
		close(ch)
		return ch
	}
	if ch, ok := f.outs[name]; ok {
		return ch
	}
	if buf <= 0 {
		buf = 256
	}
	ch := make(chan frame.Frame, buf)
	f.outs[name] = ch
	return ch
}

// Run distributes frames until the source closes or ctx is done, then closes
// every subscriber channel so their readers terminate.
func (f *Fanout) Run(ctx context.Context) {
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	defer f.closeAll()

	if f.src == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case fr, ok := <-f.src:
			if !ok {
				return
			}
			f.deliver(fr)
		}
	}
}

func (f *Fanout) deliver(fr frame.Frame) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, ch := range f.outs {
		select {
		case ch <- fr:
		default:
			// This consumer is behind. Count it and move on: blocking here
			// would punish every other probe for one slow reader.
			f.dropped[name]++
		}
	}
}

func (f *Fanout) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	for _, ch := range f.outs {
		close(ch)
	}
}

// Dropped reports how many frames each consumer missed. A non-zero count means
// that probe's window is incomplete, and its findings are a floor rather than a
// full account - worth saying out loud rather than absorbing.
func (f *Fanout) Dropped() map[string]uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]uint64, len(f.dropped))
	for k, v := range f.dropped {
		if v > 0 {
			out[k] = v
		}
	}
	return out
}

// Consumers lists the subscriber names, sorted, for deterministic reporting.
func (f *Fanout) Consumers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.outs))
	for k := range f.outs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
