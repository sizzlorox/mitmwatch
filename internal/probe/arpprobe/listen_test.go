package arpprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
)

// buildARP assembles a real Ethernet+ARP frame, so these tests exercise the
// same parse path as the wire rather than a hand-built claims map.
func buildARP(op uint16, senderMAC string, senderIP string, targetIP string) frame.Frame {
	mac := func(s string) [6]byte {
		var m [6]byte
		var a, b, c, d, e, f int
		if _, err := sscanHex(s, &a, &b, &c, &d, &e, &f); err != nil {
			panic(err)
		}
		m[0], m[1], m[2], m[3], m[4], m[5] = byte(a), byte(b), byte(c), byte(d), byte(e), byte(f)
		return m
	}
	sm := mac(senderMAC)
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	buf.Write(sm[:])
	binary.Write(&buf, binary.BigEndian, uint16(frame.EtherTypeARP)) //nolint:errcheck
	binary.Write(&buf, binary.BigEndian, uint16(1))                  //nolint:errcheck // ethernet
	binary.Write(&buf, binary.BigEndian, uint16(0x0800))             //nolint:errcheck // ipv4
	buf.WriteByte(6)
	buf.WriteByte(4)
	binary.Write(&buf, binary.BigEndian, op) //nolint:errcheck
	buf.Write(sm[:])
	sip := netip.MustParseAddr(senderIP).As4()
	buf.Write(sip[:])
	buf.Write(make([]byte, 6))
	tip := netip.MustParseAddr(targetIP).As4()
	buf.Write(tip[:])
	return frame.Frame{Time: time.Now(), Iface: "test", Data: buf.Bytes()}
}

func feed(t *testing.T, frames ...frame.Frame) (map[string]map[string]int, int) {
	t.Helper()
	ch := make(chan frame.Frame, len(frames))
	for _, f := range frames {
		ch <- f
	}
	close(ch)
	return listen(context.Background(), ch, 2*time.Second)
}

// The whole point: a spoofer answering for the router while the router also
// answers must show up as two claimants for one address.
func TestListenRecordsContendedGateway(t *testing.T) {
	claims, n := feed(t,
		buildARP(frame.ARPReply, router, "10.0.4.1", "10.0.4.48"),
		buildARP(frame.ARPReply, attacker, "10.0.4.1", "10.0.4.48"),
		buildARP(frame.ARPReply, attacker, "10.0.4.1", "10.0.4.48"),
	)
	if n != 3 {
		t.Fatalf("read %d frames, want 3", n)
	}
	got := claims["10.0.4.1"]
	if len(got) != 2 {
		t.Fatalf("claimants for the gateway = %v, want two", got)
	}
	if got[attacker] != 2 || got[router] != 1 {
		t.Errorf("counts wrong: %v", got)
	}
}

// A request asks a question. It says nothing about who owns the address, and
// counting it would make every host that looks up the router a claimant of it.
func TestListenIgnoresPlainRequests(t *testing.T) {
	claims, _ := feed(t, buildARP(frame.ARPRequest, attacker, "10.0.4.99", "10.0.4.1"))
	if _, ok := claims["10.0.4.1"]; ok {
		t.Error("a request for the gateway was recorded as a claim to it")
	}
}

// A gratuitous request IS an announcement, and is how many spoofers work.
func TestListenCountsGratuitousRequests(t *testing.T) {
	claims, _ := feed(t, buildARP(frame.ARPRequest, attacker, "10.0.4.1", "10.0.4.1"))
	if claims["10.0.4.1"][attacker] != 1 {
		t.Errorf("gratuitous announcement not counted: %v", claims)
	}
}

// RFC 5227 probe: all-zero sender means "is this free?". Counting it would
// report every host that joins the network.
func TestListenIgnoresAddressProbes(t *testing.T) {
	claims, _ := feed(t, buildARP(frame.ARPRequest, attacker, "0.0.0.0", "10.0.4.77"))
	if len(claims) != 0 {
		t.Errorf("an availability probe was recorded as a claim: %v", claims)
	}
}

// Garbage on the wire must cost one dropped frame, not the whole window.
func TestListenSurvivesMalformedFrames(t *testing.T) {
	good := buildARP(frame.ARPReply, router, "10.0.4.1", "10.0.4.48")
	claims, n := feed(t,
		frame.Frame{Data: []byte{0x00}},
		frame.Frame{Data: make([]byte, 14)},
		frame.Frame{Data: bytes.Repeat([]byte{0xff}, 60)},
		good,
	)
	if n != 4 {
		t.Fatalf("read %d frames, want all 4 consumed", n)
	}
	if claims["10.0.4.1"][router] != 1 {
		t.Errorf("the valid frame was lost among the malformed ones: %v", claims)
	}
}

// The window must bound the wait, or a quiet segment stalls every pass.
func TestListenStopsAtTheWindow(t *testing.T) {
	ch := make(chan frame.Frame) // never written, never closed
	start := time.Now()
	_, n := listen(context.Background(), ch, 150*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("listen ran for %s, want it bounded by the window", elapsed)
	}
	if n != 0 {
		t.Errorf("read %d frames from an empty channel", n)
	}
}

func TestListenStopsOnContextCancel(t *testing.T) {
	ch := make(chan frame.Frame)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	listen(ctx, ch, time.Hour)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("listen ignored cancellation for %s", elapsed)
	}
}
