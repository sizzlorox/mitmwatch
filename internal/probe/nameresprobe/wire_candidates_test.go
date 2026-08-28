package nameresprobe

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// The exclusion is decided from two things that only exist on the wire: what
// was answered, and what anybody asked. These tests build real frames so the
// correlation is exercised, not assumed.

func encName(n string) []byte {
	var out []byte
	for _, label := range splitDots(n) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// mdnsAnswer builds a response carrying one A record per name.
func mdnsAnswer(names []string, addr net.IP) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[2:4], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(b[6:8], uint16(len(names)))
	for _, n := range names {
		b = append(b, encName(n)...)
		rr := make([]byte, 10)
		binary.BigEndian.PutUint16(rr[0:2], 1)   // A
		binary.BigEndian.PutUint16(rr[2:4], 1)   // IN
		binary.BigEndian.PutUint32(rr[4:8], 120) // the TTL browsers publish
		binary.BigEndian.PutUint16(rr[8:10], 4)
		b = append(b, rr...)
		b = append(b, addr.To4()...)
	}
	return b
}

// mdnsQuery builds a query asking about one name.
func mdnsQuery(name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, encName(name)...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], 1) // A
	binary.BigEndian.PutUint16(q[2:4], 1) // IN
	return append(b, q...)
}

// udp wraps a payload in ethernet/IPv4/UDP, which is what the probe parses.
func udp(t *testing.T, srcMAC string, srcIP net.IP, payload []byte) frame.Frame {
	t.Helper()
	mac, err := net.ParseMAC(srcMAC)
	if err != nil {
		t.Fatal(err)
	}
	eth := append(append([]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, mac...), 0x08, 0x00)

	uh := make([]byte, 8)
	binary.BigEndian.PutUint16(uh[0:2], 5353)
	binary.BigEndian.PutUint16(uh[2:4], 5353)
	binary.BigEndian.PutUint16(uh[4:6], uint16(8+len(payload)))
	udpSeg := append(uh, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udpSeg)))
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], net.IPv4(224, 0, 0, 251).To4())

	return frame.Frame{Data: append(append(eth, ip...), udpSeg...)}
}

func observe(t *testing.T, frames []frame.Frame) probe.Snapshot {
	t.Helper()
	ch := make(chan frame.Frame, len(frames))
	for _, f := range frames {
		ch <- f
	}
	close(ch)
	s, err := Probe{}.Observe(context.Background(), probe.Inputs{
		Frames: ch, CaptureWindow: time.Second, Config: config.Defaults(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var browserNames = []string{
	"1e7784f6-fe08-43f0-a83c-a4aac943b893.local",
	"54e23aaa-f142-4932-876b-baba0ffb1e95.local",
	"c878fb51-b059-4b10-9b85-50839a9f4aad.local",
	"dfe5c978-3e7a-4f3b-81c3-d3fa4afe426b.local",
	"f492f680-3318-4f51-ae88-d1142e20f8ab.local",
}

// The measured false positive, end to end from frames: a desktop with a browser
// open publishing five placeholders nobody asked about.
func TestOnTheWireABrowserPublishingCandidatesIsSilent(t *testing.T) {
	snap := observe(t, []frame.Frame{
		udp(t, "5c:52:30:11:22:33", net.IPv4(192, 0, 2, 112), mdnsAnswer(browserNames, net.IPv4(192, 0, 2, 112))),
	})
	fs := Probe{}.Compare(probe.Snapshot{}, snap, probe.CompareCtx{Config: config.Defaults()})
	if hasVector(fs, vecAnswersEverything) != nil {
		t.Fatal("a browser publishing five placeholders raised the alarm from real frames")
	}
	if hasVector(fs, vecIgnoredCandidates) == nil {
		t.Error("the exclusion happened with nothing on the record")
	}
}

// The same five names, but somebody on the segment asked for every one. That is
// answering questions, which is the attack, and the query may arrive after the
// answer within the window.
func TestOnTheWireCandidatesThatWereAskedForStillFire(t *testing.T) {
	fs := []frame.Frame{
		udp(t, "de:ad:be:ef:00:01", net.IPv4(192, 0, 2, 66), mdnsAnswer(browserNames, net.IPv4(192, 0, 2, 66))),
	}
	// Queries arrive AFTER the answers: the resolution has to happen once the
	// whole window has been read, not as each frame goes by.
	for _, n := range browserNames {
		fs = append(fs, udp(t, "00:11:22:33:44:55", net.IPv4(192, 0, 2, 9), mdnsQuery(n)))
	}
	snap := observe(t, fs)
	got := Probe{}.Compare(probe.Snapshot{}, snap, probe.CompareCtx{Config: config.Defaults()})

	f := hasVector(got, vecAnswersEverything)
	if f == nil {
		t.Fatal("a host answering five names that were all asked for did not fire; the exclusion is a hiding place")
	}
	if f.Evidence["asked_for"] != "5 of 5" {
		t.Errorf("asked_for = %q", f.Evidence["asked_for"])
	}
}

// Ordinary names are unaffected by any of this.
func TestOnTheWireOrdinaryNamesStillCount(t *testing.T) {
	names := []string{"wpad.local", "fileserver.local", "printer.local", "nas.local", "backup.local"}
	snap := observe(t, []frame.Frame{
		udp(t, "de:ad:be:ef:00:01", net.IPv4(192, 0, 2, 66), mdnsAnswer(names, net.IPv4(192, 0, 2, 66))),
	})
	fs := Probe{}.Compare(probe.Snapshot{}, snap, probe.CompareCtx{Config: config.Defaults()})
	if hasVector(fs, vecAnswersEverything) == nil {
		t.Fatal("five ordinary claimed names stopped firing")
	}
}

// A host doing both: the browser half is excluded, the real half is not, and
// the alert says so.
func TestOnTheWireMixedHostFiresOnTheRealNamesOnly(t *testing.T) {
	real := []string{"wpad.local", "fileserver.local", "printer.local", "nas.local", "backup.local"}
	snap := observe(t, []frame.Frame{
		udp(t, "de:ad:be:ef:00:01", net.IPv4(192, 0, 2, 66), mdnsAnswer(browserNames, net.IPv4(192, 0, 2, 66))),
		udp(t, "de:ad:be:ef:00:01", net.IPv4(192, 0, 2, 66), mdnsAnswer(real, net.IPv4(192, 0, 2, 66))),
	})
	fs := Probe{}.Compare(probe.Snapshot{}, snap, probe.CompareCtx{Config: config.Defaults()})

	f := hasVector(fs, vecAnswersEverything)
	if f == nil {
		t.Fatal("five real claims were masked by five browser placeholders")
	}
	if f.Evidence["name_count"] != "5" {
		t.Errorf("name_count = %q, want only the five real names", f.Evidence["name_count"])
	}
}
