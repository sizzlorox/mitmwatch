package nameresprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// llmnrReply builds a real Ethernet/IPv4/UDP/LLMNR response.
func llmnrReply(srcMAC, srcIP, hostname, answerIP string) frame.Frame {
	n, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		panic(err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: netip.MustParseAddr(answerIP).As4()},
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return udpFrame(srcMAC, srcIP, frame.LLMNRPort, payload)
}

// llmnrReplyFrom is llmnrReply with an explicit (possibly IPv6) source address.
func llmnrReplyFrom(srcMAC, srcIP, hostname, answerIP string) frame.Frame {
	n, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		panic(err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: netip.MustParseAddr(answerIP).As4()},
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return udpFrameSrc(srcMAC, srcIP, frame.LLMNRPort, payload)
}

func udpFrame(srcMAC, srcIP string, srcPort uint16, payload []byte) frame.Frame {
	return udpFrameSrc(srcMAC, srcIP, srcPort, payload)
}

// udpFrameSrc builds an Ethernet/IP/UDP frame, IPv4 or IPv6 by the source addr.
func udpFrameSrc(srcMAC, srcIP string, srcPort uint16, payload []byte) frame.Frame {
	var udp bytes.Buffer
	binary.Write(&udp, binary.BigEndian, srcPort)                //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, srcPort)                //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, uint16(8+len(payload))) //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, uint16(0))              //nolint:errcheck
	udp.Write(payload)
	ub := udp.Bytes()

	src := netip.MustParseAddr(srcIP)
	var ib []byte
	var ethType uint16
	var dstMAC []byte
	if src.Is6() {
		var ip bytes.Buffer
		ip.WriteByte(0x60)
		ip.Write(make([]byte, 3))
		binary.Write(&ip, binary.BigEndian, uint16(len(ub))) //nolint:errcheck
		ip.WriteByte(frame.ProtoUDP)
		ip.WriteByte(255)
		s := src.As16()
		ip.Write(s[:])
		d := netip.MustParseAddr("ff02::1:3").As16()
		ip.Write(d[:])
		ip.Write(ub)
		ib = ip.Bytes()
		ethType = frame.EtherTypeIPv6
		dstMAC = []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x03}
	} else {
		var ip bytes.Buffer
		ip.WriteByte(0x45)
		ip.WriteByte(0)
		binary.Write(&ip, binary.BigEndian, uint16(20+len(ub))) //nolint:errcheck
		ip.Write(make([]byte, 4))
		ip.WriteByte(64)
		ip.WriteByte(frame.ProtoUDP)
		ip.Write(make([]byte, 2))
		s := src.As4()
		ip.Write(s[:])
		d := netip.MustParseAddr("224.0.0.252").As4()
		ip.Write(d[:])
		ip.Write(ub)
		ib = ip.Bytes()
		ethType = frame.EtherTypeIPv4
		dstMAC = []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc}
	}

	var eth bytes.Buffer
	eth.Write(dstMAC)
	for _, part := range strings.Split(srcMAC, ":") {
		v, _ := strconv.ParseUint(part, 16, 8)
		eth.WriteByte(byte(v))
	}
	binary.Write(&eth, binary.BigEndian, ethType) //nolint:errcheck
	eth.Write(ib)
	return frame.Frame{Time: time.Now(), Iface: "test", Data: eth.Bytes()}
}

const (
	printer  = "00:11:22:33:44:55"
	attacker = "dc:a6:32:11:22:33"
)

func run(t *testing.T, frames ...frame.Frame) probe.Snapshot {
	t.Helper()
	ch := make(chan frame.Frame, len(frames)+1)
	for _, f := range frames {
		ch <- f
	}
	close(ch)
	s, err := (Probe{}).Observe(context.Background(), probe.Inputs{
		Frames: ch, CaptureWindow: 2 * time.Second, Config: config.Defaults(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cc() probe.CompareCtx {
	return probe.CompareCtx{Config: config.Defaults(), Trust: "home"}
}

func vectors(fs []probe.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Vector] = f.Score
	}
	return out
}

// A device describing itself is what these protocols are for.
func TestHostAnsweringForItselfIsSilent(t *testing.T) {
	cur := run(t,
		llmnrReply(printer, "10.0.4.20", "officeprinter", "10.0.4.20"),
		llmnrReply(printer, "10.0.4.20", "officeprinter", "10.0.4.20"),
	)
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc()); len(fs) != 0 {
		t.Fatalf("a host describing itself produced %v", vectors(fs))
	}
}

// The Responder signature: one host answering for whatever was asked.
func TestAnsweringForManyNamesIsHigh(t *testing.T) {
	var frames []frame.Frame
	for _, n := range []string{"fileserver", "wpad", "backup", "printer01", "nas", "intranet", "hr-share"} {
		frames = append(frames, llmnrReply(attacker, "10.0.4.66", n, "10.0.4.66"))
	}
	cur := run(t, frames...)

	fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc())
	got := vectors(fs)
	if got[vecAnswersEverything] < 60 {
		t.Fatalf("%s scored %d, want >= 60: %v", vecAnswersEverything, got[vecAnswersEverything], got)
	}
	for _, f := range fs {
		if f.Vector != vecAnswersEverything {
			continue
		}
		if f.Evidence["name_count"] != "7" {
			t.Errorf("name_count = %q, want 7", f.Evidence["name_count"])
		}
		if !strings.Contains(f.Evidence["names"], "wpad") {
			t.Errorf("evidence lost the names: %q", f.Evidence["names"])
		}
		if f.Evidence["what_to_do"] == "" || f.Evidence["benign_case"] == "" {
			t.Error("no action or benign explanation offered")
		}
	}
}

// Just under the threshold must stay quiet, or every chatty media server alerts.
func TestFewNamesStaysQuiet(t *testing.T) {
	var frames []frame.Frame
	for _, n := range []string{"nas", "nas-media", "nas-print"} {
		frames = append(frames, llmnrReply(printer, "10.0.4.20", n, "10.0.4.20"))
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, run(t, frames...), cc()); len(fs) != 0 {
		t.Fatalf("a device with a few names produced %v", vectors(fs))
	}
}

func TestThresholdIsConfigurable(t *testing.T) {
	var frames []frame.Frame
	for _, n := range []string{"a", "b", "c"} {
		frames = append(frames, llmnrReply(attacker, "10.0.4.66", n, "10.0.4.66"))
	}
	c := cc()
	c.Config.Nameres.AnswerThreshold = 2
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, run(t, frames...), c)); got[vecAnswersEverything] == 0 {
		t.Fatalf("a lowered threshold had no effect: %v", got)
	}
}

// Two hosts claiming one name is worth reporting on its own.
func TestContestedNameIsReported(t *testing.T) {
	cur := run(t,
		llmnrReply(printer, "10.0.4.20", "fileserver", "10.0.4.20"),
		llmnrReply(attacker, "10.0.4.66", "fileserver", "10.0.4.66"),
	)
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, cc())); got[vecContestedName] == 0 {
		t.Fatalf("want %s, got %v", vecContestedName, got)
	}
}

// Queries say nothing about ownership. Counting them would make every machine
// on the network look like a responder.
func TestQueriesAreNotAnswers(t *testing.T) {
	n, _ := dnsmessage.NewName("fileserver.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	payload, _ := msg.Pack()
	cur := run(t, udpFrame(attacker, "10.0.4.66", frame.LLMNRPort, payload))

	var s snapshot
	if _, err := cur.Decode(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Answerers) != 0 {
		t.Fatalf("a query was recorded as an answer: %v", s.Answerers)
	}
}

// Tier 3 has no frames. That must read as "did not listen", not "heard nothing".
func TestNoCaptureIsSilent(t *testing.T) {
	s, err := (Probe{}).Observe(context.Background(), probe.Inputs{Config: config.Defaults()})
	if err != nil {
		t.Fatal(err)
	}
	var snap snapshot
	if _, err := s.Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap.Captured {
		t.Error("claimed to have captured with no frame source")
	}
	if fs := (Probe{}).Compare(probe.Snapshot{}, s, cc()); len(fs) != 0 {
		t.Fatalf("tier 3 produced findings: %v", vectors(fs))
	}
}

func TestMalformedPayloadsDoNotStopTheWindow(t *testing.T) {
	frames := []frame.Frame{
		{Data: []byte{0x01}},
		udpFrame(attacker, "10.0.4.66", frame.LLMNRPort, []byte{0xff, 0xff, 0xff}),
	}
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		frames = append(frames, llmnrReply(attacker, "10.0.4.66", n, "10.0.4.66"))
	}
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, run(t, frames...), cc())); got[vecAnswersEverything] == 0 {
		t.Fatalf("valid answers were lost among malformed ones: %v", got)
	}
}

// A single dual-stack host answering for its own name over IPv4 and IPv6 is one
// device, not a contest. Keying contested names on the L3 source address made
// it look like two claimants; keying on the hardware address fixes it.
func TestDualStackHostIsNotContested(t *testing.T) {
	// Same MAC, one name, answered from two different source addresses.
	v4 := llmnrReply(printer, "10.0.4.20", "myhost", "10.0.4.20")
	v6 := llmnrReplyFrom(printer, "fe80::1122", "myhost", "10.0.4.20")
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, run(t, v4, v6), cc())); got[vecContestedName] != 0 {
		t.Fatalf("a dual-stack host answering for itself was reported as contested: %v", got)
	}
}

// Two genuinely different devices claiming one name still fires.
func TestTwoDevicesOneNameStillContested(t *testing.T) {
	real := llmnrReply(printer, "10.0.4.20", "fileserver", "10.0.4.20")
	fake := llmnrReply(attacker, "10.0.4.66", "fileserver", "10.0.4.66")
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, run(t, real, fake), cc())); got[vecContestedName] == 0 {
		t.Fatalf("two devices claiming one name were not reported: %v", got)
	}
}
