package pathprobe

import (
	"encoding/binary"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func snapOf(t *testing.T, degraded bool, paths ...Path) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	s.Degraded = degraded
	return s
}

func mk(target string, addrs ...string) Path {
	p := Path{Target: target, Reached: true}
	for i, a := range addrs {
		p.Hops = append(p.Hops, Hop{TTL: i + 1, Addr: a})
	}
	return p
}

func cc() probe.CompareCtx { return probe.CompareCtx{Config: config.Defaults()} }

func vectors(fs []probe.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Vector] = true
	}
	return m
}

func TestIdenticalPathIsQuiet(t *testing.T) {
	p := mk("1.1.1.1", "192.168.1.1", "100.64.0.1", "203.0.113.5", "1.1.1.1")
	if fs := (Probe{}).Compare(snapOf(t, false, p), snapOf(t, false, p), cc()); len(fs) != 0 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
}

// Load balancing beyond the household changes public hops from probe to probe.
func TestECMPBeyondTheHouseIsQuiet(t *testing.T) {
	a := mk("1.1.1.1", "192.168.1.1", "203.0.113.5", "198.51.100.7", "1.1.1.1")
	b := mk("1.1.1.1", "192.168.1.1", "203.0.113.9", "198.51.100.8", "1.1.1.1")
	if fs := (Probe{}).Compare(snapOf(t, false, a), snapOf(t, false, b), cc()); len(fs) != 0 {
		t.Fatalf("ECMP variation flagged: %+v", fs)
	}
}

func TestFirstHopChanged(t *testing.T) {
	a := mk("1.1.1.1", "192.168.1.1", "203.0.113.5", "1.1.1.1")
	b := mk("1.1.1.1", "192.168.1.66", "203.0.113.5", "1.1.1.1")
	fs := (Probe{}).Compare(snapOf(t, false, a), snapOf(t, false, b), cc())
	if !vectors(fs)[vecFirstHop] || !fs[0].Change {
		t.Fatalf("want a change finding %s, got %+v", vecFirstHop, fs)
	}
}

func TestInsertedLocalHop(t *testing.T) {
	a := mk("1.1.1.1", "192.168.1.1", "203.0.113.5", "1.1.1.1")
	b := mk("1.1.1.1", "192.168.1.1", "192.168.1.66", "203.0.113.5", "1.1.1.1")
	fs := (Probe{}).Compare(snapOf(t, false, a), snapOf(t, false, b), cc())
	if !vectors(fs)[vecHopInserted] {
		t.Fatalf("want %s, got %+v", vecHopInserted, fs)
	}
}

// A router that did not answer at one TTL is unknown, not an attacker.
func TestSilentHopIsNotAChange(t *testing.T) {
	a := mk("1.1.1.1", "192.168.1.1", "10.0.0.1", "203.0.113.5", "1.1.1.1")
	b := mk("1.1.1.1", "192.168.1.1", "", "203.0.113.5", "1.1.1.1")
	if fs := (Probe{}).Compare(snapOf(t, false, a), snapOf(t, false, b), cc()); len(fs) != 0 {
		t.Fatalf("silent hop flagged: %+v", fs)
	}
}

func TestNoBaselineIsQuiet(t *testing.T) {
	p := mk("1.1.1.1", "192.168.1.1", "1.1.1.1")
	if fs := (Probe{}).Compare(probe.Snapshot{}, snapOf(t, false, p), cc()); len(fs) != 0 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
}

// Failing to trace must say so rather than read as a clean path.
func TestDegradedReportsUnavailable(t *testing.T) {
	cur, _ := probe.Incomplete(name, snapshot{}, errTest("no raw socket"))
	fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc())
	if !vectors(fs)[vecUnavailable] {
		t.Fatalf("want %s, got %+v", vecUnavailable, fs)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

// quoted builds the payload of a time-exceeded: the original IPv4 header plus
// the first 8 bytes of our echo request.
func quoted(id, seq uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	b[20] = 8
	binary.BigEndian.PutUint16(b[24:], id)
	binary.BigEndian.PutUint16(b[26:], seq)
	return b
}

func TestMatchQuoted(t *testing.T) {
	if _, ok := matchQuoted(quoted(7, 9), 7, 9, false); !ok {
		t.Fatal("own probe not matched")
	}
	if _, ok := matchQuoted(quoted(7, 10), 7, 9, false); ok {
		t.Fatal("foreign sequence matched")
	}
	for _, short := range [][]byte{nil, make([]byte, 19), quoted(7, 9)[:27]} {
		if _, ok := matchQuoted(short, 7, 9, false); ok {
			t.Fatalf("truncated input matched: %d bytes", len(short))
		}
	}
}

func TestUndecodableSnapshotIsReportedNotClean(t *testing.T) {
	cur := probe.Snapshot{Probe: name, Data: []byte("{not json")}
	if fs := (Probe{}).Compare(probe.Snapshot{}, cur, cc()); !vectors(fs)[vecUnavailable] {
		t.Fatalf("want %s, got %+v", vecUnavailable, fs)
	}
}

func TestClass(t *testing.T) {
	for _, c := range []struct {
		addr string
		ttl  int
		want string
	}{{"", 3, "unknown"}, {"192.168.1.1", 1, "gateway"}, {"10.1.1.1", 2, "local"}, {"203.0.113.5", 3, "internet"}} {
		if got := Class(c.addr, c.ttl); got != c.want {
			t.Errorf("Class(%q,%d)=%q want %q", c.addr, c.ttl, got, c.want)
		}
	}
}
