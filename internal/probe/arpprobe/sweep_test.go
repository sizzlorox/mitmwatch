package arpprobe

import (
	"net/netip"
	"testing"
)

func has(hs []netip.Addr, s string) bool {
	a := netip.MustParseAddr(s)
	for _, h := range hs {
		if h == a {
			return true
		}
	}
	return false
}

// A /24 yields 253 hosts: 256 addresses minus network, broadcast, and self.
func TestHostsInPrefixSlash24(t *testing.T) {
	hs, ok := hostsInPrefix(netip.MustParsePrefix("10.0.4.48/24"))
	if !ok {
		t.Fatal("a /24 was refused")
	}
	if len(hs) != 253 {
		t.Fatalf("got %d hosts, want 253", len(hs))
	}
	if !has(hs, "10.0.4.1") { // gateway - a real host, must be swept
		t.Error("10.0.4.1 missing")
	}
	for _, bad := range []string{"10.0.4.0", "10.0.4.255", "10.0.4.48"} { // network, broadcast, self
		if has(hs, bad) {
			t.Errorf("%s should be excluded", bad)
		}
	}
}

// The /22 gate: a big network must be refused, never swept.
func TestHostsInPrefixRefusesLargeAndV6(t *testing.T) {
	if _, ok := hostsInPrefix(netip.MustParsePrefix("10.0.0.5/16")); ok {
		t.Error("a /16 was accepted; discovery must refuse to flood it")
	}
	if _, ok := hostsInPrefix(netip.MustParsePrefix("10.0.0.5/8")); ok {
		t.Error("a /8 was accepted")
	}
	if _, ok := hostsInPrefix(netip.MustParsePrefix("2001:db8::1/64")); ok {
		t.Error("an IPv6 prefix was accepted; this sweep is IPv4-only")
	}
}

// A /22 (the boundary) is allowed and excludes its own edges.
func TestHostsInPrefixSlash22(t *testing.T) {
	hs, ok := hostsInPrefix(netip.MustParsePrefix("10.0.4.5/22"))
	if !ok {
		t.Fatal("a /22 was refused at the boundary")
	}
	if len(hs) != 1021 { // 1024 - network - broadcast - self
		t.Fatalf("got %d hosts, want 1021", len(hs))
	}
}
