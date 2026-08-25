package osq

import (
	"context"
	"testing"
	"time"
)

func TestKeyStableAndSensitive(t *testing.T) {
	a := NetworkIdentity{Iface: "Wi-Fi", SSID: "home", GatewayIP: "192.168.1.1", GatewayMAC: "aa:bb:cc:dd:ee:ff"}
	b := a
	if a.Key() != b.Key() {
		t.Fatal("identical identities must produce identical keys")
	}
	// Case and separator normalisation must not change the key: Get-NetNeighbor
	// reports "AA-BB-CC" where /proc/net/arp reports "aa:bb:cc".
	c := a
	c.GatewayMAC = normMAC("AA-BB-CC-DD-EE-FF")
	if c.Key() != a.Key() {
		t.Fatalf("MAC normalisation changed the key: %s vs %s", c.Key(), a.Key())
	}
	// A gateway MAC change must NOT move the profile. This assertion used to say
	// the opposite, and the opposite was a vulnerability: a gateway MAC change is
	// precisely what ARP spoofing looks like, so keying on it meant the attack
	// selected a fresh profile with no baseline and a new learning window, which
	// suppresses everything below Critical. The detector went quiet exactly when
	// it mattered, and stayed quiet for as long as the attacker kept rotating.
	d := a
	d.GatewayMAC = "11:22:33:44:55:66"
	if d.Key() != a.Key() {
		t.Fatal("gateway MAC changed the profile key: an ARP spoof would hand " +
			"the attacker a fresh baseline and a fresh learning window")
	}
	// Same for the DHCP server, for the same reason.
	e := a
	e.DHCPServer = "10.9.9.9"
	if e.Key() != a.Key() {
		t.Fatal("DHCP server address changed the profile key; a rogue DHCP server " +
			"would reset the baseline it is supposed to be caught by")
	}
}

// The key must still separate genuinely different networks, or every network
// shares one baseline and nothing is comparable.
func TestKeySeparatesRealNetworks(t *testing.T) {
	base := NetworkIdentity{Iface: "wlan0", SSID: "home", GatewayIP: "192.168.1.1"}
	for name, mut := range map[string]func(*NetworkIdentity){
		"different SSID":       func(n *NetworkIdentity) { n.SSID = "cafe" },
		"different gateway IP": func(n *NetworkIdentity) { n.GatewayIP = "10.0.0.1" },
		"different interface":  func(n *NetworkIdentity) { n.Iface = "eth0" },
	} {
		other := base
		mut(&other)
		if other.Key() == base.Key() {
			t.Errorf("%s produced the same profile key", name)
		}
	}
}

func TestNormMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"00:00:00:00:00:00": "",
		"  ":                "",
	} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIdentifyLive is informational: it exercises the real OS queries on
// whatever host runs the tests and reports what could not be determined.
func TestIdentifyLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := Identify(ctx)
	if err != nil {
		t.Logf("Identify: %v", err)
	}
	t.Logf("iface=%q ssid=%q gw=%s mac=%s dhcp=%q resolvers=%v missing=%v key=%s",
		n.Iface, n.SSID, n.GatewayIP, n.GatewayMAC, n.DHCPServer, n.Resolvers, n.Missing, n.Key())
	if n.GatewayIP == "" {
		t.Log("no default gateway found - offline, or this platform's query needs work")
	}
}

func TestNormMACPadsAndRejectsPlaceholders(t *testing.T) {
	for in, want := range map[string]string{
		// macOS arp(8) drops leading zeros; the same device must not read as a
		// different MAC depending on which platform observed it.
		"0:11:32:c3:cb:d6":  "00:11:32:c3:cb:d6",
		"0:1:2:3:4:5":       "00:01:02:03:04:05",
		"00-11-32-C3-CB-D6": "00:11:32:c3:cb:d6",
		"00:11:32:c3:cb:d6": "00:11:32:c3:cb:d6",
		"00:00:00:00:00:00": "",
		"ff:ff:ff:ff:ff:ff": "",
		"":                  "",
	} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

// Informational: what the neighbour table looks like on whatever runs the tests.
func TestNeighborsLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns, err := Neighbors(ctx)
	if err != nil {
		t.Logf("Neighbors: %v", err)
		return
	}
	t.Logf("%d neighbour(s)", len(ns))
	for _, n := range ns {
		t.Logf("  %-16s %s  %s", n.IP, n.MAC, n.Iface)
	}
	for _, n := range ns {
		if len(n.MAC) != 17 {
			t.Errorf("MAC %q is not canonical 17-char form", n.MAC)
		}
	}
}
