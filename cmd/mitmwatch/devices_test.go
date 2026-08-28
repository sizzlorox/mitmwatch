package main

import (
	"context"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

var when = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// arpSnap builds an observed arp snapshot with the given neighbour table.
func arpSnap(t *testing.T, neighbors map[string]string) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode("arp", struct {
		Neighbors map[string]string `json:"neighbors"`
	}{neighbors})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// devEnv is a sensor environment with no network access: resolveNames is given
// an already-warm cache so the test never makes a DNS query.
func devEnv(t *testing.T, neighbors map[string]string) *env {
	t.Helper()
	e := &env{
		profile:          &baseline.Profile{},
		net:              osq.NetworkIdentity{GatewayIP: "192.0.2.1"},
		observedThisPass: map[string]probe.Snapshot{"arp": arpSnap(t, neighbors)},
		erroredThisPass:  map[string]bool{},
		nameCache:        map[string]nameEntry{},
	}
	for ip := range neighbors {
		e.nameCache[ip] = nameEntry{name: "", at: time.Now()}
	}
	return e
}

// The most important guard here, and the analogue of the frozen-baseline rule:
// a neighbour table that could not be read is not an empty network.
func TestNeighbourReadFailureLeavesHistoryUntouched(t *testing.T) {
	e := devEnv(t, map[string]string{"192.0.2.10": "dc:a6:32:11:22:33"})
	e.recordDeviceHistory(context.Background(), when)
	before := e.profile.Devices["dc:a6:32:11:22:33"]

	e.erroredThisPass["arp"] = true
	e.recordDeviceHistory(context.Background(), when.Add(time.Hour))

	after, ok := e.profile.Devices["dc:a6:32:11:22:33"]
	if !ok {
		t.Fatal("a failed neighbour read deleted the device history")
	}
	if !after.LastSeen.Equal(before.LastSeen) {
		t.Error("a failed neighbour read stamped every device as seen just now; the page would report a network it never looked at")
	}
}

func TestNoArpObservationThisCycleLeavesHistoryUntouched(t *testing.T) {
	e := devEnv(t, map[string]string{"192.0.2.10": "dc:a6:32:11:22:33"})
	e.recordDeviceHistory(context.Background(), when)

	// A cycle in which the arp probe was not due at all.
	e.observedThisPass = map[string]probe.Snapshot{}
	e.recordDeviceHistory(context.Background(), when.Add(time.Hour))

	if got := e.profile.Devices["dc:a6:32:11:22:33"].LastSeen; !got.Equal(when) {
		t.Errorf("last seen moved to %s on a cycle where nothing looked at the network", got)
	}
}

// The neighbour table carries more than devices. Windows' own query returns the
// multicast pseudo-entries; a MAC-keyed history would grow permanent phantom
// rows that never leave and never were.
func TestMulticastAndPlaceholderAddressesAreNotDevices(t *testing.T) {
	e := devEnv(t, map[string]string{
		"224.0.0.251":     "01:00:5e:00:00:fb",
		"239.255.255.250": "01:00:5e:7f:ff:fa",
		"ff02::1":         "33:33:00:00:00:01",
		"192.0.2.255":     "ff:ff:ff:ff:ff:ff",
		"192.0.2.9":       "00:00:00:00:00:00",
		"192.0.2.10":      "dc:a6:32:11:22:33",
	})
	e.recordDeviceHistory(context.Background(), when)

	if len(e.profile.Devices) != 1 {
		t.Fatalf("recorded %d devices from a table of five placeholders and one host: %v",
			len(e.profile.Devices), e.profile.Devices)
	}
	if _, ok := e.profile.Devices["dc:a6:32:11:22:33"]; !ok {
		t.Error("the one real device was the one filtered out")
	}
}

func TestRandomisedAddressIsMarked(t *testing.T) {
	e := devEnv(t, map[string]string{
		"192.0.2.10": "6e:3b:a5:11:22:33", // locally administered
		"192.0.2.11": "dc:a6:32:11:22:33", // a real manufacturer prefix
	})
	e.recordDeviceHistory(context.Background(), when)

	if !e.profile.Devices["6e:3b:a5:11:22:33"].Random {
		t.Error("a locally administered address was not marked; the page would claim a device history that is really an address history")
	}
	if e.profile.Devices["dc:a6:32:11:22:33"].Random {
		t.Error("a manufacturer-assigned address was marked as randomised")
	}
}

func TestOneDeviceWithTwoAddressesIsOneRow(t *testing.T) {
	e := devEnv(t, map[string]string{
		"192.0.2.10": "dc:a6:32:11:22:33",
		"192.0.2.77": "dc:a6:32:11:22:33",
	})
	e.recordDeviceHistory(context.Background(), when)

	if len(e.profile.Devices) != 1 {
		t.Fatalf("one device on two addresses became %d rows", len(e.profile.Devices))
	}
	if got := e.profile.Devices["dc:a6:32:11:22:33"].Addrs; len(got) != 2 {
		t.Errorf("addresses %v, want both", got)
	}
}

func TestGatewayIsNamedRouterAndVendorIsTheFallback(t *testing.T) {
	e := devEnv(t, map[string]string{
		"192.0.2.1":  "dc:a6:32:11:22:33", // the gateway
		"192.0.2.10": "b8:27:eb:11:22:33", // a known vendor prefix
		"192.0.2.11": "6e:3b:a5:11:22:33", // randomised: no vendor to name
	})
	e.recordDeviceHistory(context.Background(), when)

	if got := e.profile.Devices["dc:a6:32:11:22:33"].Name; got != "router" {
		t.Errorf("gateway named %q, want router", got)
	}
	if got := e.profile.Devices["b8:27:eb:11:22:33"].Name; got == "" {
		t.Error("a device with a known manufacturer prefix and no hostname was left unnamed")
	}
	if got := e.profile.Devices["6e:3b:a5:11:22:33"].Name; got != "" {
		t.Errorf("a randomised address was given the manufacturer name %q, which it cannot have", got)
	}
}

// The reason the alert log can say which machine: an address the household does
// not recognise becomes the name they do.
func TestDeviceLabelNamesTheMachineBehindAnAddress(t *testing.T) {
	e := devEnv(t, map[string]string{"192.0.2.10": "dc:a6:32:11:22:33"})
	e.profile.RecordDevices(when, []baseline.Device{{
		MAC: "dc:a6:32:11:22:33", Addrs: []string{"192.0.2.10", "fe80::1"}, Name: "workshop-pc",
	}})

	if got := e.deviceLabel("fe80::1", ""); got != "workshop-pc (fe80::1)" {
		t.Errorf("deviceLabel(link-local) = %q; the log would still be showing a bare address", got)
	}
	if got := e.deviceLabel("192.0.2.1", ""); got != "router (192.0.2.1)" {
		t.Errorf("deviceLabel(gateway) = %q", got)
	}
	// Guessing would be worse than an address: a wrong name sends someone to
	// unplug the wrong machine.
	if got := e.deviceLabel("198.51.100.4", ""); got != "198.51.100.4" {
		t.Errorf("deviceLabel(unknown) = %q, want the address unchanged", got)
	}
	if got := e.deviceLabel("network", ""); got != "network" {
		t.Errorf("deviceLabel(network) = %q", got)
	}
}

// The case from the real log. One dual-stack device produces two alerts, one
// against its IPv4 address and one against its link-local, and the neighbour
// table this host reads is IPv4 only - so the link-local one matches no address
// in the history and would stay a bare fe80:: string. The finding saw the
// ethernet header, so the hardware is the join.
func TestALinkLocalTargetIsNamedByTheHardwareTheFindingReported(t *testing.T) {
	e := devEnv(t, map[string]string{"192.0.2.112": "5c:52:30:11:22:33"})
	e.profile.RecordDevices(when, []baseline.Device{{
		MAC: "5c:52:30:11:22:33", Addrs: []string{"192.0.2.112"}, Name: "workshop-pc",
	}})

	// No address match exists for the link-local half.
	if got := e.deviceLabel("fe80::c0a8:1ff:fe24:9b31", ""); got != "fe80::c0a8:1ff:fe24:9b31" {
		t.Fatalf("setup: expected no match by address, got %q", got)
	}
	got := e.deviceLabel("fe80::c0a8:1ff:fe24:9b31", "5c:52:30:11:22:33")
	if got != "workshop-pc (fe80::c0a8:1ff:fe24:9b31)" {
		t.Errorf("deviceLabel = %q; half of a dual-stack device's alerts would still name no machine", got)
	}

	// A hardware address that is not in the history is not invented into one.
	if got := e.deviceLabel("fe80::1", "de:ad:be:ef:00:01"); got != "fe80::1" {
		t.Errorf("deviceLabel = %q, want the address unchanged for unknown hardware", got)
	}
}

// End to end through the sensor's own event path, which is what the user reads.
func TestTheEventForALinkLocalAlertNamesTheDevice(t *testing.T) {
	e := devEnv(t, map[string]string{"192.0.2.112": "5c:52:30:11:22:33"})
	e.profile.RecordDevices(when, []baseline.Device{{
		MAC: "5c:52:30:11:22:33", Addrs: []string{"192.0.2.112"}, Name: "workshop-pc",
	}})
	e.recordEvents(resultWith(nameresAlert("fe80::c0a8:1ff:fe24:9b31")))

	got := lastOfKind(e.events, "alert")
	if got == nil || got.Device != "workshop-pc (fe80::c0a8:1ff:fe24:9b31)" {
		t.Fatalf("the log entry says %v; it must name the machine, not repeat the address", got)
	}
}

func TestUnicastMAC(t *testing.T) {
	for _, c := range []struct {
		mac  string
		want bool
	}{
		{"dc:a6:32:11:22:33", true},
		{"6e:3b:a5:11:22:33", true}, // randomised, but a real sender
		{"01:00:5e:00:00:fb", false},
		{"33:33:00:00:00:01", false},
		{"ff:ff:ff:ff:ff:ff", false},
		{"00:00:00:00:00:00", false},
		{"", false},
		{"nonsense", false},
	} {
		if got := unicastMAC(c.mac); got != c.want {
			t.Errorf("unicastMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}
