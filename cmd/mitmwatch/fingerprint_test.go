package main

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func assess(e *env, d baseline.Device, all ...baseline.Device) deviceAssessment {
	return e.assessDevice(d, append([]baseline.Device{d}, all...))
}

func TestAssessKnownDeviceIsNotAccused(t *testing.T) {
	e := &env{}
	d := baseline.Device{MAC: "3c:22:fb:00:00:01", Addrs: []string{"10.0.0.5"}, Established: true,
		Hostname: "Johns-iPhone", ParamList: paramsApple}
	a := assess(e, d)
	if a.Class != verdictKnown {
		t.Errorf("legitimate Apple device: %s %v", a.Class, a.Notes)
	}
}

func TestAssessRotatedPhoneIsUnverifiedNotSuspicious(t *testing.T) {
	e := &env{}
	d := baseline.Device{MAC: "02:00:00:00:00:01", Random: true, Addrs: []string{"10.0.0.6"}}
	if a := assess(e, d); a.Class != verdictUnverified {
		t.Errorf("anonymous randomised device: %s", a.Class)
	}
}

func TestAssessVendorFamilyMismatchIsSuspicious(t *testing.T) {
	e := &env{}
	d := baseline.Device{MAC: "3c:22:fb:00:00:01", Addrs: []string{"10.0.0.5"}, Established: true,
		VendorClass: "MSFT 5.0"}
	a := assess(e, d)
	if a.Class != verdictSuspicious || !strings.Contains(a.Notes[0], "WARNING") {
		t.Errorf("Apple hardware speaking Windows DHCP: %s %v", a.Class, a.Notes)
	}
}

func TestAssessUnexpectedDHCPServerAndRouterClaim(t *testing.T) {
	arp, err := probe.Encode("arp", map[string]string{
		"gateway_ip": "10.0.0.1", "gateway_mac": "aa:aa:aa:aa:aa:01",
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		net:     osq.NetworkIdentity{GatewayIP: "10.0.0.1", GatewayMAC: "bb:bb:bb:bb:bb:02"},
		profile: &baseline.Profile{Snapshots: map[string]probe.Snapshot{"arp": arp}},
	}
	d := baseline.Device{MAC: "bb:bb:bb:bb:bb:02", Addrs: []string{"10.0.0.1"}, DHCPServer: true}
	a := assess(e, d)
	if a.Class != verdictSuspicious || len(a.Notes) < 2 {
		t.Fatalf("got %s %v", a.Class, a.Notes)
	}
	router := baseline.Device{MAC: "aa:aa:aa:aa:aa:01", Addrs: []string{"10.0.0.1"}, DHCPServer: true, Established: true}
	if a := assess(e, router); a.Class == verdictSuspicious || !strings.Contains(strings.Join(a.Behaviour, " "), "expected, as it is the router") {
		t.Errorf("the protected-baseline router was not treated as expected: %#v", a)
	}
}

func TestDHCPServerWithoutProtectedRouterIdentityIsUnverified(t *testing.T) {
	e := &env{net: osq.NetworkIdentity{GatewayIP: "10.0.0.1", GatewayMAC: "aa:aa:aa:aa:aa:01"}}
	a := assess(e, baseline.Device{MAC: "bb:bb:bb:bb:bb:02", DHCPServer: true})
	if a.Class == verdictSuspicious || !strings.Contains(strings.Join(a.Behaviour, " "), "could not verify") {
		t.Fatalf("DHCP server without a protected router identity was treated as rogue: %#v", a)
	}
}

func TestHistoricalAddressReuseIsNotACurrentConflict(t *testing.T) {
	e := &env{}
	d := baseline.Device{MAC: "aa:aa:aa:aa:aa:01", Addrs: []string{"192.0.2.7"}}
	other := baseline.Device{MAC: "bb:bb:bb:bb:bb:02", Addrs: []string{"192.0.2.7"}}
	a := e.assessDevice(d, []baseline.Device{d, other})
	if a.Class == verdictSuspicious || strings.Contains(strings.Join(a.Notes, " "), "WARNING") {
		t.Fatalf("historical reuse alone was suspicious: %#v", a)
	}
	if !strings.Contains(strings.Join(a.Notes, " "), "Current ARP claims could not be checked") {
		t.Fatalf("unavailable current claims were not made explicit: %#v", a)
	}
}

func TestCurrentARPClaimsReportAnAddressConflict(t *testing.T) {
	snap, err := probe.Encode("arp", map[string]any{
		"captured": true,
		"claims": map[string]map[string]int{
			"192.0.2.7": {"aa:aa:aa:aa:aa:01": 1, "bb:bb:bb:bb:bb:02": 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{observedThisPass: map[string]probe.Snapshot{"arp": snap}}
	d := baseline.Device{MAC: "aa:aa:aa:aa:aa:01", Addrs: []string{"192.0.2.7"}}
	a := e.assessDevice(d, []baseline.Device{d})
	if a.Class != verdictSuspicious || !strings.Contains(strings.Join(a.Notes, " "), "ARP capture saw this address claimed") {
		t.Fatalf("current duplicate claims were not suspicious: %#v", a)
	}
}

func TestWindowsIsPlausibleForSamsungAndXiaomi(t *testing.T) {
	for _, device := range []struct {
		vendor string
		mac    string
	}{
		{"Samsung", "3c:5a:b4:00:00:01"},
		{"Xiaomi", "28:6c:07:00:00:01"},
	} {
		a := assess(&env{}, baseline.Device{
			MAC: device.mac, VendorClass: "MSFT 5.0", Established: true,
		})
		if a.Class == verdictSuspicious {
			t.Errorf("%s Windows laptop was reported as suspicious: %#v", device.vendor, a)
		}
	}
}
