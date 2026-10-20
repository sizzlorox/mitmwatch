package main

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/osq"
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
	e := &env{net: osq.NetworkIdentity{GatewayIP: "10.0.0.1", GatewayMAC: "aa:aa:aa:aa:aa:01"}}
	d := baseline.Device{MAC: "bb:bb:bb:bb:bb:02", Addrs: []string{"10.0.0.1"}, DHCPServer: true}
	a := assess(e, d)
	if a.Class != verdictSuspicious || len(a.Notes) < 2 {
		t.Fatalf("got %s %v", a.Class, a.Notes)
	}
	router := baseline.Device{MAC: "aa:aa:aa:aa:aa:01", Addrs: []string{"10.0.0.1"}, DHCPServer: true, Established: true}
	if a := assess(e, router); a.Class == verdictSuspicious {
		t.Errorf("the real router flagged: %v", a.Notes)
	}
}
