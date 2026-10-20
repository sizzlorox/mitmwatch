package main

import (
	"strings"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
)

// Operating-system families, as far as DHCP behaviour can tell.
const (
	famWindows  = "Windows"
	famApple    = "Apple (macOS/iOS)"
	famAndroid  = "Android"
	famLinux    = "Linux"
	famEmbedded = "embedded device"
)

// Parameter-request-list prefixes. The order a client asks for options in is
// set by its network stack, which is why it identifies the stack better than
// any value the client chooses to say.
const (
	paramsApple   = "1,121,3,6,15,119,252"
	paramsWindows = "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
)

// dhcpFamily guesses the operating-system family from what a client said in
// DHCP, or "" when nothing is recognised. A guess for a person to weigh: every
// input is sent by the device, so it can be forged.
func dhcpFamily(d baseline.Device) string {
	vc := strings.ToLower(d.VendorClass)
	host := strings.ToLower(d.Hostname)
	switch {
	case strings.HasPrefix(vc, "msft"):
		return famWindows
	case strings.HasPrefix(vc, "android-dhcp"):
		return famAndroid
	case strings.HasPrefix(vc, "udhcp"):
		return famEmbedded
	case strings.HasPrefix(vc, "dhcpcd"):
		return famLinux
	}
	switch {
	case strings.HasPrefix(d.ParamList, paramsWindows):
		return famWindows
	case strings.HasPrefix(d.ParamList, paramsApple):
		return famApple
	}
	for _, k := range []string{"iphone", "ipad", "macbook", "imac"} {
		if strings.Contains(host, k) {
			return famApple
		}
	}
	if strings.Contains(host, "android") {
		return famAndroid
	}
	return ""
}

// vendorFamilies is which families a manufacturer plausibly ships, deliberately
// short: only vendors whose products run a narrow set of systems are listed, so
// a disagreement means something and an unlisted vendor never disagrees.
var vendorFamilies = map[string][]string{
	"Apple":        {famApple},
	"Samsung":      {famWindows, famAndroid, famEmbedded, famLinux},
	"Xiaomi":       {famWindows, famAndroid, famEmbedded, famLinux},
	"Raspberry Pi": {famLinux, famEmbedded},
	"Espressif":    {famEmbedded},
	"Amazon":       {famAndroid, famEmbedded, famLinux},
	"Google":       {famAndroid, famEmbedded, famLinux},
	"Sonos":        {famEmbedded, famLinux},
	"Philips Hue":  {famEmbedded},
	"Ubiquiti":     {famEmbedded, famLinux},
	"Synology":     {famEmbedded, famLinux},
	"TP-Link":      {famEmbedded, famLinux},
	"Netgear":      {famEmbedded, famLinux},
}

// vendorContradicts reports whether the family the device's own DHCP behaviour
// points to is one its hardware vendor does not ship.
func vendorContradicts(vendor, family string) bool {
	if vendor == "" || family == "" {
		return false
	}
	allowed, ok := vendorFamilies[vendor]
	if !ok {
		return false
	}
	for _, f := range allowed {
		if f == family {
			return false
		}
	}
	return true
}

// Verdict classes for the device page.
const (
	verdictKnown      = "known"
	verdictUnverified = "unverified"
	verdictSuspicious = "suspicious"
)
