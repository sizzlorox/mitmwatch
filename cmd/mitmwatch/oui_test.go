package main

import "testing"

func TestVendorFor(t *testing.T) {
	cases := []struct{ mac, want string }{
		{"d8:bc:38:00:00:01", "Espressif"},    // a nameless ESP32 device
		{"00:11:32:00:00:01", "Synology"},     // a router/NAS maker
		{"88:ae:dd:00:00:01", "EliteGroup"},   // an EliteGroup board
		{"b8:27:eb:11:22:33", "Raspberry Pi"}, // the Pi
		{"2a:aa:28:00:00:01", ""},             // locally administered (randomised) - no vendor
		{"6e:3b:a5:00:00:01", ""},             // randomised
		{"ff:ff:ff:00:00:01", ""},             // unknown OUI (also broadcast-ish)
		{"", ""},                              // empty
		{"a4", ""},                            // too short
	}
	for _, c := range cases {
		if got := vendorFor(c.mac); got != c.want {
			t.Errorf("vendorFor(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}
