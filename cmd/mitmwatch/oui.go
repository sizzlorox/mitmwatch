package main

import "strings"

// vendorFor returns a short manufacturer label for a MAC's OUI, or "" when it is
// unknown or the address is locally administered (a randomised/private MAC, as
// modern phones use - those carry no real vendor and must not be guessed).
//
// It backs the device list: when a host has no reverse-DNS name, its maker is
// the next best label ("Espressif", "Synology") - the same thing a router's
// device page shows.
//
// ponytail: curated common-vendor table, not the full IEEE registry. Ceiling: a
// device from an uncommon vendor with no hostname stays "unnamed" (its MAC is
// still shown). Upgrade path if that bites: embed the IEEE OUI database behind a
// `make oui` target, the same way internal/roots embeds the CA bundle.
func vendorFor(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if len(mac) < 8 {
		return ""
	}
	// Locally administered bit (second-least-significant of the first octet):
	// a randomised MAC has no manufacturer to name.
	if b := hexNibblePair(mac[0:2]); b >= 0 && b&0x02 != 0 {
		return ""
	}
	return ouiVendor[mac[0:8]]
}

func hexNibblePair(s string) int {
	v := 0
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		default:
			return -1
		}
	}
	return v
}

// ouiVendor maps an OUI prefix ("xx:xx:xx", lowercase) to a short vendor label.
// Anchored on the vendors actually seen on the author's network, then broadened
// to the common consumer and IoT makers. Espressif (ESP32/ESP8266) carries many
// prefixes and covers a huge share of nameless smart-home gear, so it is the
// best-covered.
var ouiVendor = map[string]string{
	// Synology
	"00:11:32": "Synology", "90:09:d0": "Synology",
	// Espressif (ESP32/ESP8266) - the chip inside a huge share of smart plugs,
	// sensors, bulbs and DIY boards, so it is the best coverage to have.
	"3c:8a:1f": "Espressif", "94:a9:90": "Espressif", "b4:3a:45": "Espressif",
	"d8:bc:38": "Espressif", "f0:9e:9e": "Espressif", "fc:f5:c4": "Espressif",
	"18:fe:34": "Espressif", "24:0a:c4": "Espressif", "24:6f:28": "Espressif",
	"24:b2:de": "Espressif", "2c:3a:e8": "Espressif", "30:ae:a4": "Espressif",
	"3c:71:bf": "Espressif", "40:f5:20": "Espressif", "48:3f:da": "Espressif",
	"4c:11:ae": "Espressif", "54:5a:a6": "Espressif", "5c:cf:7f": "Espressif",
	"60:01:94": "Espressif", "68:c6:3a": "Espressif", "7c:9e:bd": "Espressif",
	"7c:df:a1": "Espressif", "84:0d:8e": "Espressif", "84:cc:a8": "Espressif",
	"84:f3:eb": "Espressif", "8c:aa:b5": "Espressif", "90:38:0c": "Espressif",
	"a0:20:a6": "Espressif", "a4:cf:12": "Espressif", "ac:0b:fb": "Espressif",
	"b4:e6:2d": "Espressif", "bc:dd:c2": "Espressif", "c4:4f:33": "Espressif",
	"c8:2b:96": "Espressif", "cc:50:e3": "Espressif", "d8:a0:1d": "Espressif",
	"e0:98:06": "Espressif", "e8:db:84": "Espressif", "ec:fa:bc": "Espressif",
	// Desktop / single-board computer makers
	"88:ae:dd": "EliteGroup", "c0:f5:35": "AMPAK",
	// Robots / vacuums
	"24:9e:7d": "Roborock", "50:14:79": "iRobot",
	// Lighting
	"44:4f:8e": "WiZ", "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
	"d0:73:d5": "LIFX",
	// Raspberry Pi
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	"28:cd:c1": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
	// ASUS
	"cc:28:aa": "ASUS", "00:1b:fc": "ASUS", "04:d4:c4": "ASUS", "08:60:6e": "ASUS",
	"1c:87:2c": "ASUS", "2c:56:dc": "ASUS", "38:d5:47": "ASUS", "ac:22:0b": "ASUS",
	// Apple (common prefixes; most Apple kit uses private MACs and gets a name instead)
	"3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple", "00:1b:63": "Apple",
	"88:66:5a": "Apple", "8c:85:90": "Apple", "ac:bc:32": "Apple", "dc:a9:04": "Apple",
	"f4:0f:24": "Apple", "60:f8:1d": "Apple", "90:b0:ed": "Apple", "6c:40:08": "Apple",
	// Samsung
	"3c:5a:b4": "Samsung", "5c:0a:5b": "Samsung", "8c:77:12": "Samsung", "bc:14:85": "Samsung",
	"e8:50:8b": "Samsung", "00:12:fb": "Samsung", "34:23:87": "Samsung", "d0:59:e4": "Samsung",
	// Google / Nest
	"30:fd:38": "Google", "48:d6:d5": "Google", "f4:f5:d8": "Google", "f4:f5:e8": "Google",
	"54:60:09": "Google", "64:16:66": "Nest", "18:b4:30": "Nest",
	// Amazon
	"44:65:0d": "Amazon", "68:37:e9": "Amazon", "34:d2:70": "Amazon", "fc:65:de": "Amazon",
	"f0:27:2d": "Amazon", "0c:47:c9": "Amazon",
	// Intel
	"00:1e:64": "Intel", "3c:a9:f4": "Intel", "34:e6:d7": "Intel", "7c:b0:c2": "Intel",
	"a0:a8:cd": "Intel", "e4:70:b8": "Intel",
	// TP-Link
	"50:c7:bf": "TP-Link", "60:32:b1": "TP-Link", "a4:2b:b0": "TP-Link", "f4:f2:6d": "TP-Link",
	// Ubiquiti
	"24:5a:4c": "Ubiquiti", "44:d9:e7": "Ubiquiti", "68:d7:9a": "Ubiquiti", "fc:ec:da": "Ubiquiti",
	"78:8a:20": "Ubiquiti",
	// Sonos
	"00:0e:58": "Sonos", "5c:aa:fd": "Sonos", "94:9f:3e": "Sonos", "b8:e9:37": "Sonos",
	// Xiaomi
	"28:6c:07": "Xiaomi", "34:ce:00": "Xiaomi", "50:ec:50": "Xiaomi", "64:09:80": "Xiaomi",
	"78:11:dc": "Xiaomi", "f8:a4:5f": "Xiaomi",
	// Netgear
	"a0:40:a0": "Netgear", "9c:3d:cf": "Netgear", "3c:37:86": "Netgear",
}
