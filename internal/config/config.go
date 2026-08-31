// Package config loads mitmwatch's TOML configuration and the scoring weights.
//
// Weights live in config from the first commit on purpose: the SDD concedes
// they are initial guesses, and recalibrating after the lab and soak phases
// must not require a code change.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Sensor   Sensor         `toml:"sensor"`
	Witness  Witness        `toml:"witness"`
	TLS      TLS            `toml:"tls"`
	DNS      DNS            `toml:"dns"`
	SSLStrip SSLStrip       `toml:"sslstrip"`
	Clock    Clock          `toml:"clock"`
	Nameres  Nameres        `toml:"nameres"`
	CT       CT             `toml:"ct"`
	Inbound  Inbound        `toml:"inbound"`
	Alerts   Alerts         `toml:"alerts"`
	Learning Learning       `toml:"learning"`
	Weights  map[string]int `toml:"weights"`

	path string
}

type Sensor struct {
	Role       string   `toml:"role"`    // always-on | roaming
	Capture    string   `toml:"capture"` // auto | pcap | raw | poll
	Interfaces []string `toml:"interfaces"`
	ServeDNS   bool     `toml:"serve_dns"`
	// Discover turns on active device discovery: each pass nudges every host on
	// the local subnet so quiet devices (smart plugs, sensors, an idle rogue
	// box) resolve into the neighbour table, making the device list a full
	// inventory rather than only who has spoken recently. Off by default -
	// detection stays passive; this is the one thing that actively emits.
	Discover bool `toml:"discover"`
	// Dashboard is the LAN address the status page listens on, empty to
	// disable. ":8080" listens on every interface; "127.0.0.1:8080" is
	// localhost only, which is right for a laptop.
	Dashboard string `toml:"dashboard"`
	// CaptureWindowSec is how long one pass listens on the wire. Short is
	// enough for ARP poisoning, which repeats about once a second in every
	// common tool; longer would be needed for anything that happens once.
	CaptureWindowSec int `toml:"capture_window_sec"`
}

type Witness struct {
	// --- sensor side ---
	Sync    bool   `toml:"sync"`     // enable the witness link
	Addr    string `toml:"addr"`     // witness host:port to dial
	Pin     string `toml:"pin"`      // witness SPKI pin, from `witness pair`
	BeatSec int    `toml:"beat_sec"` // heartbeat interval
	KeyDir  string `toml:"key_dir"`  // where this box's identity lives

	// --- witness side (same binary, its own box) ---
	Listen           string   `toml:"listen"`            // e.g. ":8443"
	AllowPins        []string `toml:"allow_pins"`        // accepted sensor SPKIs
	TickInterval     string   `toml:"tick_interval"`     // how often the witness observes and pushes
	ConfirmTicks     int      `toml:"confirm_ticks"`     // ticks a host must be stable before it is scored
	Freshness        string   `toml:"freshness"`         // how long a tick stays usable on the sensor
	UnreachableGrace string   `toml:"unreachable_grace"` // link down this long before reporting it
	ReconnectGrace   string   `toml:"reconnect_grace"`   // a silent sensor tolerated this long (reboot)
	HistoryPath      string   `toml:"history_path"`      // witness-side history file
}

// durationOr parses a duration string, falling back to d on empty or invalid.
func durationOr(s string, d time.Duration) time.Duration {
	if s == "" {
		return d
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return d
	}
	return v
}

// The witness knobs, each with a safe default. Chosen so that an honest network
// never false-alarms: confirm_ticks and freshness are deliberately generous.
func (w Witness) BeatInterval() time.Duration {
	if w.BeatSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(w.BeatSec) * time.Second
}
func (w Witness) Tick() time.Duration  { return durationOr(w.TickInterval, 5*time.Minute) }
func (w Witness) Fresh() time.Duration { return durationOr(w.Freshness, 10*time.Minute) }
func (w Witness) UnreachableAfter() time.Duration {
	return durationOr(w.UnreachableGrace, 10*time.Minute)
}
func (w Witness) ReconnectAfter() time.Duration { return durationOr(w.ReconnectGrace, 8*time.Minute) }
func (w Witness) Confirm() int {
	if w.ConfirmTicks <= 0 {
		return 3
	}
	return w.ConfirmTicks
}

type TLS struct {
	Pin []string `toml:"pin"`
	// LearnIssuers must not seed from a local first observation — a host that
	// is already intercepted would enrol its attacker as legitimate. Until a
	// witness exists (phase 2) the expected issuers come from ExpectIssuers.
	LearnIssuers bool `toml:"learn_issuers"`
	// ExpectIssuers maps host -> issuer organisation expected for it. A host
	// absent from the map is not issuer-checked.
	ExpectIssuers map[string]string `toml:"expect_issuers"`
	TimeoutSec    int               `toml:"timeout_sec"`
}

type Nameres struct {
	// AnswerThreshold is how many distinct names one host may claim in a
	// window before it stops looking like a device and starts looking like a
	// tool. Zero uses the built-in default.
	AnswerThreshold int `toml:"answer_threshold"`

	// IgnoreBrowserCandidates excludes RFC 8828 WebRTC placeholder names from
	// the answer count. Default on; set false to count them. A pointer so an
	// unset field is the default rather than false.
	IgnoreBrowserCandidates *bool `toml:"ignore_browser_candidates"`
}

type DNS struct {
	Anchors    []string `toml:"anchors"`
	DoH        []string `toml:"doh"`
	TimeoutSec int      `toml:"timeout_sec"`
}

type SSLStrip struct {
	// Hosts must be HSTS-preloaded: plain http to them should never return a
	// body, only a redirect.
	Hosts      []string `toml:"hosts"`
	TimeoutSec int      `toml:"timeout_sec"`
}

type Clock struct {
	NTP        []string `toml:"ntp"`
	TimeoutSec int      `toml:"timeout_sec"`
}

type CT struct {
	OwnedDomains []string `toml:"owned_domains"`
}

type Inbound struct {
	Endpoints []string `toml:"endpoints"`
}

type Alerts struct {
	Sinks     []string `toml:"sinks"`
	NtfyTopic string   `toml:"ntfy_topic"`
	Webhook   string   `toml:"webhook"`
	// CooldownHours is how long the same finding stays quiet after being
	// pushed. The log sink ignores it - a record with gaps is not a record.
	CooldownHours int `toml:"cooldown_hours"`
}

type Learning struct {
	WindowMin int `toml:"window_min"`
}

// Defaults returns a usable configuration for a host that has no config file.
func Defaults() *Config {
	return &Config{
		Sensor: Sensor{Role: "roaming", Capture: "auto"},
		TLS: TLS{
			Pin:           []string{"github.com", "www.google.com", "cloudflare-dns.com", "registry.npmjs.org"},
			LearnIssuers:  false,
			ExpectIssuers: map[string]string{},
			TimeoutSec:    10,
		},
		DNS: DNS{
			Anchors:    []string{"a.root-servers.net", "one.one.one.one", "dns.google"},
			DoH:        []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"},
			TimeoutSec: 10,
		},
		SSLStrip: SSLStrip{
			// Verified to answer plain http with a redirect and to send HSTS.
			// www.google.com looks like an obvious choice and is not one: it
			// serves 200 over http and sends no HSTS header at all.
			Hosts:      []string{"github.com", "en.wikipedia.org", "www.cloudflare.com"},
			TimeoutSec: 10,
		},
		Clock: Clock{
			NTP:        []string{"pool.ntp.org", "time.cloudflare.com"},
			TimeoutSec: 5,
		},
		Alerts:   Alerts{Sinks: []string{"log"}},
		Learning: Learning{WindowMin: 10},
		Weights:  DefaultWeights(),
	}
}

// DefaultWeights is the scoring table. See the plan's phase 2 table; every
// entry is overridable from the [weights] section of the config file.
func DefaultWeights() map[string]int {
	return map[string]int{
		// tls — witness-free (phase 0)
		"tls/shared-leaf-key":          75,
		"tls/private-root":             70,
		"tls/untrusted-root":           60,
		"tls/no-sct":                   35,
		"tls/issuer-unknown":           30,
		"tls/caa-violation":            40,
		"tls/downgrade":                25,
		"tls/leaf-rotated":             5,
		"tls/handshake-failed":         15,
		"tls/system-store-unavailable": 10,

		// witness cross-vantage (phase 2)
		"tls/witness-sct-unlogged":  50,
		"tls/witness-root-mismatch": 5,
		"witness/unreachable":       15,
		"witness/sensor-silent":     40,

		// arp - the classic same-segment attack. The gateway change is the
		// signal; the shared address is the artefact a spoofer leaves behind.
		"nd/new-router": 65,
		"nd/rogue-dns":  55,

		"nameres/answers-everything": 70,
		"nameres/contested-name":     45,

		"dhcp/rogue-gateway":     70,
		"dhcp/wpad-offered":      65,
		"dhcp/unexpected-server": 60,
		"dhcp/rogue-dns":         55,
		"dhcp/multiple-servers":  50,

		"arp/gateway-impersonation": 75,
		"arp/ip-conflict":           65,
		"arp/gateway-mac-changed":   60,
		"arp/gateway-mac-shared":    55,
		"arp/gateway-unresolved":    10,

		// dns
		"dns/resolver-disagrees": 45,
		"dns/nxdomain-to-a":      50,
		"dns/doh-unreachable":    15,

		// sslstrip
		"sslstrip/plaintext-body":  60,
		"sslstrip/no-hsts":         20,
		"sslstrip/host-unsuitable": 5,

		// truststore
		"truststore/root-added": 80,
		"truststore/young-root": 45,
		"truststore/unreadable": 10,

		// clock
		"clock/drift-major": 50,
		"clock/drift-minor": 30,
	}
}

// NameresIgnoreBrowserCandidates reports whether the WebRTC placeholder names a
// browser publishes are kept out of the answer count. On unless turned off.
func (c *Config) NameresIgnoreBrowserCandidates() bool {
	if c == nil || c.Nameres.IgnoreBrowserCandidates == nil {
		return true
	}
	return *c.Nameres.IgnoreBrowserCandidates
}

// NameresThreshold is the configured answer threshold, or 0 for the default.
func (c *Config) NameresThreshold() int {
	if c == nil {
		return 0
	}
	return c.Nameres.AnswerThreshold
}

// Cooldown is how long the same finding stays quiet on notification sinks.
func (c *Config) Cooldown() time.Duration {
	if c == nil || c.Alerts.CooldownHours <= 0 {
		return 6 * time.Hour
	}
	return time.Duration(c.Alerts.CooldownHours) * time.Hour
}

// CaptureWindow is how long a capture-fed probe may listen during one pass.
func (c *Config) CaptureWindow() time.Duration {
	if c == nil || c.Sensor.CaptureWindowSec <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.Sensor.CaptureWindowSec) * time.Second
}

// Weight returns the configured score for a vector, falling back to the
// built-in default and finally to 0 (an unknown vector never alerts).
func (c *Config) Weight(vector string) int {
	if c != nil && c.Weights != nil {
		if w, ok := c.Weights[vector]; ok {
			return w
		}
	}
	if w, ok := DefaultWeights()[vector]; ok {
		return w
	}
	return 0
}

// Path is the file this config was loaded from, or the path that was looked
// for when defaults were used.
func (c *Config) Path() string { return c.path }

// DefaultPath is where mitmwatch looks for its config file.
func DefaultPath() string {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return "/etc/mitmwatch/mitmwatch.toml"
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "mitmwatch.toml"
	}
	return filepath.Join(dir, "mitmwatch", "mitmwatch.toml")
}

// Load reads path (or DefaultPath when empty). A missing file is not an error:
// the defaults are usable and `doctor` reports which was used.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	c := Defaults()
	c.path = path

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	// Decode over the defaults so an absent key keeps its default rather than
	// zeroing out.
	if _, err := toml.Decode(string(b), c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	// [weights] is merged, not replaced: overriding one weight must not drop
	// the rest of the table.
	merged := DefaultWeights()
	for k, v := range c.Weights {
		merged[k] = v
	}
	c.Weights = merged
	return c, nil
}

// Loaded reports whether a config file actually existed.
func (c *Config) Loaded() bool {
	_, err := os.Stat(c.path)
	return err == nil
}
