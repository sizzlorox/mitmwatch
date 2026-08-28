package baseline

import (
	"sort"
	"time"
)

// Device is one host this network has been seen to contain, keyed by hardware
// address.
//
// It exists because "who is on my network, and since when" is a question the
// neighbour table cannot answer. That table holds what this host has resolved
// *right now*: a device that was here yesterday and is switched off today is
// simply absent from it, indistinguishable from one that was never here. The
// history is what turns a live listing into a record.
//
// It is a record for people, and nothing in detection may read it. The table is
// attacker-writable by construction - anyone on the segment can present any
// hardware address and mint a row, or claim an existing one - so feeding it back
// into a Compare would hand an attacker a pen into the detector's own state.
// That is the same discipline the reverse-DNS device names already follow.
type Device struct {
	MAC string `json:"mac"`
	// Addrs are the addresses this hardware has answered on, newest first. A
	// device that moves across a DHCP lease is one device, not two.
	Addrs []string `json:"addrs,omitempty"`
	// Name is cosmetic, from reverse DNS or the manufacturer table.
	Name      string    `json:"name,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Cycles counts distinct cycles this device was seen in, capped: it is a
	// promotion counter, not a statistic.
	Cycles int `json:"cycles"`
	// Established marks a device that has been present long enough to be part
	// of the household rather than something that appeared a minute ago. It is
	// what protects real history from being flooded out; see recordDevices.
	Established bool `json:"established,omitempty"`
	// Random marks a locally administered address. Phones rotate these, so the
	// history is of the address, not of the device, and the page has to say so.
	Random bool `json:"random,omitempty"`
}

// Bounds on one device record. Addresses and names come off the network, so
// both are capped: an attacker who can make the sensor store text can otherwise
// grow the profile without limit.
const (
	maxAddrs   = 8
	maxNameLen = 63
	// maxCycles caps the promotion counter. Past the promotion threshold the
	// exact number carries no information and only widens the stored integer.
	maxCycles = 16
)

// Device budgets.
//
// Two hard-separated tiers, because one shared budget is an eviction channel: a
// burst of invented hardware addresses would make every honest device the least
// recently seen, and the attacker would choose which real history to destroy.
// Provisional devices can only evict each other.
//
// The sizes are set well above any real household - the arp probe's own comment
// measures 40 neighbours on a busy desktop and 2 on a headless Pi - and well
// below the size of network this tool will look at.
const (
	MaxProvisionalDevices = 64
	MaxEstablishedDevices = 448
	MaxDevices            = MaxProvisionalDevices + MaxEstablishedDevices
)

// Promotion thresholds. Both must be met: one noisy cycle cannot promote
// anything, and neither can a single sighting that happens to be old.
const (
	establishCycles = 5
	establishAge    = time.Hour
)

// RecordDevices folds this cycle's sightings into the history.
//
// It only ever inserts or updates. Nothing is removed because a device was not
// seen: absence from one cycle is the normal state of a laptop that is asleep,
// and a neighbour read that failed must never be able to erase the record. The
// caller is responsible for not calling this at all when the observation was
// degraded - "I could not look" is not "nothing is there".
//
// atCapacity reports that the provisional tier filled during this cycle, so the
// caller can say so. A device history that silently drops what it cannot hold
// would be hiding exactly the flood that filled it.
func (p *Profile) RecordDevices(now time.Time, seen []Device) (atCapacity bool) {
	if p.Devices == nil {
		p.Devices = map[string]Device{}
	}
	for _, s := range seen {
		if s.MAC == "" {
			continue
		}
		d, known := p.Devices[s.MAC]
		if !known {
			d = Device{MAC: s.MAC, FirstSeen: now, Random: s.Random}
		}
		d.LastSeen = now
		if d.Cycles < maxCycles {
			d.Cycles++
		}
		d.Addrs = mergeAddrs(d.Addrs, s.Addrs)
		if s.Name != "" {
			d.Name = truncate(s.Name, maxNameLen)
		}
		// Promotion needs sustained presence measured two independent ways, so
		// that neither a burst nor a single long-lived sighting is enough.
		if !d.Established && d.Cycles >= establishCycles && now.Sub(d.FirstSeen) >= establishAge {
			d.Established = true
		}
		p.Devices[s.MAC] = d
	}
	return p.trimDevices()
}

// trimDevices enforces the two budgets, newest-arrived out of the provisional
// tier first and least-recently-seen out of the established one.
//
// An established device is never evicted to make room for a provisional one.
// That single rule is what makes a flood of invented addresses cost the
// attacker nothing but their own tier: they churn the 64 provisional slots
// among themselves and cannot touch a record that has been here for an hour.
//
// Honest about what it does not stop: an attacker patient enough to hold fake
// addresses alive across five cycles and an hour promotes them, and enough of
// those eventually displace real history. The price is sustained presence
// measured in hours, and that volume is itself the signature - which is why the
// capacity report above is not optional.
func (p *Profile) trimDevices() (atCapacity bool) {
	var prov, est []Device
	for _, d := range p.Devices {
		if d.Established {
			est = append(est, d)
		} else {
			prov = append(prov, d)
		}
	}
	if len(prov) > MaxProvisionalDevices {
		atCapacity = true
		// Fewest cycles first, oldest arrival to break the tie. Not
		// least-recently-seen: a flood mints addresses that are seen in exactly
		// one cycle and are the most recent thing on the network, so recency
		// would evict the honest device that keeps coming back and keep the
		// invented one. Counting appearances puts the flood at the front of the
		// queue it created.
		sort.Slice(prov, func(i, j int) bool {
			if prov[i].Cycles != prov[j].Cycles {
				return prov[i].Cycles < prov[j].Cycles
			}
			return prov[i].FirstSeen.Before(prov[j].FirstSeen)
		})
		for _, d := range prov[:len(prov)-MaxProvisionalDevices] {
			delete(p.Devices, d.MAC)
		}
	}
	if len(est) > MaxEstablishedDevices {
		sort.Slice(est, func(i, j int) bool { return est[i].LastSeen.Before(est[j].LastSeen) })
		for _, d := range est[:len(est)-MaxEstablishedDevices] {
			delete(p.Devices, d.MAC)
		}
	}
	return atCapacity
}

// DeviceList returns the history sorted for display: present-looking devices by
// most recently seen, so the order does not shuffle between page loads.
func (p *Profile) DeviceList() []Device {
	out := make([]Device, 0, len(p.Devices))
	for _, d := range p.Devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// mergeAddrs puts the freshly seen addresses at the front, keeps the rest in
// order, and drops the oldest past the cap.
func mergeAddrs(old, fresh []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, maxAddrs)
	for _, list := range [][]string{fresh, old} {
		for _, a := range list {
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
			if len(out) == maxAddrs {
				return out
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
