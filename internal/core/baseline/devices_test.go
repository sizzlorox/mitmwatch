package baseline

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func seen(macs ...string) []Device {
	out := make([]Device, 0, len(macs))
	for i, m := range macs {
		out = append(out, Device{MAC: m, Addrs: []string{fmt.Sprintf("192.0.2.%d", i+1)}})
	}
	return out
}

func TestFirstSightingIsProvisionalNotEstablished(t *testing.T) {
	p := &Profile{}
	p.RecordDevices(t0, seen("00:11:22:33:44:55"))

	d := p.Devices["00:11:22:33:44:55"]
	if d.Established {
		t.Error("a device seen once was treated as established; a flood of new addresses could then evict real history")
	}
	if d.Cycles != 1 || !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(t0) {
		t.Errorf("first sighting recorded as %+v", d)
	}
}

// Both conditions, independently. A burst inside one minute is not presence,
// and neither is a single sighting that happens to be old.
func TestPromotionNeedsBothCyclesAndAnHour(t *testing.T) {
	mac := "00:11:22:33:44:55"

	fast := &Profile{}
	for i := 0; i < 10; i++ {
		fast.RecordDevices(t0.Add(time.Duration(i)*time.Minute), seen(mac))
	}
	if fast.Devices[mac].Established {
		t.Error("ten cycles inside ten minutes promoted a device; an hour of presence is the other half of the test")
	}

	slow := &Profile{}
	for i := 0; i < 2; i++ {
		slow.RecordDevices(t0.Add(time.Duration(i)*90*time.Minute), seen(mac))
	}
	if slow.Devices[mac].Established {
		t.Error("two sightings three hours apart promoted a device; repeated presence is the other half")
	}

	real := &Profile{}
	for i := 0; i < establishCycles; i++ {
		real.RecordDevices(t0.Add(time.Duration(i)*20*time.Minute), seen(mac))
	}
	if !real.Devices[mac].Established {
		t.Error("a device present across five cycles and eighty minutes was never promoted, so nothing is ever safe from eviction")
	}
}

// The attack this bounding exists for. An attacker on the segment can present
// any hardware address they like; if that could push out real records, the
// history would be an evidence-destruction channel rather than evidence.
func TestFloodOfNewAddressesCannotEvictEstablishedHistory(t *testing.T) {
	p := &Profile{}
	const real = "dc:a6:32:11:22:33"

	// A real device earns its place.
	for i := 0; i < establishCycles; i++ {
		p.RecordDevices(t0.Add(time.Duration(i)*20*time.Minute), seen(real))
	}
	if !p.Devices[real].Established {
		t.Fatal("setup: the real device was not established")
	}
	firstSeen := p.Devices[real].FirstSeen

	// Then five thousand invented ones arrive.
	at := t0.Add(2 * time.Hour)
	sawCapacity := false
	for cycle := 0; cycle < 20; cycle++ {
		at = at.Add(2 * time.Minute)
		flood := make([]Device, 0, 250)
		for i := 0; i < 250; i++ {
			flood = append(flood, Device{
				MAC:   fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", cycle, i>>8, i&0xff, 0x11),
				Addrs: []string{"198.51.100.7"},
			})
		}
		if p.RecordDevices(at, flood) {
			sawCapacity = true
		}
	}

	d, ok := p.Devices[real]
	if !ok {
		t.Fatal("a flood of invented hardware addresses evicted a device that had been here for hours")
	}
	if !d.FirstSeen.Equal(firstSeen) {
		t.Errorf("the real device's history was rewritten: first seen %s, want %s", d.FirstSeen, firstSeen)
	}
	if len(p.Devices) > MaxDevices {
		t.Errorf("history grew to %d entries, past the %d cap", len(p.Devices), MaxDevices)
	}
	if !sawCapacity {
		t.Error("the history filled and dropped entries without ever saying so; capacity pressure is itself the signature of the flood that caused it")
	}
}

// Recency is the wrong key inside the provisional tier: a flood mints addresses
// that are the most recent thing on the network, so evicting the least recently
// seen would keep the invented ones and drop the honest device that keeps
// coming back.
func TestProvisionalEvictionDropsOneShotSightingsFirst(t *testing.T) {
	p := &Profile{}
	const regular = "00:11:22:33:44:55"

	// A device that turns up every cycle but has not been here an hour.
	for i := 0; i < 4; i++ {
		p.RecordDevices(t0.Add(time.Duration(i)*time.Minute), seen(regular))
	}
	// A single cycle of one-shot addresses, all newer.
	flood := make([]Device, 0, MaxProvisionalDevices*2)
	for i := 0; i < MaxProvisionalDevices*2; i++ {
		flood = append(flood, Device{MAC: fmt.Sprintf("02:aa:00:00:%02x:%02x", i>>8, i&0xff)})
	}
	p.RecordDevices(t0.Add(5*time.Minute), flood)

	if _, ok := p.Devices[regular]; !ok {
		t.Error("a device seen in four consecutive cycles was evicted by one burst of addresses seen once each")
	}
}

// Absence is not evidence. A laptop asleep, a phone out of the house, or a
// neighbour table read that returned a subset must never remove a record.
func TestRecordingASubsetRemovesNothing(t *testing.T) {
	p := &Profile{}
	p.RecordDevices(t0, seen("00:11:22:33:44:55", "dc:a6:32:11:22:33"))
	p.RecordDevices(t0.Add(time.Hour), seen("00:11:22:33:44:55"))

	gone, ok := p.Devices["dc:a6:32:11:22:33"]
	if !ok {
		t.Fatal("a device missing from one cycle was deleted from the history; that is what history is for")
	}
	if !gone.LastSeen.Equal(t0) {
		t.Errorf("an absent device had its last-seen moved forward to %s; the page would call it connected", gone.LastSeen)
	}
	if p.Devices["00:11:22:33:44:55"].Cycles != 2 {
		t.Error("the present device did not accumulate a cycle")
	}
}

func TestAddressesAndNameAreBounded(t *testing.T) {
	p := &Profile{}
	long := ""
	for i := 0; i < 4096; i++ {
		long += "x"
	}
	for i := 0; i < 20; i++ {
		p.RecordDevices(t0.Add(time.Duration(i)*time.Minute), []Device{{
			MAC:   "00:11:22:33:44:55",
			Addrs: []string{fmt.Sprintf("192.0.2.%d", i)},
			Name:  long,
		}})
	}
	d := p.Devices["00:11:22:33:44:55"]
	if len(d.Addrs) > maxAddrs {
		t.Errorf("kept %d addresses; a host cycling through leases would grow the profile without limit", len(d.Addrs))
	}
	if d.Addrs[0] != "192.0.2.19" {
		t.Errorf("newest address is %q, want the most recent one first", d.Addrs[0])
	}
	if len(d.Name) > maxNameLen {
		t.Errorf("stored a %d-byte name from the network", len(d.Name))
	}
	if d.Cycles > maxCycles {
		t.Errorf("cycle counter reached %d, past its cap", d.Cycles)
	}
}

func TestMovingAddressStaysOneDevice(t *testing.T) {
	p := &Profile{}
	p.RecordDevices(t0, []Device{{MAC: "00:11:22:33:44:55", Addrs: []string{"192.0.2.10"}}})
	p.RecordDevices(t0.Add(time.Hour), []Device{{MAC: "00:11:22:33:44:55", Addrs: []string{"192.0.2.44"}}})

	if len(p.Devices) != 1 {
		t.Fatalf("a device that changed address became %d rows", len(p.Devices))
	}
	got := p.Devices["00:11:22:33:44:55"].Addrs
	if len(got) != 2 || got[0] != "192.0.2.44" {
		t.Errorf("addresses %v, want the new lease first and the old one kept", got)
	}
}

func TestRecordDevicesOnNilMapDoesNotPanic(t *testing.T) {
	// A profile written before this field existed decodes with a nil map, which
	// reads fine and panics on the first write. The sensor restarts on failure,
	// so that panic is a crash loop.
	p := &Profile{}
	if p.Devices != nil {
		t.Fatal("setup: expected a nil map")
	}
	p.RecordDevices(t0, seen("00:11:22:33:44:55"))
	if len(p.Devices) != 1 {
		t.Error("recording into a nil device map did not work")
	}
}

func TestDeviceListIsOrderedAndStable(t *testing.T) {
	p := &Profile{}
	p.RecordDevices(t0, seen("00:11:22:33:44:55"))
	p.RecordDevices(t0.Add(time.Hour), seen("dc:a6:32:11:22:33"))

	for i := 0; i < 5; i++ {
		l := p.DeviceList()
		if len(l) != 2 || l[0].MAC != "dc:a6:32:11:22:33" {
			t.Fatalf("device list %v, want most recently seen first and the same order every time", l)
		}
	}
}
