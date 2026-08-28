package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/osq"
)

func store(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ident() osq.NetworkIdentity {
	return osq.NetworkIdentity{Iface: "eth0", GatewayIP: "192.0.2.1", GatewayMAC: "00:11:22:33:44:55"}
}

func TestProfileRoundTripsDeviceHistory(t *testing.T) {
	s := store(t)
	p, _, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p.RecordDevices(t0, []Device{{MAC: "dc:a6:32:11:22:33", Addrs: []string{"192.0.2.10"}, Name: "printer"}})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}

	back, fresh, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Fatal("a saved profile reloaded as brand new")
	}
	d, ok := back.Devices["dc:a6:32:11:22:33"]
	if !ok {
		t.Fatal("the device history did not survive a save and load; a restart would erase what the network contains")
	}
	if d.Name != "printer" || !d.FirstSeen.Equal(t0) || len(d.Addrs) != 1 {
		t.Errorf("device came back as %+v", d)
	}
}

// The upgrade case. Every profile already on disk was written without this
// field, so it decodes with a nil map - which reads fine and panics on the
// first write. Under Restart=always that panic is a crash loop.
func TestProfileWrittenBeforeDeviceHistoryLoadsAndIsWritable(t *testing.T) {
	s := store(t)
	key := ident().Key()
	old := map[string]any{
		"key":        key,
		"label":      "eth0",
		"trust":      "home",
		"first_seen": t0,
		"last_seen":  t0,
	}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Path(), key+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	p, _, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p.RecordDevices(t0, []Device{{MAC: "00:11:22:33:44:55"}})
	p.Accept("abc", Accept{Vector: "x"})
	p.Notified["abc"] = t0
	p.Snapshots["arp"] = p.Snapshots["arp"]

	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d profiles", len(list))
	}
	// List hands out profiles that callers write to as well.
	list[0].RecordDevices(t0, []Device{{MAC: "00:11:22:33:44:55"}})
}

// Relearning what is normal on a network is not a reason to erase the record of
// what has happened on it - and a reset that quietly did would be the easiest
// way to hide an incident from whoever looks next.
func TestResetClearsTheProfileAndKeepsTheActivityLog(t *testing.T) {
	s := store(t)
	p, _, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p.RecordDevices(t0, []Device{{MAC: "00:11:22:33:44:55"}})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(p.Key, []Event{{When: t0, Kind: "alert", Text: "something happened"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.Reset(p.Key); err != nil {
		t.Fatal(err)
	}
	evs, err := s.LoadEvents(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Text != "something happened" {
		t.Fatalf("baseline reset destroyed the activity log: %v", evs)
	}
	fresh, isNew, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew || len(fresh.Devices) != 0 {
		t.Error("reset did not clear the profile itself")
	}
}

// `profiles trust` used to save a copy taken from List. The sensor rewrites the
// same file every couple of minutes, so that rolled back everything learned
// since the listing - most visibly the device history.
func TestSetTrustPreservesWhatTheSensorWroteMeanwhile(t *testing.T) {
	s := store(t)
	p, _, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	// Someone runs `profiles list` here, then the sensor completes a cycle.
	stale, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	_ = stale
	p.RecordDevices(t0, []Device{{MAC: "dc:a6:32:11:22:33", Name: "printer"}})
	p.Notified["deadbeef"] = t0
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}

	if _, err := s.SetTrust(p.Key, TrustWork); err != nil {
		t.Fatal(err)
	}
	back, _, err := s.Load(ident(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if back.Trust != TrustWork {
		t.Errorf("trust is %q, want work", back.Trust)
	}
	if _, ok := back.Devices["dc:a6:32:11:22:33"]; !ok {
		t.Error("setting the trust level erased the device history the sensor had written")
	}
	if _, ok := back.Notified["deadbeef"]; !ok {
		t.Error("setting the trust level erased the notification cooldown state, which would re-push every standing alert")
	}
}

func TestSetTrustOnAnUnknownProfileIsAnError(t *testing.T) {
	if _, err := store(t).SetTrust("nope", TrustHome); err == nil {
		t.Error("setting trust on a profile that does not exist silently created one")
	}
}

func TestEventsRoundTripNewestKeptAndBounded(t *testing.T) {
	s := store(t)
	var evs []Event
	for i := 0; i < MaxEvents+50; i++ {
		evs = append(evs, Event{When: t0.Add(time.Duration(i) * time.Minute), Kind: "system", Text: "tick"})
	}
	if err := s.SaveEvents("k", evs); err != nil {
		t.Fatal(err)
	}
	back, err := s.LoadEvents("k")
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != MaxEvents {
		t.Fatalf("kept %d events, want the newest %d", len(back), MaxEvents)
	}
	if !back[len(back)-1].When.Equal(evs[len(evs)-1].When) {
		t.Error("the newest entry was dropped; the log kept the oldest instead")
	}
}

func TestEventEvidenceFromTheWireIsBounded(t *testing.T) {
	s := store(t)
	huge := map[string]string{}
	big := ""
	for i := 0; i < 10_000; i++ {
		big += "y"
	}
	for i := 0; i < 200; i++ {
		huge[string(rune('a'+i%26))+string(rune('a'+i/26))] = big
	}
	if err := s.SaveEvents("k", []Event{{When: t0, Kind: "alert", Text: big, Evidence: huge}}); err != nil {
		t.Fatal(err)
	}
	back, err := s.LoadEvents("k")
	if err != nil {
		t.Fatal(err)
	}
	e := back[0]
	if len(e.Evidence) > maxEventEvidence {
		t.Errorf("stored %d evidence keys from the wire", len(e.Evidence))
	}
	if len(e.Text) > maxEventText {
		t.Errorf("stored a %d-byte event text from the wire", len(e.Text))
	}
	for k, v := range e.Evidence {
		if len(v) > maxEvidenceValue {
			t.Errorf("evidence %q is %d bytes", k, len(v))
		}
	}
}

func TestMissingEventLogIsNotAnError(t *testing.T) {
	evs, err := store(t).LoadEvents("never-written")
	if err != nil || evs != nil {
		t.Errorf("LoadEvents on a fresh store = %v, %v; a sensor that has recorded nothing is not a failure", evs, err)
	}
}
