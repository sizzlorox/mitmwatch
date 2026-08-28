package nameresprobe

import (
	"strings"
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// snapWith builds a snapshot directly, so the Compare rules can be exercised
// without a capture. Observe is covered separately by the wire tests.
func snapWith(t *testing.T, o answererObs, src string) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{
		Captured:  true,
		Answerers: map[string]answererObs{src: o},
		Contested: map[string][]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func compare(t *testing.T, s probe.Snapshot, cfg *config.Config) []probe.Finding {
	t.Helper()
	return Probe{}.Compare(probe.Snapshot{}, s, probe.CompareCtx{Config: cfg})
}

func vecList(fs []probe.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Vector)
	}
	return out
}

func hasVector(fs []probe.Finding, v string) *probe.Finding {
	for i := range fs {
		if fs[i].Vector == v {
			return &fs[i]
		}
	}
	return nil
}

// THE FALSE POSITIVE, measured on a real network: a browser publishes one
// random name per local address for every connection a page opens, five at a
// time, a fresh set each time. Counting them made a desktop with tabs open look
// like a credential-stealing tool every couple of hours.
func TestBrowserCandidatesDoNotRaiseAnAlarm(t *testing.T) {
	fs := compare(t, snapWith(t, answererObs{
		MAC: "5c:52:30:11:22:33", Protos: []string{"mdns"}, Heard: 5, Count: 0,
		Candidates: []string{
			"1e7784f6-fe08-43f0-a83c-a4aac943b893.local",
			"54e23aaa-f142-4932-876b-baba0ffb1e95.local",
			"c878fb51-b059-4b10-9b85-50839a9f4aad.local",
			"dfe5c978-3e7a-4f3b-81c3-d3fa4afe426b.local",
			"f492f680-3318-4f51-ae88-d1142e20f8ab.local",
		},
	}, "10.0.4.112"), config.Defaults())

	if f := hasVector(fs, vecAnswersEverything); f != nil {
		t.Fatalf("a browser publishing five private-address placeholders was reported as answering for names that are not its own: %v", f.Evidence)
	}
	// Suppressed is not the same as hidden: the exclusion changed the outcome,
	// so it is on the record.
	note := hasVector(fs, vecIgnoredCandidates)
	if note == nil {
		t.Fatalf("the exclusion left no trace at all; vectors were %v", vecList(fs))
	}
	if note.Score >= 20 {
		t.Errorf("the accounting note scored %d, which would colour a card and interrupt somebody", note.Score)
	}
	if note.Evidence["ignored"] != "5" || note.Evidence["counted"] != "0" {
		t.Errorf("the note does not say what was excluded: %v", note.Evidence)
	}
}

// THE TRUE POSITIVE that must survive it. Responder answers the questions a
// victim asked - wpad, a file server, a NetBIOS name - over LLMNR and NBT-NS,
// which is how it collects an authentication exchange.
func TestResponderStillFires(t *testing.T) {
	fs := compare(t, snapWith(t, answererObs{
		MAC: "de:ad:be:ef:00:01", Protos: []string{"llmnr", "nbt-ns"},
		Names: []string{"FILESERVER", "ISATAP", "WORKGROUP", "printer", "wpad"},
		Count: 5, Asked: 5, Heard: 5,
	}, "10.0.4.66"), config.Defaults())

	f := hasVector(fs, vecAnswersEverything)
	if f == nil {
		t.Fatalf("a host answering five asked-for names over LLMNR and NBT-NS did not fire: %v", vecList(fs))
	}
	if f.Evidence["asked_for"] != "5 of 5" {
		t.Errorf("asked_for = %q; the evidence has to separate answering questions from announcing", f.Evidence["asked_for"])
	}
	if f.Score < 60 {
		t.Errorf("score %d, want the original weight untouched", f.Score)
	}
}

// The exclusion must not become a hiding place. A name shaped like a
// placeholder that somebody actually queried was answered, not announced, and
// counts like anything else.
func TestACandidateSomebodyAskedForStillCounts(t *testing.T) {
	fs := compare(t, snapWith(t, answererObs{
		MAC: "de:ad:be:ef:00:01", Protos: []string{"mdns"},
		Names: []string{
			"1e7784f6-fe08-43f0-a83c-a4aac943b893.local",
			"54e23aaa-f142-4932-876b-baba0ffb1e95.local",
			"c878fb51-b059-4b10-9b85-50839a9f4aad.local",
			"dfe5c978-3e7a-4f3b-81c3-d3fa4afe426b.local",
			"f492f680-3318-4f51-ae88-d1142e20f8ab.local",
		},
		Count: 5, Asked: 5, Heard: 5,
	}, "10.0.4.66"), config.Defaults())

	if hasVector(fs, vecAnswersEverything) == nil {
		t.Fatal("names that were asked for were treated as unasked placeholders; the exclusion is a hiding place")
	}
}

// A host doing both must not have the real half masked by the excluded half.
func TestRealNamesAlongsideCandidatesStillFire(t *testing.T) {
	fs := compare(t, snapWith(t, answererObs{
		MAC: "de:ad:be:ef:00:01", Protos: []string{"mdns", "llmnr"},
		Names:      []string{"FILESERVER", "ISATAP", "WORKGROUP", "printer", "wpad"},
		Candidates: []string{"1e7784f6-fe08-43f0-a83c-a4aac943b893.local"},
		Count:      5, Asked: 5, Heard: 6,
	}, "10.0.4.66"), config.Defaults())

	f := hasVector(fs, vecAnswersEverything)
	if f == nil {
		t.Fatal("five real claims were masked by one browser placeholder")
	}
	if !strings.Contains(f.Evidence["ignored"], "1 browser placeholder") {
		t.Errorf("the alert does not disclose what was left out: %v", f.Evidence["ignored"])
	}
}

// The escape hatch has to actually work, or "visible and configured" is only
// half true.
func TestTheExclusionCanBeTurnedOff(t *testing.T) {
	cfg := config.Defaults()
	off := false
	cfg.Nameres.IgnoreBrowserCandidates = &off

	fs := compare(t, snapWith(t, answererObs{
		MAC: "5c:52:30:11:22:33", Protos: []string{"mdns"}, Heard: 5, Count: 0,
		Candidates: []string{
			"1e7784f6-fe08-43f0-a83c-a4aac943b893.local",
			"54e23aaa-f142-4932-876b-baba0ffb1e95.local",
			"c878fb51-b059-4b10-9b85-50839a9f4aad.local",
			"dfe5c978-3e7a-4f3b-81c3-d3fa4afe426b.local",
			"f492f680-3318-4f51-ae88-d1142e20f8ab.local",
		},
	}, "10.0.4.112"), cfg)

	if hasVector(fs, vecAnswersEverything) == nil {
		t.Fatal("ignore_browser_candidates = false did not put the names back into the count")
	}
}

// Below the threshold for ordinary reasons is not the same as below it because
// of the exclusion, and only the latter is worth a note.
func TestAQuietHostGetsNoAccountingNote(t *testing.T) {
	fs := compare(t, snapWith(t, answererObs{
		MAC: "dc:a6:32:11:22:33", Protos: []string{"mdns"},
		Names: []string{"printer.local"}, Count: 1, Heard: 2,
		Candidates: []string{"1e7784f6-fe08-43f0-a83c-a4aac943b893.local"},
	}, "10.0.4.9"), config.Defaults())

	if len(fs) != 0 {
		t.Errorf("a printer and one browser name produced %v; the log would fill with notes about nothing", vecList(fs))
	}
}

// The shape test is the whole exclusion, so it is pinned exactly. Anything a
// person could have chosen as a hostname must keep counting.
func TestOnlyTheExactPlaceholderShapeIsExcluded(t *testing.T) {
	for _, c := range []struct {
		proto, name string
		want        bool
	}{
		{"mdns", "1e7784f6-fe08-43f0-a83c-a4aac943b893.local", true},
		{"mdns", "1E7784F6-FE08-43F0-A83C-A4AAC943B893.local", true},  // case-insensitive
		{"mdns", "1e7784f6-fe08-43f0-a83c-a4aac943b893", false},       // no .local
		{"mdns", "1e7784f6-fe08-43f0-a83c-a4aac943b89.local", false},  // one short
		{"mdns", "1e7784f6fe0843f0a83ca4aac943b893.local", false},     // no dashes
		{"mdns", "g17784f6-fe08-43f0-a83c-a4aac943b893.local", false}, // not hex
		{"mdns", "my-laptop-is-called-this-and-that.local", false},
		{"mdns", "wpad.local", false},
		{"mdns", "", false},
		// The protocols a credential-stealing tool actually speaks never carry
		// these, so the shape alone must not be enough.
		{"llmnr", "1e7784f6-fe08-43f0-a83c-a4aac943b893.local", false},
		{"nbt-ns", "1e7784f6-fe08-43f0-a83c-a4aac943b893.local", false},
	} {
		if got := isWebRTCCandidate(c.proto, c.name); got != c.want {
			t.Errorf("isWebRTCCandidate(%q, %q) = %v, want %v", c.proto, c.name, got, c.want)
		}
	}
}
