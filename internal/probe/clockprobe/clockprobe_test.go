package clockprobe

import (
	"testing"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func cc(t *testing.T) probe.CompareCtx {
	t.Helper()
	return probe.CompareCtx{Config: config.Defaults(), Trust: "unknown"}
}

func snap(t *testing.T, srcs ...source) probe.Snapshot {
	t.Helper()
	s, err := probe.Encode(name, snapshot{Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func vectorOf(fs []probe.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	return fs[0].Vector
}

func TestAgreeingClocksAreSilent(t *testing.T) {
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t,
		source{Name: "a", DriftSec: 0.4}, source{Name: "b", DriftSec: -0.2},
		source{Name: "c", DriftSec: 1.0}), cc(t))
	if len(fs) != 0 {
		t.Fatalf("sub-second drift reported: %v", fs)
	}
}

func TestDriftBands(t *testing.T) {
	for _, tc := range []struct {
		drift float64
		want  string
	}{{30, ""}, {90, vecDriftMinor}, {-90, vecDriftMinor}, {600, vecDriftMajor}, {-600, vecDriftMajor}} {
		fs := (Probe{}).Compare(probe.Snapshot{}, snap(t,
			source{Name: "a", DriftSec: tc.drift},
			source{Name: "b", DriftSec: tc.drift},
			source{Name: "c", DriftSec: tc.drift}), cc(t))
		if got := vectorOf(fs); got != tc.want {
			t.Errorf("drift %.0fs gave %q, want %q", tc.drift, got, tc.want)
		}
	}
}

// One lying or broken source must not move the verdict: the median decides.
func TestSingleOutlierIsIgnored(t *testing.T) {
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t,
		source{Name: "honest-a", DriftSec: 0.1},
		source{Name: "honest-b", DriftSec: 0.2},
		source{Name: "liar", DriftSec: 100000},
		source{Name: "honest-c", DriftSec: 0.3}), cc(t))
	if len(fs) != 0 {
		t.Fatalf("one outlier among four produced %v", fs)
	}
}

// With too few answers there is nothing to compare against, so stay quiet
// rather than trust a single source.
func TestTooFewSourcesIsQuiet(t *testing.T) {
	fs := (Probe{}).Compare(probe.Snapshot{}, snap(t,
		source{Name: "a", DriftSec: 9000},
		source{Name: "b", Err: "timeout"},
		source{Name: "c", Err: "timeout"}), cc(t))
	if len(fs) != 0 {
		t.Fatalf("a single reachable source produced %v", fs)
	}
}
