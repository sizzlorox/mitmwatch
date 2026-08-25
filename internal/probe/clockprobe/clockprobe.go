// Package clockprobe detects manipulated system time.
//
// Time matters to a MITM detector for its own sake (threat P6): a certificate
// that has expired, or one issued for a window in the future, becomes valid if
// the clock can be moved. It is also why the witness, not a shared wall clock,
// drives the sync tick from phase 2 onward.
package clockprobe

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "clock"

// ntpEpochOffset converts between the NTP epoch (1900) and the Unix epoch.
const ntpEpochOffset = 2208988800

type source struct {
	Name string `json:"name"`
	// DriftSec is remote time minus local time. Positive means the local clock
	// is behind.
	DriftSec float64 `json:"drift_sec"`
	Err      string  `json:"err,omitempty"`
}

type snapshot struct {
	LocalTime time.Time `json:"local_time"`
	Sources   []source  `json:"sources"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) Interval() time.Duration { return 15 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	timeout := time.Duration(in.Config.Clock.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	snap := snapshot{LocalTime: time.Now().UTC()}
	for _, host := range in.Config.Clock.NTP {
		snap.Sources = append(snap.Sources, ntpSource(ctx, host, timeout))
	}
	// HTTPS Date headers are a second, independent opinion that survives UDP
	// 123 being blocked, which is common on guest and hotel networks.
	//
	// ponytail: this uses the default HTTP client, system roots and all. The
	// question is what time it is, not whether the certificate is honest -
	// that is the tls probe's job, and duplicating it here would double-count.
	for _, host := range in.Config.TLS.Pin {
		snap.Sources = append(snap.Sources, httpDateSource(ctx, host, timeout))
	}
	return probe.Encode(name, snap)
}

// ntpSource performs a minimal SNTP query (RFC 4330 section 5).
func ntpSource(ctx context.Context, host string, timeout time.Duration) source {
	s := source{Name: "ntp:" + host}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, "123"))
	if err != nil {
		s.Err = err.Error()
		return s
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl) //nolint:errcheck // deadline is best-effort
	}

	// LI = 0, VN = 3, Mode = 3 (client).
	req := make([]byte, 48)
	req[0] = 0x1B

	sent := time.Now()
	if _, err := conn.Write(req); err != nil {
		s.Err = err.Error()
		return s
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		s.Err = err.Error()
		return s
	}
	recv := time.Now()

	// Transmit timestamp: seconds at offset 40, fraction at offset 44.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 {
		s.Err = "empty transmit timestamp"
		return s
	}
	remote := time.Unix(int64(secs)-ntpEpochOffset, int64(frac)*1e9>>32).UTC()

	// Compare against the midpoint of the request, so the round trip does not
	// register as drift.
	local := sent.Add(recv.Sub(sent) / 2)
	s.DriftSec = remote.Sub(local).Seconds()
	return s
}

func httpDateSource(ctx context.Context, host string, timeout time.Duration) source {
	s := source{Name: "https:" + host}

	c := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		s.Err = err.Error()
		return s
	}
	req.Header.Set("User-Agent", "mitmwatch")

	sent := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		s.Err = err.Error()
		return s
	}
	defer resp.Body.Close()
	recv := time.Now()

	remote, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		s.Err = "no usable Date header"
		return s
	}
	local := sent.Add(recv.Sub(sent) / 2)
	s.DriftSec = remote.Sub(local).Seconds()
	return s
}

const (
	vecDriftMajor = "clock/drift-major"
	vecDriftMinor = "clock/drift-minor"
)

// HTTP Date headers only carry whole seconds, so a small apparent drift is
// quantisation, not evidence.
const (
	minorDriftSec = 60
	majorDriftSec = 300
)

func (Probe) Compare(_, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}

	// One unreachable or lying source must not raise an alarm; the median of
	// the sources that answered is the comparison.
	var drifts []float64
	agreeing := 0
	for _, s := range now.Sources {
		if s.Err == "" {
			drifts = append(drifts, s.DriftSec)
			agreeing++
		}
	}
	if agreeing < 2 {
		return nil
	}
	sort.Float64s(drifts)
	median := drifts[len(drifts)/2]
	if len(drifts)%2 == 0 {
		median = (drifts[len(drifts)/2-1] + drifts[len(drifts)/2]) / 2
	}

	abs := math.Abs(median)
	vector := ""
	switch {
	case abs >= majorDriftSec:
		vector = vecDriftMajor
	case abs >= minorDriftSec:
		vector = vecDriftMinor
	default:
		return nil
	}

	worst := make([]string, 0, len(now.Sources))
	for _, s := range now.Sources {
		if s.Err == "" {
			worst = append(worst, s.Name+"="+strconv.FormatFloat(s.DriftSec, 'f', 1, 64)+"s")
		}
	}
	return []probe.Finding{{
		Probe: name, Vector: vector, Target: "network",
		Score: cc.Weight(vector),
		Title: "This computer's clock disagrees with the rest of the internet",
		// No identity beyond the vector: the drift differs on every pass, so
		// hashing it would mean this could never be accepted at all.
		Evidence: map[string]string{
			"median_drift_sec": strconv.FormatFloat(median, 'f', 1, 64),
			"sources_agreeing": strconv.Itoa(agreeing),
			"per_source":       joinComma(worst),
			"why_it_matters":   "moving the clock can make an expired or not-yet-valid certificate look valid",
		},
	}}
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
