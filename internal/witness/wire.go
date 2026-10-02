// Package witness is the phase 2 cross-vantage corroboration protocol.
//
// A sensor on a home LAN cannot tell a fraudulent certificate served to it
// specifically - by a compromised router, its ISP, or a BGP hijack - from the
// real one, because it only ever sees its own view. A witness on a different
// network and ASN sees the genuine certificate. When the two views of the same
// host at the same moment disagree in a way an honest certificate cannot
// produce, something between the sensor and the internet is intercepting.
//
// The protocol is one long-lived mutual-TLS connection, dialed OUT by the
// sensor (NAT-friendly), over which the WITNESS owns the clock: it pushes ticks
// carrying its own fresh observation, and the sensor feeds that observation
// into the existing tls Compare. Clock manipulation is a threat (P6), so no
// wall clock is ever compared across the two boxes - freshness is judged on the
// sensor's own monotonic clock, and replay is bounded by a witness-issued nonce
// and a monotonic sequence number.
package witness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// Proto is the wire version. A mismatch is refused rather than guessed at.
const Proto = 1

// Frame types.
const (
	TypeHello  = "hello"
	TypeTick   = "tick"
	TypeReport = "report"
	TypeBeat   = "beat"
	TypeBye    = "bye"
)

// Frame is the envelope. Messages are newline-delimited JSON: one JSON value per
// line, which needs no length framing and is trivially inspectable.
type Frame struct {
	T string          `json:"t"`
	B json.RawMessage `json:"b"`
}

// Hello is the sensor's opening frame.
type Hello struct {
	Proto    int      `json:"proto"`
	SensorID string   `json:"sensor_id"`
	Role     string   `json:"role"` // always-on | roaming
	Targets  []string `json:"targets"`
	BeatSec  int      `json:"beat_sec"`
}

// Tick is the witness's observation, pushed on its own schedule.
//
// DeadlineMono and Seq are the witness's own monotonic values, used only to
// bound replay on the witness side. The sensor never treats them as a time
// base: it stamps its own receipt time and judges freshness against that.
type Tick struct {
	Nonce   string                     `json:"nonce"`
	Seq     uint64                     `json:"seq"`
	Targets []string                   `json:"targets"`
	Refused []string                   `json:"refused,omitempty"`
	Snap    map[string]json.RawMessage `json:"snap"` // probe name -> that probe's snapshot payload
	// ObservedAtUnix is the witness's wall clock, for human-readable evidence
	// only. Nothing depends on it for correctness.
	ObservedAtUnix int64 `json:"observed_at_unix"`
	CheckNanos     map[string]int64 `json:"check_nanos,omitempty"`
}

// Report is the sensor's answer: its own view, for the witness's history and
// audit log. It is never fed back into the sensor's own detection.
type Report struct {
	Nonce string                     `json:"nonce"`
	Snap  map[string]json.RawMessage `json:"snap"`
	Err   map[string]string          `json:"err,omitempty"`
}

// Beat is a liveness ping on the idle channel, sent independently of ticks so
// that a stalled probe cannot look like a dead sensor. Seq is monotonic; the
// witness rejects a non-increasing Seq so a captured beat cannot be replayed to
// fake liveness.
type Beat struct {
	Seq uint64 `json:"seq"`
}

// Bye disarms the dead-man's switch on a graceful stop.
type Bye struct {
	Reason string `json:"reason"`
}

// maxFrame bounds a single frame so a peer cannot exhaust memory with one
// enormous line. A tick over the default host list is a few kilobytes.
const maxFrame = 1 << 20 // 1 MiB

// Encoder writes frames to a connection.
type Encoder struct{ w *json.Encoder }

// NewEncoder wraps a writer.
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: json.NewEncoder(w)} }

// Write marshals v as the body of a typed frame and writes it.
func (e *Encoder) Write(kind string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("witness: marshal %s: %w", kind, err)
	}
	return e.w.Encode(Frame{T: kind, B: b})
}

// Decoder reads frames, bounding each line's length.
type Decoder struct{ s *bufio.Scanner }

// NewDecoder wraps a reader.
func NewDecoder(r io.Reader) *Decoder {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), maxFrame)
	return &Decoder{s: s}
}

// Read returns the next frame, or io.EOF at end of stream.
func (d *Decoder) Read() (Frame, error) {
	if !d.s.Scan() {
		if err := d.s.Err(); err != nil {
			return Frame{}, err
		}
		return Frame{}, io.EOF
	}
	var f Frame
	if err := json.Unmarshal(d.s.Bytes(), &f); err != nil {
		return Frame{}, fmt.Errorf("witness: decode frame: %w", err)
	}
	return f, nil
}

// Into unmarshals a frame body into v.
func (f Frame) Into(v any) error {
	if err := json.Unmarshal(f.B, v); err != nil {
		return fmt.Errorf("witness: decode %s body: %w", f.T, err)
	}
	return nil
}
