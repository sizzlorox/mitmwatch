// Package frame holds the wire types shared by every capture tier.
//
// Phase 0 only needs the envelope: probes are written against a channel of
// Frame so that Phase 1 can add real parsers without reshaping the probe API.
package frame

import "time"

// Frame is one captured link-layer frame.
type Frame struct {
	Time  time.Time
	Iface string
	Data  []byte
}
