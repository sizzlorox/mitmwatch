//go:build !linux

package capture

import "runtime"

// open on platforms without a pure-Go capture backend.
//
// macOS can do this through /dev/bpf and Windows needs Npcap; both are later
// phases. Until then the honest answer is tier 3 plus the reason, so `doctor`
// can say what is not covered instead of implying it is.
func open(_ []string) (Source, error) {
	return newPollSource("pure-Go raw capture is implemented for linux only; " +
		runtime.GOOS + " needs the pcap build (phase 3)"), nil
}
