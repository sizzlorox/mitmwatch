package arpprobe

import (
	"fmt"
	"strings"
)

// sscanHex parses "aa:bb:cc:dd:ee:ff" into six ints.
func sscanHex(s string, a, b, c, d, e, f *int) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return 0, fmt.Errorf("not a MAC: %q", s)
	}
	outs := []*int{a, b, c, d, e, f}
	for i, p := range parts {
		var v int
		if _, err := fmt.Sscanf(p, "%x", &v); err != nil {
			return i, err
		}
		*outs[i] = v
	}
	return 6, nil
}
