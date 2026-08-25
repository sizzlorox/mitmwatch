package main

import (
	"context"
	"fmt"
	"io"

	"github.com/sizzlorox/mitmwatch/internal/core/alert"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// maxNotifyState bounds how many finding hashes a profile remembers having
// pushed. A network producing a slow drip of one-off findings would otherwise
// grow the profile file forever.
const maxNotifyState = 512

// deliver sends alerts, applying cooldown to everything except the log.
//
// The split is deliberate. The log is a record and must be complete, so it gets
// every alert every time. A notification interrupts a person, and the second
// identical interruption is worth less than the first - so those are held for
// the cooldown window, re-stated afterwards, and forgotten when the condition
// clears.
func (e *env) deliver(ctx context.Context, res verdict.Result, all []probe.Finding, out io.Writer) []error {
	sinks, err := alert.Sinks(e.cfg, out)
	if err != nil {
		return []error{err}
	}

	var errs []error
	var push []alert.Sink
	for _, s := range sinks {
		if s.Name() == "log" {
			for _, a := range res.Alerts {
				if err := s.Send(ctx, a); err != nil {
					errs = append(errs, fmt.Errorf("sink %s: %w", s.Name(), err))
				}
			}
			continue
		}
		push = append(push, s)
	}
	if len(push) == 0 {
		return errs
	}

	cd := alert.NewCooldown(e.profile.Notified, e.cfg.Cooldown())

	// Forget findings that no longer appear, so a condition that clears and
	// comes back is announced immediately rather than waiting out a window it
	// started before it went away. Held alerts count as live: they are still
	// true, merely suppressed by the learning window.
	//
	// NOT on the first cycle after start. The cooldown state is persisted in the
	// profile, but the in-memory finding union (e.recent) starts empty on every
	// restart - and the sensor restarts on every upgrade and on any crash under
	// Restart=always. So the first cycle's `live` set is missing every
	// persistent finding, and forgetting on it would delete their cooldown
	// entries and re-push all of them. Two quick restarts would fire a fresh
	// notification of everything. Skip the forget until the sensor has observed
	// at least one full picture of its own.
	if !e.firstDeliver {
		live := map[string]bool{}
		for _, f := range all {
			live[f.Hash()] = true
		}
		cd.Forget(live)
	}
	e.firstDeliver = false

	due := cd.Filter(res.Alerts)
	sent := make([]verdict.Alert, 0, len(due))
	for _, a := range due {
		delivered := false
		for _, s := range push {
			if err := s.Send(ctx, a); err != nil {
				errs = append(errs, fmt.Errorf("sink %s: %w", s.Name(), err))
				continue
			}
			delivered = true
		}
		// Only a delivery that actually happened starts the clock. A push that
		// failed must be retried next pass, not silenced for six hours.
		if delivered {
			sent = append(sent, a)
		}
	}
	cd.Record(sent)
	cd.Prune(maxNotifyState)
	e.profile.Notified = cd.Sent
	return errs
}
