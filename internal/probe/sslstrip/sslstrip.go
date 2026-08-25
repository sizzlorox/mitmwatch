// Package sslstrip detects HTTPS being downgraded to plain HTTP.
//
// The hosts checked here are HSTS-preloaded, so a plain-http request to them
// must never produce a page: browsers refuse to send one at all, and the
// origin only ever redirects. A body coming back means something in the middle
// answered on the origin's behalf.
package sslstrip

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "sslstrip"

type hostObs struct {
	Host string `json:"host"`

	// Plain-http observation.
	HTTPStatus   int    `json:"http_status,omitempty"`
	HTTPLocation string `json:"http_location,omitempty"`
	HTTPBodyLen  int    `json:"http_body_len"`
	HTTPErr      string `json:"http_err,omitempty"`

	// https observation.
	HSTS     string `json:"hsts,omitempty"`
	HTTPSErr string `json:"https_err,omitempty"`
}

type snapshot struct {
	Hosts map[string]hostObs `json:"hosts"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) Interval() time.Duration { return 5 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	timeout := time.Duration(in.Config.SSLStrip.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// Redirects are the expected answer, so they must not be followed: the
	// status code is the observation.
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	snap := snapshot{Hosts: map[string]hostObs{}}
	for _, host := range in.Config.SSLStrip.Hosts {
		snap.Hosts[host] = inspect(ctx, client, host)
	}
	return probe.Encode(name, snap)
}

func inspect(ctx context.Context, c *http.Client, host string) hostObs {
	o := hostObs{Host: host}

	if resp, err := get(ctx, c, "http://"+host+"/"); err != nil {
		o.HTTPErr = err.Error()
	} else {
		defer resp.Body.Close()
		o.HTTPStatus = resp.StatusCode
		o.HTTPLocation = resp.Header.Get("Location")
		// Cap the read: the body length is all that matters and a hostile
		// middlebox should not be able to stream into the sensor.
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		o.HTTPBodyLen = int(n)
	}

	// The https side uses the default client on purpose: this probe asks
	// whether HSTS is advertised, not whether the certificate is trustworthy.
	// Certificate trust is the tls probe's job and duplicating it here would
	// double-count the same evidence.
	if resp, err := get(ctx, c, "https://"+host+"/"); err != nil {
		o.HTTPSErr = err.Error()
	} else {
		defer resp.Body.Close()
		o.HSTS = resp.Header.Get("Strict-Transport-Security")
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // drain only
	}
	return o
}

func get(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mitmwatch")
	return c.Do(req)
}

const (
	vecPlaintextBody  = "sslstrip/plaintext-body"
	vecNoHSTS         = "sslstrip/no-hsts"
	vecHostUnsuitable = "sslstrip/host-unsuitable"
)

// Compare only treats a host as strip-checkable once it has been seen
// advertising HSTS. Without that the check has no ground truth: www.google.com
// is the cautionary example - it looks like the most preloaded host on the
// internet and in fact answers plain http with 200 and sends no HSTS header,
// so a naive rule reports it as stripped forever.
func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	var prev snapshot
	hasBase, _ := base.Decode(&prev)

	hosts := make([]string, 0, len(now.Hosts))
	for h := range now.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	for _, host := range hosts {
		o := now.Hosts[host]
		p, hadPrev := prev.Hosts[host]
		everHSTS := o.HSTS != "" || (hasBase && hadPrev && p.HSTS != "")

		if !everHSTS {
			// Not an attack: this host was never suitable for the check. Say
			// so once, as information, so the config can be fixed.
			if o.HTTPSErr == "" {
				add(probe.Finding{
					Vector: vecHostUnsuitable, Target: host,
					Title: host + " cannot be used for this check",
					Evidence: map[string]string{
						"reason": "it never advertises Strict-Transport-Security, so there is nothing to downgrade",
						"action": "remove it from [sslstrip] hosts",
					},
				})
			}
			continue
		}

		if o.HTTPErr == "" && o.HTTPStatus == http.StatusOK && o.HTTPBodyLen > 0 {
			add(probe.Finding{
				Vector: vecPlaintextBody, Target: host,
				Title: "A site that should always be encrypted served an unencrypted page",
				// body_bytes moves with the page; the url is what is accepted.
				Identity: map[string]string{"url": "http://" + host + "/"},
				Evidence: map[string]string{
					"url": "http://" + host + "/", "status": strconv.Itoa(o.HTTPStatus),
					"body_bytes": strconv.Itoa(o.HTTPBodyLen),
					"expected":   "a redirect to https, never a page",
				},
			})
		}

		// Loss of HSTS relative to the baseline, not mere absence. Absence at
		// first sight is handled above.
		if o.HTTPSErr == "" && o.HSTS == "" && hasBase && hadPrev && p.HSTS != "" {
			add(probe.Finding{
				Vector: vecNoHSTS, Target: host,
				Title:  host + " stopped telling browsers to always use encryption",
				Change: true,
				Evidence: map[string]string{
					"header": "Strict-Transport-Security",
					"was":    p.HSTS, "now": "absent",
				},
			})
		}
	}
	return out
}
