// Package dnsprobe compares what the local resolver answers against what
// DNS-over-HTTPS answers.
//
// The DoH client verifies against the embedded Mozilla bundle, never the
// system store: the comparison channel is the whole point, and a channel that
// can itself be transparently intercepted proves nothing. When DoH cannot be
// reached under those rules that is reported as a finding rather than quietly
// falling back to a weaker check.
package dnsprobe

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/roots"
)

const name = "dns"

// answer is one resolver's view of one host.
type answer struct {
	IPs      []string `json:"ips,omitempty"`
	NXDomain bool     `json:"nxdomain,omitempty"`
	Err      string   `json:"err,omitempty"`
}

type snapshot struct {
	// System is the OS resolver's answers, host -> answer.
	System map[string]answer `json:"system"`
	// DoH is endpoint -> host -> answer.
	DoH map[string]map[string]answer `json:"doh"`
	// DoHErr is endpoint -> transport-level failure, when the endpoint itself
	// could not be reached under embedded-root verification.
	DoHErr map[string]string `json:"doh_err,omitempty"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) Interval() time.Duration { return 5 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	anchors := in.Config.DNS.Anchors
	timeout := time.Duration(in.Config.DNS.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	snap := snapshot{
		System: map[string]answer{},
		DoH:    map[string]map[string]answer{},
		DoHErr: map[string]string{},
	}

	sysRes := &net.Resolver{PreferGo: false}
	for _, host := range anchors {
		snap.System[host] = systemLookup(ctx, sysRes, host, timeout)
	}

	client, err := dohClient(timeout)
	if err != nil {
		return probe.Snapshot{}, err
	}
	for _, ep := range in.Config.DNS.DoH {
		perHost := map[string]answer{}
		for _, host := range anchors {
			a := dohLookup(ctx, client, ep, host)
			// A transport failure is a property of the endpoint, not the host:
			// record it once and stop hammering the same dead endpoint.
			if a.Err != "" && len(perHost) == 0 {
				if _, dup := snap.DoHErr[ep]; !dup {
					snap.DoHErr[ep] = a.Err
				}
			}
			perHost[host] = a
		}
		snap.DoH[ep] = perHost
	}

	return probe.Encode(name, snap)
}

func systemLookup(ctx context.Context, r *net.Resolver, host string, timeout time.Duration) answer {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			return answer{NXDomain: true}
		}
		return answer{Err: err.Error()}
	}
	return answer{IPs: ipStrings(addrs)}
}

// dohClient builds an HTTP client that trusts only the embedded bundle.
func dohClient(timeout time.Duration) (*http.Client, error) {
	pool, err := roots.Pool()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil, // never route the comparison channel through a proxy
		},
	}, nil
}

// dohLookup performs an RFC 8484 GET query.
func dohLookup(ctx context.Context, c *http.Client, endpoint, host string) answer {
	wire, err := query(host)
	if err != nil {
		return answer{Err: err.Error()}
	}
	url := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(wire)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return answer{Err: err.Error()}
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.Do(req)
	if err != nil {
		return answer{Err: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return answer{Err: fmt.Sprintf("http %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return answer{Err: err.Error()}
	}
	return parseAnswer(body)
}

// query builds a wire-format A query. DoH GET requires ID 0 so that responses
// are cacheable.
func query(host string) ([]byte, error) {
	n, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	return m.Pack()
}

func parseAnswer(body []byte) answer {
	var p dnsmessage.Parser
	h, err := p.Start(body)
	if err != nil {
		return answer{Err: "malformed dns response: " + err.Error()}
	}
	if err := p.SkipAllQuestions(); err != nil {
		return answer{Err: "malformed dns response: " + err.Error()}
	}
	if h.RCode == dnsmessage.RCodeNameError {
		return answer{NXDomain: true}
	}
	var ips []string
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return answer{Err: "malformed dns answer: " + err.Error()}
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return answer{Err: err.Error()}
			}
			ips = append(ips, net.IP(r.A[:]).String())
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return answer{Err: err.Error()}
			}
			ips = append(ips, net.IP(r.AAAA[:]).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return answer{Err: err.Error()}
			}
		}
	}
	sort.Strings(ips)
	return answer{IPs: ips}
}

func fqdn(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		return h
	}
	return h + "."
}

func ipStrings(addrs []net.IPAddr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	sort.Strings(out)
	return out
}

// asDNSError is errors.As specialised to *net.DNSError, kept separate so the
// lookup path stays readable.
func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if e, ok := err.(*net.DNSError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
