// Package nameresprobe watches multicast name resolution for a host that
// answers to everything.
//
// When Windows cannot resolve a name through DNS it shouts the question at the
// whole segment over LLMNR, NBT-NS or mDNS, and believes the first machine that
// answers. Tools built around this - Responder is the common one - answer every
// query with their own address. The victim connects to the attacker thinking it
// is a file share, and hands over an authentication exchange that can be
// relayed or cracked offline. It costs the attacker nothing but being present,
// and the user sees a directory that failed to open.
//
// The signal is not that a host answers. Every printer and phone on the network
// answers mDNS constantly, for its own names. The signal is a host answering
// for names that are not its own, in quantity: a legitimate responder knows one
// or two names, and a tool pretending to be everything knows however many were
// asked for.
//
// This probe only listens. Sending is opt-in - see honeytokens - because a
// security tool that emits traffic by surprise is a different product from one
// that watches.
package nameresprobe

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "nameres"

// answererObs is what one host was heard claiming.
type answererObs struct {
	MAC    string   `json:"mac,omitempty"`
	Names  []string `json:"names,omitempty"`
	Protos []string `json:"protos,omitempty"`
	Count  int      `json:"count"`
}

type snapshot struct {
	// Answerers is keyed by the address that sent the answers, this pass only.
	Answerers map[string]answererObs `json:"answerers,omitempty"`
	// Contested lists names answered by more than one address.
	Contested map[string][]string `json:"contested,omitempty"`
	Captured  bool                `json:"captured"`
	Frames    int                 `json:"frames,omitempty"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) ConsumesFrames() bool    { return true }
func (Probe) Interval() time.Duration { return 2 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	snap := snapshot{Answerers: map[string]answererObs{}, Contested: map[string][]string{}}
	if in.Frames == nil || in.CaptureWindow <= 0 {
		return probe.Encode(name, snap)
	}
	snap.Captured = true

	// name -> set of addresses that claimed it, for the contested check.
	claims := map[string]map[string]bool{}
	names := map[string]map[string]bool{}
	protos := map[string]map[string]bool{}

	deadline := time.NewTimer(in.CaptureWindow)
	defer deadline.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-deadline.C:
			break loop
		case f, ok := <-in.Frames:
			if !ok {
				break loop
			}
			snap.Frames++
			d, ok := frame.ParseUDPDatagram(f.Data)
			if !ok {
				continue
			}
			port := d.UDP.SrcPort
			if !isNameResPort(port) {
				port = d.UDP.DstPort
				if !isNameResPort(port) {
					continue
				}
			}
			answers := frame.ParseNameAnswers(port, d.UDP.Payload)
			if len(answers) == 0 {
				continue
			}

			src := d.IP.Src.String()
			mac := d.Eth.Src.String()
			o := snap.Answerers[src]
			o.MAC = mac
			snap.Answerers[src] = o

			for _, a := range answers {
				if a.Name == "" {
					continue
				}
				recordName(names, src, a.Name)
				recordName(protos, src, a.Proto)

				// Contested names are keyed by the hardware address, not by the
				// answered address and not by the L3 source. The attack is two
				// distinct devices each answering one name - Responder claims
				// "fileserver" while the real fileserver also claims it. Keying
				// on the answered address, or on the L3 source, both miss that
				// and false-fire on one ordinary dual-stack host answering A
				// from its IPv4 and AAAA from its IPv6: same device, two
				// addresses, one MAC.
				//
				// Residual, honestly: a single device answering for one name
				// over two interfaces (wired and Wi-Fi) has two MACs and still
				// trips this. That is far rarer than dual-stack, the evidence
				// names the benign case, and it is Medium not High. A baseline
				// of who-owns-what would remove it and is future work.
				recordName(claims, a.Name, mac)
			}
		}
	}

	for src, set := range names {
		o := snap.Answerers[src]
		o.Names = sortedSet(set)
		o.Count = len(o.Names)
		o.Protos = sortedSet(protos[src])
		snap.Answerers[src] = o
	}
	for n, set := range claims {
		if len(set) > 1 {
			snap.Contested[n] = sortedSet(set)
		}
	}
	return probe.Encode(name, snap)
}

func isNameResPort(p uint16) bool {
	return p == frame.MDNSPort || p == frame.LLMNRPort || p == frame.NBNSPort
}

func recordName(m map[string]map[string]bool, key, val string) {
	if m[key] == nil {
		m[key] = map[string]bool{}
	}
	m[key][val] = true
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	vecAnswersEverything = "nameres/answers-everything"
	vecContestedName     = "nameres/contested-name"
)

// answerThreshold is how many distinct names one host may claim before it stops
// looking like a device and starts looking like a tool.
//
// A printer answers for itself. A phone answers for itself and a couple of
// service names. Responder answers for whatever was asked, which on a busy
// segment is dozens within seconds. Five is comfortably above the honest case
// and far below the dishonest one; it is in config so a network with an unusual
// service discovery setup can move it without a rebuild.
const answerThreshold = 5

func (Probe) Compare(_, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	if !now.Captured {
		return nil
	}

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	threshold := answerThreshold
	if t := cc.Config.NameresThreshold(); t > 0 {
		threshold = t
	}

	srcs := make([]string, 0, len(now.Answerers))
	for s := range now.Answerers {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	for _, src := range srcs {
		o := now.Answerers[src]
		if o.Count < threshold {
			continue
		}
		add(probe.Finding{
			Vector: vecAnswersEverything, Target: src,
			Identity: map[string]string{"answerer": src},
			Title:    "A device on your network is answering to names that are not its own",
			Evidence: map[string]string{
				"address":     src,
				"hardware":    o.MAC,
				"names":       strings.Join(trim(o.Names, 12), ", "),
				"name_count":  strconv.Itoa(o.Count),
				"protocols":   strings.Join(o.Protos, ", "),
				"why":         "a printer or phone answers for itself; answering for many names is what credential-stealing tools do",
				"what_to_do":  "disconnect what you do not recognise, and change passwords used on this network today",
				"benign_case": "a service-discovery gateway or a media server bridging networks can also answer broadly",
			},
		})
	}

	names := make([]string, 0, len(now.Contested))
	for n := range now.Contested {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(probe.Finding{
			Vector: vecContestedName, Target: n,
			Identity: map[string]string{"name": n, "claimants": strings.Join(now.Contested[n], ",")},
			Title:    "Two devices are claiming the same network name",
			Evidence: map[string]string{
				"name":          n,
				"claimed_by":    strings.Join(now.Contested[n], ", "),
				"benign_case":   "one device answering over both wired and Wi-Fi, or two devices sharing a name, look like this too",
				"identified_by": "hardware address",
			},
		})
	}
	return out
}

func trim(s []string, max int) []string {
	if len(s) <= max {
		return s
	}
	out := append([]string(nil), s[:max]...)
	return append(out, "... and "+strconv.Itoa(len(s)-max)+" more")
}
