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
	MAC string `json:"mac,omitempty"`
	// Names are the claims that count: everything heard, less the browser
	// candidates below.
	Names  []string `json:"names,omitempty"`
	Protos []string `json:"protos,omitempty"`
	Count  int      `json:"count"`
	// Candidates are the WebRTC names excluded from Count, kept so the
	// exclusion can be shown rather than merely done. See isWebRTCCandidate.
	Candidates []string `json:"candidates,omitempty"`
	// Asked is how many of Names somebody on the segment actually queried
	// during the window. A tool answers questions; this is the count of
	// questions this host answered.
	Asked int `json:"asked"`
	// Heard is every name this host claimed, candidates included, so that
	// "5 of 5 were browser candidates" can be stated exactly.
	Heard int `json:"heard"`
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
	// Names anybody asked about during the window, and the subset each host
	// answered for that is browser-candidate shaped. Both are needed to tell a
	// tool answering questions from a host announcing itself.
	asked := map[string]bool{}
	candidates := map[string]map[string]bool{}

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
			for _, q := range frame.ParseNameQuestions(port, d.UDP.Payload) {
				asked[strings.ToLower(q)] = true
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
				if isWebRTCCandidate(a.Proto, a.Name) {
					recordName(candidates, src, a.Name)
				}

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

	// Resolve the exclusion only now that the whole window has been read: a
	// name can be answered before the query for it arrives, and a candidate
	// somebody did ask about is not a candidate, it is an answer.
	for src, set := range names {
		o := snap.Answerers[src]
		o.Heard = len(set)
		var counted, cand []string
		for n := range set {
			if candidates[src][n] && !asked[strings.ToLower(n)] {
				cand = append(cand, n)
				continue
			}
			counted = append(counted, n)
			if asked[strings.ToLower(n)] {
				o.Asked++
			}
		}
		sort.Strings(counted)
		sort.Strings(cand)
		o.Names, o.Candidates = counted, cand
		o.Count = len(counted)
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

// isWebRTCCandidate reports whether a name is a browser's private-address
// placeholder rather than a claim on anything.
//
// Every web page that opens a peer connection makes the browser list the
// addresses it can be reached on, which used to hand the site the machine's
// address on the local network. RFC 8828 replaced that with a random UUID
// published over mDNS: the page gets the UUID, a genuine peer on the same
// segment resolves it, and nobody learns the address. So a browser with tabs
// open publishes a handful of these, discards them, and publishes fresh ones
// for the next connection - which reads, to a rule that counts names, exactly
// like a host claiming to be five things at once.
//
// This was measured, not assumed. On the network this was written for, one
// desktop and one laptop produced 26 of these in fifteen minutes, five at a
// time, a new set each time, while every genuine service name on the same wire
// was being queried by somebody.
//
// Excluding them does not blind the rule, because none of them can carry the
// attack it detects. Name poisoning works by answering the question a victim
// asked - "wpad", "fileserver", a NetBIOS name - so that the victim connects
// and authenticates. Nothing ever asks for a random UUID it has not already
// been given out of band, and a name nobody asks for cannot capture anyone.
// The caller additionally requires that nobody asked: a UUID that somebody DID
// query is answered, not announced, and counts like any other name.
//
// The test is deliberately narrow on all three axes - the exact canonical UUID
// layout, the .local suffix, and mDNS - because each one is a way for a real
// claim to be mistaken for a placeholder.
func isWebRTCCandidate(proto, name string) bool {
	// LLMNR and NBT-NS never carry these, and they are the protocols the
	// credential-stealing tools actually speak.
	if proto != "mdns" {
		return false
	}
	label, ok := strings.CutSuffix(strings.ToLower(name), ".local")
	if !ok {
		return false
	}
	return isUUID(label)
}

// isUUID matches the canonical 8-4-4-4-12 hexadecimal layout, and nothing else.
// A hostname that merely contains dashes, or a shorter identifier, is a name
// somebody chose and must keep counting.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
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
	vecIgnoredCandidates = "nameres/browser-candidates-ignored"
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
	// The operator can put the browser placeholders back into the count. Off by
	// default would mean shipping the false alarm to everyone; on by default
	// with a switch, and with the Info-band note above whenever it changes an
	// outcome, keeps the exclusion visible and configured rather than silent.
	if !cc.Config.NameresIgnoreBrowserCandidates() {
		for src, o := range now.Answerers {
			o.Names = append(o.Names, o.Candidates...)
			sort.Strings(o.Names)
			o.Count, o.Candidates = len(o.Names), nil
			now.Answerers[src] = o
		}
	}

	srcs := make([]string, 0, len(now.Answerers))
	for s := range now.Answerers {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	for _, src := range srcs {
		o := now.Answerers[src]
		if o.Count < threshold {
			// Below the threshold only because browser placeholders were taken
			// out is a different thing from below it outright, and the
			// difference is recorded rather than left to be inferred from
			// silence. Info band: it is an accounting note, not something to
			// act on, so it colours no card and interrupts nobody.
			if len(o.Candidates) > 0 && o.Heard >= threshold {
				add(probe.Finding{
					Vector: vecIgnoredCandidates, Target: src,
					Identity: map[string]string{"answerer": src},
					Title:    "A browser on this device published private-address placeholders",
					Evidence: map[string]string{
						"address":         src,
						"hardware":        o.MAC,
						"names_heard":     strconv.Itoa(o.Heard),
						"ignored":         strconv.Itoa(len(o.Candidates)),
						"counted":         strconv.Itoa(o.Count),
						"examples":        strings.Join(trim(o.Candidates, 3), ", "),
						"why":             "a browser publishes a random name per connection so a web page cannot learn this machine's address on your network (RFC 8828)",
						"why_not_counted": "nothing ever asks for a random name it was not already given, and a name nobody asks for cannot capture anyone",
						"what_to_do":      "nothing; set ignore_browser_candidates = false under [nameres] to count these anyway",
					},
				})
			}
			continue
		}
		ev := map[string]string{
			"address":     src,
			"hardware":    o.MAC,
			"names":       strings.Join(trim(o.Names, 12), ", "),
			"name_count":  strconv.Itoa(o.Count),
			"asked_for":   strconv.Itoa(o.Asked) + " of " + strconv.Itoa(o.Count),
			"protocols":   strings.Join(o.Protos, ", "),
			"why":         "a printer or phone answers for itself; answering for many names is what credential-stealing tools do",
			"what_to_do":  "disconnect what you do not recognise, and change passwords used on this network today",
			"benign_case": "a service-discovery gateway or a media server bridging networks can also answer broadly",
		}
		if len(o.Candidates) > 0 {
			ev["ignored"] = strconv.Itoa(len(o.Candidates)) + " browser placeholders, not counted"
		}
		add(probe.Finding{
			Vector: vecAnswersEverything, Target: src,
			Identity: map[string]string{"answerer": src},
			Title:    "A device on your network is answering to names that are not its own",
			Evidence: ev,
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
