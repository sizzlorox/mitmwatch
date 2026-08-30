//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sizzlorox/mitmwatch/internal/frame"
)

// open tries a real capture socket and falls back to polling.
//
// Falling back is normal: an unprivileged run is a supported deployment. What
// must never happen is falling back silently, so the reason travels with the
// source and `doctor` prints it.
func open(ifaces []string) (Source, error) {
	name, err := pickInterface(ifaces)
	if err != nil {
		return newPollSource("no usable interface: " + err.Error()), nil
	}
	src, err := openAFPacket(name)
	if err != nil {
		return newPollSource(fmt.Sprintf("raw capture on %s unavailable (%v); "+
			"grant it with: setcap cap_net_raw,cap_net_admin+ep $(command -v mitmwatch)", name, err)), nil
	}
	return src, nil
}

// pickInterface takes the first configured name, or the one carrying the
// default route.
func pickInterface(ifaces []string) (string, error) {
	for _, n := range ifaces {
		if n != "" {
			return n, nil
		}
	}
	if n, _ := defaultRoute(); n != "" {
		return n, nil
	}
	return "", errors.New("no default route and no interface configured")
}

// bpfFilter keeps everything except bulk TCP.
//
// Precision was tempting and is the wrong trade here. A filter that reaches
// past a VLAN tag to check UDP ports has to know how many tags there are, and
// getting it wrong drops real evidence silently - which is the failure this
// codebase has already hit three times in other guises, and the worst kind,
// because an empty capture reads exactly like a quiet network.
//
// Excluding TCP is the one cut that is both trivially correct and worth making:
// on a home segment TCP is essentially all of the bytes and none of the
// evidence. Everything a probe here cares about - ARP, DHCP, mDNS, LLMNR,
// NBT-NS, router advertisements - is ARP, UDP or ICMPv6, and userspace does the
// precise matching where a mistake is visible and testable.
//
//	 0  ldh  [12]              ; ethertype
//	 1  jeq  #0x0806 -> accept ; ARP
//	 2  jeq  #0x8100 -> accept ; VLAN, unwrapped by internal/frame
//	 3  jeq  #0x0800 -> v4
//	 4  jeq  #0x86dd -> v6 else drop
//	 5  ldb  [23]              ; IPv4 protocol
//	 6  jeq  #6      -> drop   ; TCP
//	 7  ldb  [20]              ; IPv6 next header
//	 8  jeq  #6      -> drop   ; TCP
//	 9  ret  #0
//	10  ret  #262144
var bpfFilter = []unix.SockFilter{
	{Code: 0x28, Jt: 0, Jf: 0, K: 12},
	{Code: 0x15, Jt: 8, Jf: 0, K: 0x0806},
	{Code: 0x15, Jt: 7, Jf: 0, K: 0x8100},
	{Code: 0x15, Jt: 1, Jf: 0, K: 0x0800},
	{Code: 0x15, Jt: 2, Jf: 4, K: 0x86dd},
	{Code: 0x30, Jt: 0, Jf: 0, K: 23},
	{Code: 0x15, Jt: 2, Jf: 3, K: ProtoTCP},
	{Code: 0x30, Jt: 0, Jf: 0, K: 20},
	{Code: 0x15, Jt: 0, Jf: 1, K: ProtoTCP},
	{Code: 0x06, Jt: 0, Jf: 0, K: 0},
	{Code: 0x06, Jt: 0, Jf: 0, K: 262144},
}

// ProtoTCP is duplicated from internal/frame to keep this file free of an
// import that would otherwise exist only for one constant.
const ProtoTCP = 6

type afPacket struct {
	fd    int
	iface string
	ch    chan frame.Frame

	recv atomic.Uint64
	err  atomic.Pointer[error]

	closeOnce sync.Once
	done      chan struct{}

	// limit describes a capture that opened but cannot see everything, empty
	// when there is nothing to report.
	limit string
}

func openAFPacket(iface string) (*afPacket, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	// ETH_P_ALL rather than ETH_P_ARP: the filter below decides what is kept,
	// and later probes (dhcp, name resolution) extend the filter rather than
	// needing a second socket.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w", err)
	}

	// Attach the filter BEFORE binding. Bound first, frames matching nothing
	// can already be queued, and the socket would deliver pre-filter traffic
	// on its first reads.
	prog := unix.SockFprog{Len: uint16(len(bpfFilter)), Filter: &bpfFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("attach filter: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}

	// Ask the interface for every multicast group, or half the name-resolution
	// probe is watching a wire it cannot hear.
	//
	// A NIC that is neither promiscuous nor allmulti delivers only the groups
	// something on the host has joined. On a normal sensor that is 224.0.0.251
	// and ff02::fb, because avahi joined them - and nothing joins LLMNR's
	// 224.0.0.252 or ff02::1:3, because nothing on a Linux box speaks LLMNR.
	// So the hardware filter drops every LLMNR frame before the socket sees it,
	// and nameresprobe reports Captured with no answers: "no LLMNR poisoning
	// here", when it never listened. Measured on the deployed sensor - eight
	// LLMNR queries put on the segment, 519 mDNS frames captured in the same
	// window, zero LLMNR. LLMNR is the protocol Responder leans on hardest.
	//
	// ALLMULTI, not PROMISC. It is the narrowest thing that fixes it: the
	// socket wants multicast it is not a member of, not unicast addressed to
	// other machines. A detector should not quietly start reading its
	// neighbours' traffic to fix its own blind spot.
	mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_ALLMULTI}
	allmultiErr := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)

	// A read deadline is what lets Close actually stop the reader instead of
	// leaving it blocked in recvfrom until the next frame arrives - which on a
	// quiet segment can be minutes.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set receive timeout: %w", err)
	}

	a := &afPacket{
		fd:    fd,
		iface: iface,
		ch:    make(chan frame.Frame, 256),
		done:  make(chan struct{}),
	}
	if allmultiErr != nil {
		// Not fatal - ARP, DHCP and the groups the host already joined still
		// arrive, so capture is worth having. But the probe that reads LLMNR is
		// now looking at a wire it cannot fully hear, and that has to be said
		// rather than left to look like a quiet network.
		a.limit = fmt.Sprintf("multicast is filtered by the interface: could not set ALLMULTI on %s (%v), "+
			"so LLMNR and any other group nothing on this host has joined will not be seen", iface, allmultiErr)
	}
	go a.read()
	return a, nil
}

func (a *afPacket) read() {
	defer close(a.ch)
	buf := make([]byte, 2048) // covers a tagged frame; nothing watched here is larger
	for {
		select {
		case <-a.done:
			return
		default:
		}

		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		if err != nil {
			// A timeout is the normal quiet case, not a failure.
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return // closed underneath us
			}
			a.err.Store(&err)
			return
		}
		if n <= 0 {
			continue
		}
		a.recv.Add(1)

		// Copy: buf is reused on the next read, and the frame outlives it.
		b := make([]byte, n)
		copy(b, buf[:n])

		select {
		case a.ch <- frame.Frame{Time: time.Now(), Iface: a.iface, Data: b}:
		case <-a.done:
			return
		default:
			// The consumer is behind. Dropping the newest frame is better than
			// blocking the reader, which would let the kernel ring overflow and
			// lose frames without any record of it. Stats reports the loss.
		}
	}
}

func (a *afPacket) Tier() Tier                 { return Tier2Raw }
func (a *afPacket) Reason() string             { return a.limit }
func (a *afPacket) Iface() string              { return a.iface }
func (a *afPacket) Frames() <-chan frame.Frame { return a.ch }

func (a *afPacket) Err() error {
	if p := a.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Stats asks the kernel how many frames it handled and how many it had to drop
// because this process was not reading fast enough.
//
// PACKET_STATISTICS resets the counters on read, so the totals accumulate here
// rather than being re-read each time.
func (a *afPacket) Stats() Stats {
	s := Stats{Received: a.recv.Load()}
	if ts, err := unix.GetsockoptTpacketStats(a.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		s.Dropped = uint64(ts.Drops)
	}
	return s
}

func (a *afPacket) Close() error {
	var err error
	a.closeOnce.Do(func() {
		close(a.done)
		err = unix.Close(a.fd)
	})
	return err
}

// htons converts to network byte order without unsafe: write big-endian, read
// back native. binary.NativeEndian makes this correct on either endianness
// rather than assuming little.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// defaultRoute reads the interface carrying the default route, the same way
// osq does. Duplicated rather than imported to keep capture free of a
// dependency on osq, which would otherwise be circular once osq grows a
// capture-backed query.
func defaultRoute() (string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0], nil
		}
	}
	return "", errors.New("no default route in /proc/net/route")
}
