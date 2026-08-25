package frame

import (
	"encoding/binary"
	"net/netip"
)

// ICMPv6 types this package decodes.
const (
	ICMPv6RouterAdvert = 134
	ICMPv6NeighborAdv  = 136

	// RA option types.
	raOptSourceLLA = 1
	raOptPrefix    = 3
	raOptMTU       = 5
	raOptRDNSS     = 25 // recursive DNS server (RFC 8106) - the DNS-hijack vector

	raHeaderLen = 16 // ICMPv6 RA fixed header, from type through retrans timer
)

// RouterAdvert is a parsed IPv6 Router Advertisement - how a router tells the
// segment "I am your default gateway, here is your prefix, here are your DNS
// servers". A rogue RA is a man-in-the-middle that needs no ARP: on a dual-stack
// network, hosts prefer IPv6, so an attacker who sends RAs becomes the gateway
// and the resolver for everything, and the victim never touches IPv4 again.
type RouterAdvert struct {
	// RouterMAC is the source hardware address the RA came from (the L2 source,
	// which a rogue router cannot borrow from the real one without also winning
	// neighbor discovery).
	RouterMAC MAC
	// RouterIP is the link-local source address that is claiming to be a router.
	RouterIP netip.Addr
	// Lifetime is how long the sender says it should be used as a default
	// router. Zero means "I am not a default router" - only a non-zero lifetime
	// is a claim to route traffic.
	Lifetime uint16
	// Managed and Other are the M/O flags (use DHCPv6).
	Managed, Other bool
	// Prefixes advertised for stateless autoconfiguration.
	Prefixes []netip.Prefix
	// DNS is the RDNSS option: resolvers the router hands out. A rogue value
	// here redirects every lookup, the IPv6 equivalent of rogue-DHCP DNS.
	DNS []netip.Addr
}

// IsDefaultRouter reports whether this RA claims routing authority. An RA with
// a zero lifetime is deprecating itself, not claiming to route.
func (r RouterAdvert) IsDefaultRouter() bool { return r.Lifetime > 0 }

// ParseRouterAdvert decodes an RA from an Ethernet frame, or reports false.
//
// It enforces the protocol's own anti-spoofing rule: a genuine RA arrives with
// an IPv6 hop limit of 255, because a router on the local link never decrements
// it, so anything less has been forwarded and cannot be a legitimate on-link
// RA. This is a real check the protocol builds in, not a heuristic.
func ParseRouterAdvert(b []byte) (RouterAdvert, bool) {
	eth, ok := ParseEthernet(b)
	if !ok || eth.EtherType != EtherTypeIPv6 {
		return RouterAdvert{}, false
	}
	ip, ok := ParseIPv6(eth.Payload)
	if !ok || ip.Proto != ProtoICMPv6 || ip.HopLimit != 255 {
		return RouterAdvert{}, false
	}
	p := ip.Payload
	if len(p) < raHeaderLen || p[0] != ICMPv6RouterAdvert {
		return RouterAdvert{}, false
	}

	ra := RouterAdvert{
		RouterMAC: eth.Src,
		RouterIP:  ip.Src,
		Lifetime:  binary.BigEndian.Uint16(p[6:8]),
		Managed:   p[4]&0x80 != 0,
		Other:     p[4]&0x40 != 0,
	}

	// Options are a TLV list, each length in units of 8 bytes. Every read is
	// bounded by the buffer, never by the length octet alone - the sender of a
	// rogue RA is exactly the attacker this parser must not trust.
	opts := p[raHeaderLen:]
	for len(opts) >= 2 {
		typ := opts[0]
		olen := int(opts[1]) * 8
		if olen == 0 || olen > len(opts) {
			break
		}
		body := opts[2:olen]
		switch typ {
		case raOptPrefix:
			// prefix-length(1) flags(1) valid(4) preferred(4) reserved(4) prefix(16)
			if len(body) >= 30 {
				plen := int(body[0])
				if plen <= 128 {
					addr := netip.AddrFrom16([16]byte(body[14:30]))
					if pfx, err := addr.Prefix(plen); err == nil {
						ra.Prefixes = append(ra.Prefixes, pfx)
					}
				}
			}
		case raOptRDNSS:
			// reserved(2) lifetime(4) then one or more 16-byte addresses.
			if len(body) >= 6 {
				addrs := body[6:]
				for len(addrs) >= 16 {
					ra.DNS = append(ra.DNS, netip.AddrFrom16([16]byte(addrs[:16])).Unmap())
					addrs = addrs[16:]
				}
			}
		case raOptSourceLLA, raOptMTU:
			// decoded for completeness; not scored
		}
		opts = opts[olen:]
	}
	return ra, true
}
