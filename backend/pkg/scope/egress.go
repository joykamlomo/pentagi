package scope

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Ruleset is a pair of iptables-restore scripts that confine a container's
// outbound traffic. Everything is dropped (with a fast REJECT so tools fail
// immediately instead of hanging) except loopback, replies to inbound
// connections, DNS to the container's own resolvers, and the listed targets.
//
// The scripts are built only from values parsed as IP addresses or prefixes,
// never from hostnames or free text, so they cannot carry injected syntax.
type Ruleset struct {
	IPv4 string
	IPv6 string
}

// BuildRuleset renders the egress rules. targets are the authorized IP ranges
// (including any resolved hostnames) and nameservers are the container's DNS
// resolvers. Output is deterministic: entries are de-duplicated and sorted.
func BuildRuleset(targets []netip.Prefix, nameservers []netip.Addr) Ruleset {
	var t4, t6 []netip.Prefix
	for _, t := range dedupePrefixes(targets) {
		if t.Addr().Is4() {
			t4 = append(t4, t)
		} else {
			t6 = append(t6, t)
		}
	}

	var n4, n6 []netip.Addr
	for _, n := range dedupeAddrs(nameservers) {
		n = n.Unmap().WithZone("") // iptables rejects zone suffixes such as %eth0
		if n.IsLoopback() {
			continue // already covered by the loopback rule
		}
		if n.Is4() {
			n4 = append(n4, n)
		} else {
			n6 = append(n6, n)
		}
	}

	return Ruleset{
		IPv4: render(t4, n4, "icmp-admin-prohibited"),
		IPv6: render(t6, n6, "icmp6-adm-prohibited"),
	}
}

func render[A interface{ String() string }, P interface{ String() string }](targets []P, nameservers []A, reject string) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":INPUT ACCEPT [0:0]\n")
	b.WriteString(":FORWARD ACCEPT [0:0]\n")
	b.WriteString(":OUTPUT DROP [0:0]\n")
	b.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	b.WriteString("-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	for _, ns := range nameservers {
		fmt.Fprintf(&b, "-A OUTPUT -d %s -p udp --dport 53 -j ACCEPT\n", ns)
		fmt.Fprintf(&b, "-A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT\n", ns)
	}
	for _, t := range targets {
		fmt.Fprintf(&b, "-A OUTPUT -d %s -j ACCEPT\n", t)
	}
	fmt.Fprintf(&b, "-A OUTPUT -j REJECT --reject-with %s\n", reject)
	b.WriteString("COMMIT\n")
	return b.String()
}

func dedupePrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func dedupeAddrs(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
