// Package scope implements a target-scope guardrail for agent shell commands.
//
// An operator declares which targets an engagement is authorized to touch
// (IPs, CIDR ranges, hostnames, "*.example.com" wildcards). Before a command
// is executed, Check extracts every network destination it can find and
// reports those that fall outside the declared scope.
//
// This is a best-effort guardrail, NOT a security boundary. It reads the
// command text only: it cannot see destinations built at runtime
// (`curl $(cat hosts.txt)`, base64 tricks, scripts the agent writes and then
// runs) and it does not resolve DNS, so an in-scope hostname that resolves to
// an out-of-scope address is not caught. Hard enforcement belongs at the
// network layer (an egress allow-list on the worker container).
package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// infraHosts are package mirrors and tool sources that agents legitimately
// need while setting up their environment. They are never pentest targets,
// so they are always allowed. Matching is exact-or-subdomain.
var infraHosts = []string{
	"github.com", "githubusercontent.com", "gitlab.com",
	"pypi.org", "pythonhosted.org",
	"npmjs.org", "npmjs.com", "yarnpkg.com",
	"golang.org", "go.dev", "googleapis.com",
	"rubygems.org", "crates.io", "rust-lang.org",
	"debian.org", "ubuntu.com", "kali.org",
	"docker.io", "docker.com", "ghcr.io",
	"exploit-db.com", "nist.gov", "mitre.org",
}

// notHosts are file extensions that look like TLDs when they follow a dot.
var notHosts = map[string]struct{}{
	"txt": {}, "xml": {}, "json": {}, "yaml": {}, "yml": {}, "toml": {}, "ini": {}, "conf": {}, "cfg": {},
	"log": {}, "out": {}, "csv": {}, "md": {}, "html": {}, "htm": {}, "js": {}, "ts": {}, "css": {},
	"py": {}, "pyc": {}, "rb": {}, "php": {}, "pl": {}, "go": {}, "rs": {}, "c": {}, "h": {}, "cpp": {},
	"java": {}, "class": {}, "jar": {}, "war": {}, "sh": {}, "bash": {}, "zsh": {}, "bat": {}, "ps1": {},
	"exe": {}, "dll": {}, "so": {}, "bin": {}, "elf": {}, "o": {}, "a": {},
	"zip": {}, "tar": {}, "gz": {}, "tgz": {}, "bz2": {}, "xz": {}, "7z": {}, "rar": {},
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "svg": {}, "pdf": {}, "doc": {}, "docx": {}, "xls": {}, "xlsx": {},
	"pcap": {}, "pcapng": {}, "db": {}, "sql": {}, "sqlite": {}, "key": {}, "pem": {}, "crt": {}, "cer": {},
	"lst": {}, "list": {}, "dict": {}, "wordlist": {}, "gnmap": {}, "nmap": {}, "state": {}, "tmp": {},
	"bak": {}, "old": {}, "orig": {}, "swp": {}, "lock": {}, "mod": {}, "sum": {}, "local": {}, "internal": {},
}

var (
	// scheme://[user@]host[:port] — host is captured.
	urlRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://(?:[^\s/@'"` + "`" + `]*@)?(\[[0-9a-f:.]+\]|[^\s/:'"` + "`" + `?#]+)`)
	// user@host and host:port forms used by ssh/scp/nc/etc.
	atHostRe = regexp.MustCompile(`(?i)\b[a-z0-9._\-]+@([a-z0-9][a-z0-9.\-]*[a-z0-9])`)
	// dotted-quad IPv4 with optional /prefix.
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b`)
	// bare hostname with at least one dot and an alphabetic TLD.
	hostRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9._\-/@])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24})\b`)
	// a complete hostname: one or more labels, optionally dotted.
	hostnameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*$`)
)

// Policy is an immutable set of authorized targets. A nil *Policy means
// enforcement is disabled.
type Policy struct {
	prefixes []netip.Prefix
	exact    map[string]struct{}
	suffixes []string // ".example.com" for "*.example.com"
}

// Parse builds a Policy from target entries. Accepted forms: an IP
// ("10.0.0.5"), a CIDR ("10.0.0.0/24"), a hostname ("app.example.com", apex
// only), a wildcard ("*.example.com", subdomains only) or a URL (host used).
// An empty list returns a nil Policy (enforcement disabled).
func Parse(entries []string) (*Policy, error) {
	p := &Policy{exact: map[string]struct{}{}}
	n := 0

	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		n++

		if strings.Contains(e, "://") {
			u, err := url.Parse(e)
			if err != nil || u.Hostname() == "" {
				return nil, fmt.Errorf("invalid scope entry %q", raw)
			}
			e = u.Hostname()
		}

		if pfx, err := netip.ParsePrefix(e); err == nil {
			p.prefixes = append(p.prefixes, pfx.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(e); err == nil {
			p.prefixes = append(p.prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}

		host := strings.ToLower(strings.TrimSuffix(e, "."))
		if sub, ok := strings.CutPrefix(host, "*."); ok {
			if !validHostname(sub) {
				return nil, fmt.Errorf("invalid scope entry %q", raw)
			}
			p.suffixes = append(p.suffixes, "."+sub)
			continue
		}
		if !validHostname(host) {
			return nil, fmt.Errorf("invalid scope entry %q", raw)
		}
		p.exact[host] = struct{}{}
	}

	if n == 0 {
		return nil, nil
	}
	return p, nil
}

// DenyAll returns a policy that authorizes nothing. Use it to fail closed
// when the configured scope cannot be parsed.
func DenyAll() *Policy {
	return &Policy{exact: map[string]struct{}{}}
}

func validHostname(h string) bool {
	return h != "" && len(h) <= 253 && hostnameRe.MatchString(h)
}

// Check returns the destinations in command that are outside the policy,
// sorted and de-duplicated. A nil policy allows everything.
func (p *Policy) Check(command string) []string {
	if p == nil {
		return nil
	}

	seen := map[string]struct{}{}
	add := func(s string) { seen[s] = struct{}{} }

	for _, d := range extract(command) {
		if d.prefix.IsValid() {
			if !p.allowsPrefix(d.prefix) {
				add(d.text)
			}
			continue
		}
		if !p.allowsHost(d.text) {
			add(d.text)
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

type dest struct {
	text   string       // as shown to the user
	prefix netip.Prefix // valid for IP/CIDR destinations
}

func extract(command string) []dest {
	var out []dest
	seenText := map[string]struct{}{}
	push := func(d dest) {
		if _, ok := seenText[d.text]; ok {
			return
		}
		seenText[d.text] = struct{}{}
		out = append(out, d)
	}
	// pushHost records a destination. explicit is true when the syntax itself
	// marks it as a network destination (URL, user@host), so single-label names
	// such as "dc01" count; bare tokens must look like a dotted hostname.
	pushHost := func(h string, explicit bool) {
		h = strings.ToLower(strings.Trim(h, "[]."))
		if h == "" || strings.ContainsAny(h, "$`(){}*%\\") {
			return // built at runtime; cannot be verified from the text
		}
		if addr, err := netip.ParseAddr(h); err == nil {
			addr = addr.Unmap()
			push(dest{text: addr.String(), prefix: netip.PrefixFrom(addr, addr.BitLen())})
			return
		}
		if !validHostname(h) || (!explicit && !looksLikeHost(h)) {
			return
		}
		push(dest{text: h})
	}

	for _, m := range urlRe.FindAllStringSubmatch(command, -1) {
		pushHost(m[1], true)
	}
	for _, m := range atHostRe.FindAllStringSubmatch(command, -1) {
		pushHost(m[1], true)
	}
	for _, m := range ipv4Re.FindAllStringSubmatch(command, -1) {
		text := m[1]
		if m[2] != "" {
			text += "/" + m[2]
		}
		if pfx, err := netip.ParsePrefix(text); err == nil {
			push(dest{text: text, prefix: pfx.Masked()})
		} else if addr, err := netip.ParseAddr(m[1]); err == nil && m[2] == "" {
			push(dest{text: text, prefix: netip.PrefixFrom(addr, 32)})
		}
		// Not a valid address (e.g. a version string like 999.1.1.1): ignore.
	}
	for _, m := range hostRe.FindAllStringSubmatch(command, -1) {
		pushHost(m[1], false)
	}

	return out
}

func looksLikeHost(h string) bool {
	if h == "localhost" {
		return true
	}
	i := strings.LastIndex(h, ".")
	if i < 0 {
		return false
	}
	_, isFile := notHosts[h[i+1:]]
	return !isFile
}

func (p *Policy) allowsPrefix(q netip.Prefix) bool {
	if isLoopback(q) {
		return true
	}
	for _, a := range p.prefixes {
		if a.Addr().BitLen() == q.Addr().BitLen() && a.Bits() <= q.Bits() && a.Contains(q.Addr()) {
			return true
		}
	}
	return false
}

func isLoopback(q netip.Prefix) bool {
	return q.Addr().IsLoopback() && (q.Addr().Is6() || q.Bits() >= 8)
}

func (p *Policy) allowsHost(h string) bool {
	if h == "localhost" || isInfra(h) {
		return true
	}
	if _, ok := p.exact[h]; ok {
		return true
	}
	for _, s := range p.suffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

func isInfra(h string) bool {
	for _, i := range infraHosts {
		if h == i || strings.HasSuffix(h, "."+i) {
			return true
		}
	}
	return false
}
