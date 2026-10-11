package scope

import (
	"bytes"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestBuildRuleset_DefaultDeniesAndAllowsOnlyTargets(t *testing.T) {
	rs := BuildRuleset(
		[]netip.Prefix{pfx(t, "10.0.0.0/24"), pfx(t, "203.0.113.7/32")},
		[]netip.Addr{addr(t, "192.168.65.7")},
	)

	for _, want := range []string{
		":OUTPUT DROP [0:0]",
		"-A OUTPUT -o lo -j ACCEPT",
		"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A OUTPUT -d 192.168.65.7 -p udp --dport 53 -j ACCEPT",
		"-A OUTPUT -d 192.168.65.7 -p tcp --dport 53 -j ACCEPT",
		"-A OUTPUT -d 10.0.0.0/24 -j ACCEPT",
		"-A OUTPUT -d 203.0.113.7/32 -j ACCEPT",
		"-A OUTPUT -j REJECT --reject-with icmp-admin-prohibited",
		"COMMIT",
	} {
		if !strings.Contains(rs.IPv4, want+"\n") {
			t.Errorf("IPv4 ruleset missing %q:\n%s", want, rs.IPv4)
		}
	}

	// the REJECT must come after every ACCEPT, or targets would be unreachable
	if strings.LastIndex(rs.IPv4, "-d 203.0.113.7/32") > strings.Index(rs.IPv4, "REJECT") {
		t.Errorf("REJECT precedes an ACCEPT rule:\n%s", rs.IPv4)
	}
}

func TestBuildRuleset_SplitsFamilies(t *testing.T) {
	rs := BuildRuleset(
		[]netip.Prefix{pfx(t, "10.0.0.5/32"), pfx(t, "2001:db8::/32")},
		[]netip.Addr{addr(t, "10.0.0.2"), addr(t, "2001:4860:4860::8888")},
	)

	if strings.Contains(rs.IPv4, "2001:") || strings.Contains(rs.IPv6, "10.0.0") {
		t.Errorf("address families leaked across rulesets:\nv4:\n%s\nv6:\n%s", rs.IPv4, rs.IPv6)
	}
	if !strings.Contains(rs.IPv6, "-d 2001:db8::/32 -j ACCEPT") ||
		!strings.Contains(rs.IPv6, "icmp6-adm-prohibited") {
		t.Errorf("IPv6 ruleset incomplete:\n%s", rs.IPv6)
	}
}

func TestBuildRuleset_NoTargetsStillDeniesEverythingElse(t *testing.T) {
	rs := BuildRuleset(nil, nil)

	for _, s := range []string{rs.IPv4, rs.IPv6} {
		if !strings.Contains(s, ":OUTPUT DROP") || !strings.Contains(s, "REJECT") {
			t.Errorf("empty-target ruleset must still deny by default:\n%s", s)
		}
		if strings.Count(s, "-j ACCEPT") != 2 { // loopback + established only
			t.Errorf("empty-target ruleset allows more than loopback/replies:\n%s", s)
		}
	}
}

func TestBuildRuleset_DeterministicAndDeduplicated(t *testing.T) {
	a := BuildRuleset(
		[]netip.Prefix{pfx(t, "10.0.0.9/24"), pfx(t, "10.0.0.0/24"), pfx(t, "9.9.9.9/32")},
		[]netip.Addr{addr(t, "8.8.8.8"), addr(t, "8.8.8.8")},
	)
	b := BuildRuleset(
		[]netip.Prefix{pfx(t, "9.9.9.9/32"), pfx(t, "10.0.0.0/24")},
		[]netip.Addr{addr(t, "8.8.8.8")},
	)

	if a != b {
		t.Errorf("same inputs in different order/duplication gave different output:\n%s\nvs\n%s", a.IPv4, b.IPv4)
	}
	if strings.Count(a.IPv4, "-d 10.0.0.0/24") != 1 {
		t.Errorf("prefix not de-duplicated/masked:\n%s", a.IPv4)
	}
}

func TestBuildRuleset_NameserverNormalization(t *testing.T) {
	rs := BuildRuleset(nil, []netip.Addr{
		addr(t, "127.0.0.11"),         // docker embedded DNS: covered by loopback rule
		addr(t, "::ffff:192.168.0.1"), // v4-mapped must land in the v4 rules
		addr(t, "fe80::1%eth0"),       // zone must be stripped
	})

	if strings.Contains(rs.IPv4, "127.0.0.11") {
		t.Errorf("loopback resolver got a redundant rule:\n%s", rs.IPv4)
	}
	if !strings.Contains(rs.IPv4, "-d 192.168.0.1 -p udp --dport 53") {
		t.Errorf("v4-mapped resolver not unmapped into IPv4 rules:\n%s", rs.IPv4)
	}
	if strings.Contains(rs.IPv6, "%") || !strings.Contains(rs.IPv6, "-d fe80::1 -p udp --dport 53") {
		t.Errorf("zone suffix not stripped:\n%s", rs.IPv6)
	}
}

// Every line must come from the fixed vocabulary below. If a future edit lets
// free text (a hostname, a user string) reach the script, this fails.
func TestBuildRuleset_OnlyFixedVocabulary(t *testing.T) {
	rs := BuildRuleset(
		[]netip.Prefix{pfx(t, "10.0.0.0/24"), pfx(t, "2001:db8::1/128")},
		[]netip.Addr{addr(t, "10.0.0.2"), addr(t, "2001:db8::53")},
	)

	allowed := []*regexp.Regexp{
		regexp.MustCompile(`^\*filter$`),
		regexp.MustCompile(`^:(INPUT|FORWARD) ACCEPT \[0:0\]$`),
		regexp.MustCompile(`^:OUTPUT DROP \[0:0\]$`),
		regexp.MustCompile(`^-A OUTPUT -o lo -j ACCEPT$`),
		regexp.MustCompile(`^-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT$`),
		regexp.MustCompile(`^-A OUTPUT -d [0-9a-f:.]+ -p (udp|tcp) --dport 53 -j ACCEPT$`),
		regexp.MustCompile(`^-A OUTPUT -d [0-9a-f:.]+(/[0-9]{1,3})? -j ACCEPT$`),
		regexp.MustCompile(`^-A OUTPUT -j REJECT --reject-with icmp6?-adm(in)?-prohibited$`),
		regexp.MustCompile(`^COMMIT$`),
	}

	for _, script := range []string{rs.IPv4, rs.IPv6} {
		for _, line := range strings.Split(strings.TrimSuffix(script, "\n"), "\n") {
			ok := false
			for _, re := range allowed {
				if re.MatchString(line) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("unexpected line in ruleset: %q", line)
			}
		}
	}
}

// Validate against the real parser when the tool is present and permitted.
func TestBuildRuleset_AcceptedByIptablesRestore(t *testing.T) {
	rs := BuildRuleset(
		[]netip.Prefix{pfx(t, "10.0.0.0/24"), pfx(t, "203.0.113.7/32"), pfx(t, "2001:db8::/32")},
		[]netip.Addr{addr(t, "192.168.65.7"), addr(t, "2001:4860:4860::8888")},
	)

	for _, tc := range []struct{ bin, script string }{
		{"iptables-restore", rs.IPv4},
		{"ip6tables-restore", rs.IPv6},
	} {
		path, err := exec.LookPath(tc.bin)
		if err != nil {
			t.Skipf("%s not installed", tc.bin)
		}
		cmd := exec.Command(path, "--test")
		cmd.Stdin = strings.NewReader(tc.script)
		var out bytes.Buffer
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			if strings.Contains(out.String(), "Permission denied") || strings.Contains(out.String(), "Operation not permitted") {
				t.Skipf("%s --test not permitted here: %s", tc.bin, out.String())
			}
			t.Errorf("%s rejected the ruleset: %v\n%s\n--- script ---\n%s", tc.bin, err, out.String(), tc.script)
		}
	}
}
