package scope

import (
	"reflect"
	"testing"
)

func mustParse(t *testing.T, entries ...string) *Policy {
	t.Helper()
	p, err := Parse(entries)
	if err != nil {
		t.Fatalf("Parse(%v) error = %v", entries, err)
	}
	return p
}

func TestParse(t *testing.T) {
	if p, err := Parse(nil); p != nil || err != nil {
		t.Fatalf("Parse(nil) = %v, %v; want nil policy (enforcement disabled)", p, err)
	}
	if p, err := Parse([]string{"", "  "}); p != nil || err != nil {
		t.Fatalf("Parse(blank) = %v, %v; want nil policy", p, err)
	}

	valid := []string{"10.0.0.5", "10.0.0.0/24", "app.example.com", "*.example.com", "https://app.example.com:8443/x", "dc01", "2001:db8::/32"}
	if _, err := Parse(valid); err != nil {
		t.Fatalf("Parse(valid) error = %v", err)
	}

	for _, bad := range []string{"10.0.0.0/99", "exa mple.com", "*.", "-bad.com", "a..b.com", "http://"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("Parse(%q) succeeded; want error", bad)
		}
	}
}

func TestCheck_NilPolicyAllowsEverything(t *testing.T) {
	var p *Policy
	if got := p.Check("nmap -sV 8.8.8.8 evil.com"); len(got) != 0 {
		t.Fatalf("nil policy flagged %v", got)
	}
}

func TestCheck(t *testing.T) {
	p := mustParse(t, "10.0.0.0/24", "192.168.1.7", "app.example.com", "*.corp.example.com", "dc01")

	tests := []struct {
		name string
		cmd  string
		want []string // out-of-scope destinations
	}{
		// in scope
		{"ip in cidr", "nmap -sV 10.0.0.15", nil},
		{"cidr inside cidr", "nmap 10.0.0.0/25", nil},
		{"exact ip", "ping -c1 192.168.1.7", nil},
		{"exact host", "curl -s https://app.example.com/login", nil},
		{"host with port", "nc app.example.com 443", nil},
		{"wildcard subdomain", "curl http://api.corp.example.com:8080/", nil},
		{"single label host", "ssh root@dc01", nil},
		{"uppercase host", "curl https://APP.EXAMPLE.COM/", nil},
		{"loopback", "curl http://127.0.0.1:8080 && curl localhost", nil},
		{"infra download", "pip install requests && git clone https://github.com/x/y.git", nil},
		{"infra subdomain", "wget https://raw.githubusercontent.com/x/y/main/a.sh", nil},

		// out of scope
		{"ip outside", "nmap 10.0.1.5", []string{"10.0.1.5"}},
		{"cidr wider than scope", "nmap 10.0.0.0/16", []string{"10.0.0.0/16"}},
		{"internet sweep", "masscan 0.0.0.0/0 -p80", []string{"0.0.0.0/0"}},
		{"other host", "curl https://other.com/", []string{"other.com"}},
		{"apex not covered by wildcard", "curl https://corp.example.com", []string{"corp.example.com"}},
		{"sibling domain", "curl https://app.example.com.evil.net/", []string{"app.example.com.evil.net"}},
		{"suffix trick", "curl https://notapp.example.com/", []string{"notapp.example.com"}},
		{"unlisted single label", "ssh root@dc02", []string{"dc02"}},
		{"bare host arg", "nikto -h target.org -p 80", []string{"target.org"}},
		{"flag equals host", "sqlmap --url=https://shop.example.net/?id=1", []string{"shop.example.net"}},
		{"userinfo in url", "curl https://user:pw@other.com/x", []string{"other.com"}},
		{"private range not implicit", "nmap 172.16.0.9", []string{"172.16.0.9"}},
		{"mixed", "nmap 10.0.0.5 10.9.9.9 app.example.com evil.io", []string{"10.9.9.9", "evil.io"}},
		{"ipv6 url", "curl http://[2001:db8::1]/", []string{"2001:db8::1"}},
		{"deduplicated and sorted", "curl z.io a.io z.io", []string{"a.io", "z.io"}},

		// must not be mistaken for targets
		{"filenames", "nmap -oN scan.txt -oX out.xml 10.0.0.5 && python3 exploit.py && cat notes.md report.pdf", nil},
		{"paths", "cat /usr/share/wordlists/rockyou.txt /etc/hosts && ls /opt/tools/bin", nil},
		{"version number", "nmap --version 7.94 && python3.11 -V", nil},
		{"no destination", "ls -la && whoami", nil},
		{"unverifiable variable", "curl http://$TARGET/ && ssh root@${HOST}", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Check(tt.cmd)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Check(%q) = %v; want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestDenyAll(t *testing.T) {
	p := DenyAll()
	if got := p.Check("nmap 10.0.0.5"); len(got) != 1 {
		t.Errorf("DenyAll allowed 10.0.0.5: %v", got)
	}
	if got := p.Check("curl http://127.0.0.1 && pip install x"); len(got) != 0 {
		t.Errorf("DenyAll blocked loopback/infra: %v", got)
	}
}
