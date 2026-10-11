package docker

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"pentagi/pkg/scope"

	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedDaemon answers exec requests from a handler keyed on the command, and
// records every exec so tests can assert on what ran and with which privileges.
type scriptedDaemon struct {
	mu      sync.Mutex
	handler func(cmd []string) (out string, exit int)
	created []client.ExecCreateOptions
	results map[string]int // exec id -> exit code
	outputs map[string]string
	nextID  int
}

func newDaemon(handler func(cmd []string) (string, int)) *scriptedDaemon {
	return &scriptedDaemon{handler: handler, results: map[string]int{}, outputs: map[string]string{}}
}

func (d *scriptedDaemon) ContainerExecCreate(_ context.Context, _ string, o client.ExecCreateOptions) (client.ExecCreateResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.created = append(d.created, o)
	d.nextID++
	id := "exec-" + string(rune('a'+d.nextID))
	out, code := d.handler(o.Cmd)
	d.outputs[id], d.results[id] = out, code
	return client.ExecCreateResult{ID: id}, nil
}

func (d *scriptedDaemon) ContainerExecAttach(_ context.Context, id string, _ client.ExecAttachOptions) (client.HijackedResponse, error) {
	d.mu.Lock()
	out := d.outputs[id]
	d.mu.Unlock()
	pr, pw := net.Pipe()
	go func() {
		_, _ = pw.Write([]byte(strings.ReplaceAll(out, "\n", "\r\n"))) // TTY mode emits CRLF
		_ = pw.Close()
	}()
	return client.HijackedResponse{Conn: pr, Reader: bufio.NewReader(pr)}, nil
}

func (d *scriptedDaemon) ContainerExecInspect(_ context.Context, id string) (client.ExecInspectResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return client.ExecInspectResult{ID: id, ExitCode: d.results[id]}, nil
}

func (d *scriptedDaemon) commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.created))
	for i, c := range d.created {
		out[i] = strings.Join(c.Cmd, " ")
	}
	return out
}

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(&strings.Builder{})
	return logrus.NewEntry(l)
}

func mustPolicy(t *testing.T, entries ...string) *scope.Policy {
	t.Helper()
	p, err := scope.Parse(entries)
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

// healthy simulates a container with iptables, one resolver, working DNS for
// app.example.com, and a default-deny policy that sticks after loading.
func healthy(cmd []string) (string, int) {
	joined := strings.Join(cmd, " ")
	switch {
	case strings.Contains(joined, "command -v iptables-restore"):
		return "/usr/sbin/iptables-restore\n", 0
	case joined == "cat /etc/resolv.conf":
		return "search example.com\nnameserver 192.168.65.7\n", 0
	case joined == "getent ahosts app.example.com":
		return "203.0.113.7  STREAM app.example.com\n203.0.113.7  DGRAM\n203.0.113.7  RAW\n", 0
	case strings.HasPrefix(joined, "sh -c iptables-restore"), strings.HasPrefix(joined, "sh -c ip6tables-restore"):
		return "", 0
	case joined == "iptables -S OUTPUT", joined == "ip6tables -S OUTPUT":
		return "-P OUTPUT DROP\n-A OUTPUT -o lo -j ACCEPT\n", 0
	}
	return "", 0
}

func TestApplyEgressPolicy_AppliesRulesPrivilegedAndVerifies(t *testing.T) {
	d := newDaemon(healthy)

	err := ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "10.0.0.0/24", "app.example.com"), testLogger())
	require.NoError(t, err)

	// every command must run as root with full capabilities, or it cannot touch netfilter
	for _, c := range d.created {
		assert.True(t, c.Privileged, "exec %v not privileged", c.Cmd)
		assert.Equal(t, "root", c.User)
	}

	var v4 string
	for _, c := range d.commands() {
		if strings.HasPrefix(c, "sh -c iptables-restore") {
			v4 = c
		}
	}
	require.NotEmpty(t, v4, "IPv4 rules were never loaded; ran: %v", d.commands())
	assert.Contains(t, v4, ":OUTPUT DROP")
	assert.Contains(t, v4, "-d 10.0.0.0/24 -j ACCEPT")
	assert.Contains(t, v4, "-d 203.0.113.7/32 -j ACCEPT", "hostname must be enforced as its resolved IP")
	assert.Contains(t, v4, "-d 192.168.65.7 -p udp --dport 53", "the container's resolver must stay reachable")

	cmds := d.commands()
	assert.Contains(t, cmds, "iptables -S OUTPUT", "default-deny must be verified after loading")
}

func TestApplyEgressPolicy_FailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(cmd []string) (string, int, bool) // returns handled=true to override
		wantErr string
	}{
		{
			name: "image has no iptables",
			mutate: func(cmd []string) (string, int, bool) {
				if strings.Contains(strings.Join(cmd, " "), "command -v iptables-restore") {
					return "", 1, true
				}
				return "", 0, false
			},
			wantErr: "no iptables-restore",
		},
		{
			name: "iptables-restore fails",
			mutate: func(cmd []string) (string, int, bool) {
				if strings.HasPrefix(strings.Join(cmd, " "), "sh -c iptables-restore") {
					return "iptables-restore: line 5 failed", 1, true
				}
				return "", 0, false
			},
			wantErr: "IPv4 egress rules",
		},
		{
			name: "rules loaded but default-deny not active",
			mutate: func(cmd []string) (string, int, bool) {
				if strings.Join(cmd, " ") == "iptables -S OUTPUT" {
					return "-P OUTPUT ACCEPT\n", 0, true
				}
				return "", 0, false
			},
			wantErr: "default-deny policy not active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDaemon(func(cmd []string) (string, int) {
				if out, code, ok := tt.mutate(cmd); ok {
					return out, code
				}
				return healthy(cmd)
			})

			err := ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "10.0.0.0/24"), testLogger())

			require.Error(t, err, "an unrestricted sandbox must never be reported as success")
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestApplyEgressPolicy_IPv6(t *testing.T) {
	v6Fails := func(cmd []string) (string, int) {
		if strings.HasPrefix(strings.Join(cmd, " "), "sh -c ip6tables-restore") {
			return "ip6tables-restore: command not found", 127
		}
		return healthy(cmd)
	}

	t.Run("no routable IPv6: ip6tables failure is tolerated", func(t *testing.T) {
		d := newDaemon(func(cmd []string) (string, int) {
			if strings.Join(cmd, " ") == "cat "+ipv6ProcFile {
				return "00000000000000000000000000000001 01 80 10 80 lo\nfe800000000000000042acfffe110002 05 40 20 80 eth0\n", 0
			}
			return v6Fails(cmd)
		})
		require.NoError(t, ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "10.0.0.0/24"), testLogger()))
	})

	t.Run("routable IPv6 and no ip6tables: refuse", func(t *testing.T) {
		d := newDaemon(func(cmd []string) (string, int) {
			if strings.Join(cmd, " ") == "cat "+ipv6ProcFile {
				return "20010db8000000000000000000000005 05 40 00 80 eth0\n", 0
			}
			return v6Fails(cmd)
		})
		err := ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "10.0.0.0/24"), testLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IPv6 egress rules")
	})
}

func TestApplyEgressPolicy_UnresolvableHostIsUnreachableNotFatal(t *testing.T) {
	d := newDaemon(func(cmd []string) (string, int) {
		if strings.HasPrefix(strings.Join(cmd, " "), "getent ahosts") {
			return "", 2 // getent: name not found
		}
		return healthy(cmd)
	})

	require.NoError(t, ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "10.0.0.5", "gone.example.com"), testLogger()))
}

func TestApplyEgressPolicy_RequiresPolicy(t *testing.T) {
	err := ApplyEgressPolicy(t.Context(), newDaemon(healthy), "cid", nil, testLogger())
	require.Error(t, err)
}

func TestApplyEgressPolicy_HostnameNeverReachesAShell(t *testing.T) {
	d := newDaemon(healthy)
	require.NoError(t, ApplyEgressPolicy(t.Context(), d, "cid", mustPolicy(t, "app.example.com"), testLogger()))

	for _, c := range d.created {
		if len(c.Cmd) > 0 && c.Cmd[0] == "getent" {
			assert.Equal(t, []string{"getent", "ahosts", "app.example.com"}, c.Cmd, "host must be a bare argv element")
		}
	}
}

var _ execer = (*scriptedDaemon)(nil)
