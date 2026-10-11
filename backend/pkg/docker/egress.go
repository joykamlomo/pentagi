package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"pentagi/pkg/scope"

	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

const (
	egressApplyTimeout = 45 * time.Second
	// ipv6ProcFile lists every IPv6 address configured in the container.
	ipv6ProcFile = "/proc/net/if_inet6"
)

// execer is the slice of the Docker API needed to run commands in a container.
type execer interface {
	ContainerExecCreate(ctx context.Context, container string, config client.ExecCreateOptions) (client.ExecCreateResult, error)
	ContainerExecAttach(ctx context.Context, execID string, config client.ExecAttachOptions) (client.HijackedResponse, error)
	ContainerExecInspect(ctx context.Context, execID string) (client.ExecInspectResult, error)
}

// ApplyEgressPolicy confines the container's outbound traffic to the targets
// in policy by loading iptables rules into its network namespace.
//
// The rules are installed with a privileged, root exec, so they work even
// though worker containers drop every capability, and the agents' own
// processes (which lack NET_ADMIN) cannot change them afterwards. The caller
// must treat any error as fatal and discard the container: a sandbox whose
// rules did not load is unrestricted.
//
// Hostname targets are resolved from inside the container (so internal DNS
// names work) and enforced as the IPs they resolve to at this moment.
// "*.example.com" wildcards cannot be expressed as IP rules and are not
// reachable in this mode; list the hosts or their address ranges explicitly.
func ApplyEgressPolicy(ctx context.Context, ex execer, containerID string, policy *scope.Policy, logger *logrus.Entry) error {
	if policy == nil {
		return fmt.Errorf("no scope policy to enforce")
	}

	ctx, cancel := context.WithTimeout(ctx, egressApplyTimeout)
	defer cancel()

	if w := policy.Wildcards(); len(w) > 0 {
		logger.WithField("wildcards", w).Warn("wildcard scope entries cannot be enforced at the network layer " +
			"and will be unreachable; list the hosts or their IP ranges explicitly")
	}

	if _, code, err := execPrivileged(ctx, ex, containerID, "sh", "-c", "command -v iptables-restore"); err != nil {
		return fmt.Errorf("failed to check for iptables: %w", err)
	} else if code != 0 {
		return fmt.Errorf("the worker image has no iptables-restore, so egress rules cannot be loaded; " +
			"use a pentest image that includes iptables (or turn SCOPE_EGRESS_ENFORCE off)")
	}

	nameservers, err := containerNameservers(ctx, ex, containerID)
	if err != nil {
		return err
	}

	targets := policy.Prefixes()
	for _, host := range policy.Hostnames() {
		addrs, err := resolveInContainer(ctx, ex, containerID, host)
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			logger.WithField("host", host).Warn("scope hostname did not resolve; it will be unreachable")
		}
		for _, a := range addrs {
			targets = append(targets, netip.PrefixFrom(a, a.BitLen()))
		}
	}

	rules := scope.BuildRuleset(targets, nameservers)

	if err := loadRules(ctx, ex, containerID, "iptables-restore", "iptables", rules.IPv4); err != nil {
		return fmt.Errorf("IPv4 egress rules: %w", err)
	}

	if err := loadRules(ctx, ex, containerID, "ip6tables-restore", "ip6tables", rules.IPv6); err != nil {
		// A container with no routable IPv6 has no IPv6 egress to restrict.
		has, checkErr := hasRoutableIPv6(ctx, ex, containerID)
		if checkErr != nil || has {
			return fmt.Errorf("IPv6 egress rules: %w", err)
		}
		logger.WithError(err).Debug("ip6tables unavailable but the container has no routable IPv6; continuing")
	}

	logger.WithFields(logrus.Fields{
		"targets":     len(targets),
		"nameservers": len(nameservers),
	}).Info("egress policy applied")

	return nil
}

// loadRules installs one family's ruleset and confirms the default-deny policy
// is really in place before returning.
func loadRules(ctx context.Context, ex execer, containerID, restoreBin, listBin, script string) error {
	const delimiter = "SCOPE_EGRESS_EOF"
	if strings.Contains(script, delimiter) {
		return fmt.Errorf("ruleset contains its own heredoc delimiter")
	}

	apply := fmt.Sprintf("%s <<'%s'\n%s%s\n", restoreBin, delimiter, script, delimiter)
	if out, code, err := execPrivileged(ctx, ex, containerID, "sh", "-c", apply); err != nil {
		return err
	} else if code != 0 {
		return fmt.Errorf("%s failed (exit %d): %s", restoreBin, code, strings.TrimSpace(out))
	}

	out, code, err := execPrivileged(ctx, ex, containerID, listBin, "-S", "OUTPUT")
	if err != nil {
		return err
	}
	if code != 0 || !strings.Contains(out, "-P OUTPUT DROP") {
		return fmt.Errorf("default-deny policy not active after loading rules (exit %d): %s", code, strings.TrimSpace(out))
	}

	return nil
}

func containerNameservers(ctx context.Context, ex execer, containerID string) ([]netip.Addr, error) {
	out, code, err := execPrivileged(ctx, ex, containerID, "cat", "/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to read resolv.conf: %w", err)
	}
	if code != 0 {
		return nil, nil // no resolver configured: nothing to allow
	}

	var servers []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				servers = append(servers, a)
			}
		}
	}
	return servers, nil
}

// resolveInContainer resolves host with the container's own resolver. host is
// passed as a single argv element, never through a shell.
func resolveInContainer(ctx context.Context, ex execer, containerID, host string) ([]netip.Addr, error) {
	out, code, err := execPrivileged(ctx, ex, containerID, "getent", "ahosts", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %q: %w", host, err)
	}
	if code != 0 {
		return nil, nil // unresolvable (getent exits 2) or getent missing
	}

	var addrs []netip.Addr
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if a, err := netip.ParseAddr(fields[0]); err == nil {
			addrs = append(addrs, a.Unmap())
		}
	}
	return addrs, nil
}

func hasRoutableIPv6(ctx context.Context, ex execer, containerID string) (bool, error) {
	out, code, err := execPrivileged(ctx, ex, containerID, "cat", ipv6ProcFile)
	if err != nil {
		return false, err
	}
	if code != 0 {
		return false, nil // file absent: IPv6 is disabled in this kernel/namespace
	}

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields[0]) != 32 {
			continue
		}
		addr := strings.ToLower(fields[0])
		if addr == "00000000000000000000000000000001" || strings.HasPrefix(addr, "fe80") {
			continue // loopback and link-local never leave the host/segment
		}
		return true, nil
	}
	return false, nil
}

// execPrivileged runs cmd in the container as root with full capabilities and
// returns its combined output and exit code.
func execPrivileged(ctx context.Context, ex execer, containerID string, cmd ...string) (string, int, error) {
	created, err := ex.ContainerExecCreate(ctx, containerID, client.ExecCreateOptions{
		Cmd:          cmd,
		User:         "root",
		Privileged:   true,
		AttachStdout: true,
		AttachStderr: true,
		TTY:          true,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := ex.ContainerExecAttach(ctx, created.ID, client.ExecAttachOptions{TTY: true})
	if err != nil {
		return "", 0, fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer resp.Close()

	data, err := io.ReadAll(resp.Reader)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read exec output: %w", err)
	}
	out := strings.ReplaceAll(string(data), "\r\n", "\n")

	// The stream closes when the process exits; allow the daemon a moment to
	// publish the exit status.
	for range 20 {
		inspected, err := ex.ContainerExecInspect(ctx, created.ID)
		if err != nil {
			return out, 0, fmt.Errorf("failed to inspect exec: %w", err)
		}
		if !inspected.Running {
			return out, inspected.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return out, 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return out, 0, fmt.Errorf("exec did not finish")
}
