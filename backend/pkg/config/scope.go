package config

import (
	"fmt"
	"strings"

	"pentagi/pkg/scope"
)

// ScopePolicy builds the target-scope policy from SCOPE_ALLOWED_TARGETS.
// It returns a nil policy when the variable is empty, which disables the
// scope guardrail (the historical behavior).
func (c *Config) ScopePolicy() (*scope.Policy, error) {
	if c == nil {
		return nil, nil
	}

	policy, err := scope.Parse(c.ScopeEntries())
	if err != nil {
		return nil, fmt.Errorf("invalid SCOPE_ALLOWED_TARGETS: %w", err)
	}

	return policy, nil
}

// ValidateScope reports whether SCOPE_ALLOWED_TARGETS parses. Callers should
// treat a non-nil result as fatal: a mistyped scope that silently fell back to
// "no restriction" would defeat the purpose of declaring one.
func (c *Config) ValidateScope() error {
	policy, err := c.ScopePolicy()
	if err != nil {
		return err
	}

	if c == nil || !c.ScopeEgressEnforce {
		return nil
	}

	// Each of these would leave the firewall rules either meaningless or
	// circumventable, so refuse to start rather than imply a restriction that
	// does not hold.
	switch {
	case policy == nil:
		return fmt.Errorf("SCOPE_EGRESS_ENFORCE needs SCOPE_ALLOWED_TARGETS: with no targets every connection would be blocked")
	case strings.EqualFold(c.DockerNetwork, "host"):
		return fmt.Errorf("SCOPE_EGRESS_ENFORCE cannot be used with DOCKER_NETWORK=host: the rules would be loaded into the host's own network stack")
	case c.DockerNetAdmin:
		return fmt.Errorf("SCOPE_EGRESS_ENFORCE cannot be used with DOCKER_NET_ADMIN=true: agents could remove the firewall rules")
	case c.DockerInside || c.DockerInsideHost != "":
		return fmt.Errorf("SCOPE_EGRESS_ENFORCE cannot be used with DOCKER_INSIDE / DOCKER_INSIDE_HOST: agents with Docker access can start unrestricted containers")
	}

	return nil
}

// ScopeEntries returns the individual SCOPE_ALLOWED_TARGETS entries as written.
func (c *Config) ScopeEntries() []string {
	if c == nil {
		return nil
	}
	return strings.FieldsFunc(c.ScopeAllowedTargets, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
}
