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

	entries := strings.FieldsFunc(c.ScopeAllowedTargets, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})

	policy, err := scope.Parse(entries)
	if err != nil {
		return nil, fmt.Errorf("invalid SCOPE_ALLOWED_TARGETS: %w", err)
	}

	return policy, nil
}

// ValidateScope reports whether SCOPE_ALLOWED_TARGETS parses. Callers should
// treat a non-nil result as fatal: a mistyped scope that silently fell back to
// "no restriction" would defeat the purpose of declaring one.
func (c *Config) ValidateScope() error {
	_, err := c.ScopePolicy()
	return err
}
