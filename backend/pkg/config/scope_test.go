package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopePolicy_EmptyDisablesEnforcement(t *testing.T) {
	for _, v := range []string{"", "   ", " , ; "} {
		p, err := (&Config{ScopeAllowedTargets: v}).ScopePolicy()
		require.NoError(t, err, "value %q", v)
		assert.Nil(t, p, "value %q must leave the guardrail off", v)
	}

	var nilCfg *Config
	p, err := nilCfg.ScopePolicy()
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestScopePolicy_ParsesMixedSeparators(t *testing.T) {
	cfg := &Config{ScopeAllowedTargets: "10.0.0.0/24, app.example.com;*.corp.example.com\n192.168.1.7"}

	p, err := cfg.ScopePolicy()
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.Empty(t, p.Check("nmap 10.0.0.9 app.example.com api.corp.example.com 192.168.1.7"))
	assert.Equal(t, []string{"10.0.1.9"}, p.Check("nmap 10.0.1.9"))
}

func TestValidateScope_RejectsGarbage(t *testing.T) {
	err := (&Config{ScopeAllowedTargets: "10.0.0.0/24,not a host!"}).ValidateScope()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCOPE_ALLOWED_TARGETS")

	assert.NoError(t, (&Config{ScopeAllowedTargets: "10.0.0.0/24"}).ValidateScope())
	assert.NoError(t, (&Config{}).ValidateScope())
}
