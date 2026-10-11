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

func TestValidateScope_EgressEnforcementPreconditions(t *testing.T) {
	ok := Config{ScopeAllowedTargets: "10.0.0.0/24", ScopeEgressEnforce: true}
	require.NoError(t, ok.ValidateScope())

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"no targets", func(c *Config) { c.ScopeAllowedTargets = "" }, "needs SCOPE_ALLOWED_TARGETS"},
		{"host network", func(c *Config) { c.DockerNetwork = "host" }, "DOCKER_NETWORK=host"},
		{"host network any case", func(c *Config) { c.DockerNetwork = "Host" }, "DOCKER_NETWORK=host"},
		{"net admin", func(c *Config) { c.DockerNetAdmin = true }, "DOCKER_NET_ADMIN"},
		{"docker inside", func(c *Config) { c.DockerInside = true }, "DOCKER_INSIDE"},
		{"external inside daemon", func(c *Config) { c.DockerInsideHost = "tcp://10.0.0.1:2376" }, "DOCKER_INSIDE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ok
			tt.mutate(&cfg)
			err := cfg.ValidateScope()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	// the same settings are fine when egress enforcement is off
	off := Config{ScopeAllowedTargets: "10.0.0.0/24", DockerNetwork: "host", DockerNetAdmin: true, DockerInside: true}
	assert.NoError(t, off.ValidateScope())
}
