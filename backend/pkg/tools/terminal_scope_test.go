package tools

import (
	"context"
	"sync"
	"testing"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/scope"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// execCountingDocker counts how many exec processes the terminal creates, so
// tests can prove a blocked command never reaches the container.
type execCountingDocker struct {
	*contextAwareMockDockerClient
	mu    sync.Mutex
	execs int
}

func (d *execCountingDocker) ContainerExecCreate(ctx context.Context, name string, opts client.ExecCreateOptions) (client.ExecCreateResult, error) {
	d.mu.Lock()
	d.execs++
	d.mu.Unlock()
	return d.contextAwareMockDockerClient.ContainerExecCreate(ctx, name, opts)
}

func (d *execCountingDocker) execCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.execs
}

type recordedTermMsg struct {
	typ database.TermlogType
	msg string
}

type recordingTermLog struct {
	mu   sync.Mutex
	msgs []recordedTermMsg
}

func (r *recordingTermLog) PutMsg(_ context.Context, typ database.TermlogType, msg string,
	_ int64, _, _ *int64) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, recordedTermMsg{typ: typ, msg: msg})
	return 1, nil
}

func newScopedTerminal(t *testing.T, targets ...string) (*terminal, *execCountingDocker, *recordingTermLog) {
	t.Helper()

	policy, err := scope.Parse(targets)
	require.NoError(t, err)

	docker := &execCountingDocker{contextAwareMockDockerClient: &contextAwareMockDockerClient{
		isRunning:      true,
		execCreateResp: client.ExecCreateResult{ID: "exec-scope-test"},
		attachOutput:   []byte("scan finished"),
		inspectResp:    client.ExecInspectResult{ExitCode: 0},
	}}
	tlp := &recordingTermLog{}

	term := NewTerminalTool(1, nil, nil, 1, "test-container", "", docker, tlp, time.Minute, WithScope(policy))
	return term.(*terminal), docker, tlp
}

func TestExecCommand_ScopeBlocksOutOfScopeTarget(t *testing.T) {
	term, docker, tlp := newScopedTerminal(t, "10.0.0.0/24")

	out, err := term.ExecCommand(t.Context(), "/work", "nmap -sV 203.0.113.9", false, 5*time.Second)

	require.Error(t, err)
	assert.Empty(t, out)
	assert.Contains(t, err.Error(), "203.0.113.9")
	assert.Contains(t, err.Error(), "authorized engagement scope")
	assert.Zero(t, docker.execCount(), "a blocked command must never reach the container")

	require.Len(t, tlp.msgs, 1, "the blocked attempt must be recorded in the terminal log")
	assert.Equal(t, database.TermlogTypeStderr, tlp.msgs[0].typ)
	assert.Contains(t, tlp.msgs[0].msg, "nmap -sV 203.0.113.9")
	assert.Contains(t, tlp.msgs[0].msg, "BLOCKED")
}

func TestExecCommand_ScopeAllowsInScopeTarget(t *testing.T) {
	term, docker, _ := newScopedTerminal(t, "10.0.0.0/24")

	out, err := term.ExecCommand(t.Context(), "/work", "nmap -sV 10.0.0.15 -oN scan.txt", false, 5*time.Second)

	require.NoError(t, err)
	assert.Contains(t, out, "scan finished")
	assert.Equal(t, 1, docker.execCount())
}

func TestExecCommand_NoScopeIsUnrestricted(t *testing.T) {
	term, docker, _ := newScopedTerminal(t) // no targets: guardrail disabled

	_, err := term.ExecCommand(t.Context(), "/work", "nmap -sV 203.0.113.9", false, 5*time.Second)

	require.NoError(t, err)
	assert.Equal(t, 1, docker.execCount())
}

func TestTerminalHandle_ScopeViolationIsReportedToAgentNotFatal(t *testing.T) {
	term, docker, _ := newScopedTerminal(t, "app.example.com")

	out, err := term.Handle(t.Context(), TerminalToolName,
		[]byte(`{"input":"curl https://other.example.net/admin","cwd":"/work","timeout":5,"message":"probe"}`))

	// The agent must get an explanation it can act on, not a hard tool failure.
	require.NoError(t, err)
	assert.Contains(t, out, "other.example.net")
	assert.Contains(t, out, "outside the authorized engagement scope")
	assert.Zero(t, docker.execCount())
}
