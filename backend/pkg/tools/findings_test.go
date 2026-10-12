package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"pentagi/pkg/database"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAction() ReportFindingAction {
	return ReportFindingAction{
		Title:       "SQL injection in login form",
		Asset:       "https://app.example.com/login",
		Severity:    "high",
		Status:      "confirmed",
		Description: "The username parameter is concatenated into a SQL query.",
		Impact:      "An attacker can read or modify the user database.",
		Evidence:    "curl -s 'https://app.example.com/login' -d \"u=' OR 1=1--&p=x\" -> HTTP 302 /admin",
		Remediation: "Use parameterized queries.",
		Message:     "found sqli",
	}
}

// fakeFindingsDB implements only what the findings tool calls; any other
// Querier method panics on the nil embedded interface, which would flag an
// unexpected dependency.
type fakeFindingsDB struct {
	database.Querier
	got      database.UpsertFindingParams
	calls    int
	noRows   bool
	insertID int64
}

func (d *fakeFindingsDB) UpsertFinding(_ context.Context, p database.UpsertFindingParams) (database.Finding, error) {
	d.calls++
	d.got = p
	if d.noRows {
		return database.Finding{}, sql.ErrNoRows
	}
	return database.Finding{ID: d.insertID}, nil
}

func handleFinding(t *testing.T, db *fakeFindingsDB, a ReportFindingAction) (string, error) {
	t.Helper()
	args, err := json.Marshal(a)
	require.NoError(t, err)
	taskID, subtaskID := int64(7), int64(9)
	return NewFindingsTool(42, &taskID, &subtaskID, db).Handle(t.Context(), ReportFindingToolName, args)
}

func TestFindingsTool_RecordsFindingWithFlowTaskAndScore(t *testing.T) {
	db := &fakeFindingsDB{insertID: 5}
	a := validAction()
	a.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	out, err := handleFinding(t, db, a)

	require.NoError(t, err)
	assert.Contains(t, out, "Finding #5 recorded")
	assert.Contains(t, out, "[CRITICAL]")
	assert.Contains(t, out, "CVSS 9.8")

	assert.Equal(t, int64(42), db.got.FlowID)
	assert.Equal(t, sql.NullInt64{Int64: 7, Valid: true}, db.got.TaskID)
	assert.Equal(t, sql.NullInt64{Int64: 9, Valid: true}, db.got.SubtaskID)
	assert.Equal(t, database.FindingSeverityCritical, db.got.Severity)
	assert.Equal(t, "9.8", db.got.CvssScore)
	assert.Equal(t, "https://app.example.com/login", db.got.Asset, "real hosts must be stored, never anonymized")
}

func TestFindingsTool_ValidationFailureIsFeedbackNotAToolError(t *testing.T) {
	db := &fakeFindingsDB{}
	a := validAction()
	a.Evidence = ""

	out, err := handleFinding(t, db, a)

	require.NoError(t, err, "the agent must be able to read the problem and retry")
	assert.Contains(t, out, "Finding NOT recorded")
	assert.Contains(t, out, "requires evidence")
	assert.Zero(t, db.calls, "an invalid finding must not touch the database")
}

func TestFindingsTool_ReviewedFindingIsLeftUnchanged(t *testing.T) {
	db := &fakeFindingsDB{noRows: true}

	out, err := handleFinding(t, db, validAction())

	require.NoError(t, err)
	assert.Contains(t, out, "already reviewed by a person")
	assert.Contains(t, out, "left unchanged")
}

func TestFindingsTool_UnknownToolAndBadJSON(t *testing.T) {
	tool := NewFindingsTool(1, nil, nil, &fakeFindingsDB{})

	_, err := tool.Handle(t.Context(), "nope", []byte(`{}`))
	require.Error(t, err)

	_, err = tool.Handle(t.Context(), ReportFindingToolName, []byte(`{not json`))
	require.Error(t, err)
}

func TestFindingsTool_NilTaskIDsStoredAsNull(t *testing.T) {
	db := &fakeFindingsDB{insertID: 1}
	args, err := json.Marshal(validAction())
	require.NoError(t, err)

	_, err = NewFindingsTool(3, nil, nil, db).Handle(t.Context(), ReportFindingToolName, args)

	require.NoError(t, err)
	assert.False(t, db.got.TaskID.Valid)
	assert.False(t, db.got.SubtaskID.Valid)
}

func TestFindingsTool_Availability(t *testing.T) {
	assert.True(t, NewFindingsTool(1, nil, nil, &fakeFindingsDB{}).IsAvailable())
	assert.False(t, NewFindingsTool(1, nil, nil, nil).IsAvailable())
}
