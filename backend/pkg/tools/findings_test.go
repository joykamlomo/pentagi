package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
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

func TestNormalizeFinding_Valid(t *testing.T) {
	f, err := normalizeFinding(validAction())
	require.NoError(t, err)

	assert.Equal(t, database.FindingSeverityHigh, f.severity)
	assert.Equal(t, database.FindingStatusConfirmed, f.status)
	assert.Equal(t, "SQL injection in login form", f.title)
	assert.Empty(t, f.cvssVector)
	assert.JSONEq(t, `[]`, string(f.refs), "no references must serialize as an empty array, not null")
}

func TestNormalizeFinding_RejectsWithAllProblemsListed(t *testing.T) {
	a := validAction()
	a.Title, a.Remediation, a.Severity = "  ", "", "catastrophic"

	_, err := normalizeFinding(a)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "title")
	assert.Contains(t, err.Error(), "remediation")
	assert.Contains(t, err.Error(), `severity "catastrophic" is invalid`)
}

func TestNormalizeFinding_ConfirmedNeedsEvidence(t *testing.T) {
	a := validAction()
	a.Evidence = "   "

	_, err := normalizeFinding(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires evidence")

	a.Status = "potential"
	f, err := normalizeFinding(a)
	require.NoError(t, err, "an unverified finding may omit evidence")
	assert.Equal(t, database.FindingStatusPotential, f.status)
}

func TestNormalizeFinding_StatusDefaultsToPotential(t *testing.T) {
	a := validAction()
	a.Status = ""
	f, err := normalizeFinding(a)
	require.NoError(t, err)
	assert.Equal(t, database.FindingStatusPotential, f.status)
}

func TestNormalizeFinding_SeverityAliasesAndCase(t *testing.T) {
	for in, want := range map[string]database.FindingSeverity{
		"CRITICAL": database.FindingSeverityCritical, " High ": database.FindingSeverityHigh,
		"Medium": database.FindingSeverityMedium, "low": database.FindingSeverityLow,
		"informational": database.FindingSeverityInfo, "INFO": database.FindingSeverityInfo,
	} {
		a := validAction()
		a.Severity = String(in)
		f, err := normalizeFinding(a)
		require.NoError(t, err, in)
		assert.Equal(t, want, f.severity, in)
	}
}

func TestNormalizeFinding_CVSSOverridesSeverity(t *testing.T) {
	a := validAction()
	a.Severity = "low" // the agent under-rates an unauthenticated RCE
	a.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	f, err := normalizeFinding(a)
	require.NoError(t, err)

	assert.Equal(t, database.FindingSeverityCritical, f.severity, "the computed score is authoritative")
	assert.Equal(t, 9.8, f.cvssScore)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", f.cvssVector)
	require.Len(t, f.notes, 1)
	assert.Contains(t, f.notes[0], "severity set to critical")
}

func TestNormalizeFinding_CVSSAgreeingSeverityAddsNoNote(t *testing.T) {
	a := validAction()
	a.Severity = "critical"
	a.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	f, err := normalizeFinding(a)
	require.NoError(t, err)
	assert.Empty(t, f.notes)
}

func TestNormalizeFinding_InvalidCVSSIsRejectedNotIgnored(t *testing.T) {
	a := validAction()
	a.CVSSVector = "CVSS:3.1/AV:N/AC:L"

	_, err := normalizeFinding(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cvss_vector")
}

func TestNormalizeFinding_StripsCharactersPostgresRejects(t *testing.T) {
	a := validAction()
	a.Evidence = "nmap output\x00 with NUL and bad bytes \xff\xfe end"
	a.Description = "ok\x00"

	f, err := normalizeFinding(a)
	require.NoError(t, err)

	assert.NotContains(t, f.evidence, "\x00")
	assert.True(t, strings.ToValidUTF8(f.evidence, "") == f.evidence, "evidence must be valid UTF-8")
	assert.Equal(t, "ok", f.description)
}

func TestNormalizeFinding_TruncatesOversizedTextWithoutSplittingRunes(t *testing.T) {
	a := validAction()
	a.Evidence = strings.Repeat("é", maxFindingEvidence) // 2 bytes per rune

	f, err := normalizeFinding(a)
	require.NoError(t, err)

	assert.LessOrEqual(t, len(f.evidence), maxFindingEvidence)
	assert.True(t, strings.HasSuffix(f.evidence, truncatedMarkerText))
	assert.True(t, strings.ToValidUTF8(f.evidence, "") == f.evidence, "truncation must not split a multi-byte rune")
	require.NotEmpty(t, f.notes)
	assert.Contains(t, f.notes[0], "evidence truncated")
}

func TestNormalizeFinding_RejectsOverlongTitleAndAsset(t *testing.T) {
	a := validAction()
	a.Title = strings.Repeat("a", maxFindingTitleLen+1)
	a.Asset = strings.Repeat("b", maxFindingAssetLen+1)

	_, err := normalizeFinding(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "title is too long")
	assert.Contains(t, err.Error(), "asset is too long")
}

func TestNormalizeFinding_References(t *testing.T) {
	a := validAction()
	a.References = Strings{"CVE-2021-44228", " cve-2021-44228 ", "", "CWE-89", "https://owasp.org/Top10/A03_2021-Injection/"}

	f, err := normalizeFinding(a)
	require.NoError(t, err)

	var refs []string
	require.NoError(t, json.Unmarshal(f.refs, &refs))
	assert.Equal(t, []string{"CVE-2021-44228", "CWE-89", "https://owasp.org/Top10/A03_2021-Injection/"}, refs,
		"duplicates (case-insensitive) and blanks are dropped, order preserved")
}

func TestNormalizeFinding_CapsReferences(t *testing.T) {
	a := validAction()
	for i := range maxFindingRefs + 5 {
		a.References = append(a.References, "CVE-2020-"+strings.Repeat("1", i+1))
	}

	f, err := normalizeFinding(a)
	require.NoError(t, err)

	var refs []string
	require.NoError(t, json.Unmarshal(f.refs, &refs))
	assert.Len(t, refs, maxFindingRefs)
	require.NotEmpty(t, f.notes)
	assert.Contains(t, f.notes[len(f.notes)-1], "references were kept")
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
