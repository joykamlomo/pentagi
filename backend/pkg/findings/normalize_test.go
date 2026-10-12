package findings

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func valid() Input {
	return Input{
		Title:       "SQL injection in login form",
		Asset:       "https://app.example.com/login",
		Severity:    "high",
		Status:      "confirmed",
		Description: "The username parameter is concatenated into a SQL query.",
		Impact:      "An attacker can read or modify the user database.",
		Evidence:    "curl -s 'https://app.example.com/login' -d \"u=' OR 1=1--&p=x\" -> HTTP 302 /admin",
		Remediation: "Use parameterized queries.",
	}
}

const rce = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func TestNormalize_Valid(t *testing.T) {
	r, err := Normalize(valid(), Options{})
	require.NoError(t, err)

	assert.Equal(t, SeverityHigh, r.Severity)
	assert.Equal(t, StatusConfirmed, r.Status)
	assert.Equal(t, "SQL injection in login form", r.Title)
	assert.Empty(t, r.CVSSVector)
	assert.Empty(t, r.References)
	assert.Empty(t, r.Notes)
}

func TestNormalize_RejectsWithAllProblemsListed(t *testing.T) {
	in := valid()
	in.Title, in.Remediation, in.Severity = "  ", "", "catastrophic"

	_, err := Normalize(in, Options{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "title")
	assert.Contains(t, err.Error(), "remediation")
	assert.Contains(t, err.Error(), `severity "catastrophic" is invalid`)
}

func TestNormalize_ConfirmedNeedsEvidence(t *testing.T) {
	in := valid()
	in.Evidence = "   "

	for _, opt := range []Options{{}, {Reviewer: true}} {
		_, err := Normalize(in, opt)
		require.Error(t, err, "reviewer=%v", opt.Reviewer)
		assert.Contains(t, err.Error(), "requires evidence")
	}

	in.Status = "potential"
	r, err := Normalize(in, Options{})
	require.NoError(t, err, "an unverified finding may omit evidence")
	assert.Equal(t, StatusPotential, r.Status)
}

func TestNormalize_StatusDefaultsToPotential(t *testing.T) {
	in := valid()
	in.Status = ""
	r, err := Normalize(in, Options{})
	require.NoError(t, err)
	assert.Equal(t, StatusPotential, r.Status)
}

func TestNormalize_FalsePositiveIsReviewerOnly(t *testing.T) {
	in := valid()
	in.Status = "false_positive"

	_, err := Normalize(in, Options{})
	require.Error(t, err, "an agent must not be able to discard findings")
	assert.Contains(t, err.Error(), "only be set by a reviewer")

	r, err := Normalize(in, Options{Reviewer: true})
	require.NoError(t, err)
	assert.Equal(t, StatusFalsePositive, r.Status)
}

func TestNormalize_SeverityAliasesAndCase(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": SeverityCritical, " High ": SeverityHigh, "Medium": SeverityMedium,
		"low": SeverityLow, "informational": SeverityInfo, "INFO": SeverityInfo,
	} {
		i := valid()
		i.Severity = in
		r, err := Normalize(i, Options{})
		require.NoError(t, err, in)
		assert.Equal(t, want, r.Severity, in)
	}
}

func TestNormalize_SeverityRequiredUnlessDerivable(t *testing.T) {
	in := valid()
	in.Severity = ""

	_, err := Normalize(in, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "severity is required")

	in.CVSSVector = rce
	r, err := Normalize(in, Options{})
	require.NoError(t, err, "a CVSS vector can stand in for an omitted severity")
	assert.Equal(t, SeverityCritical, r.Severity)
	assert.Empty(t, r.Notes, "nothing was overridden")
}

func TestNormalize_AgentSeverityFollowsCVSS(t *testing.T) {
	in := valid()
	in.Severity = "low" // an under-rated unauthenticated RCE
	in.CVSSVector = rce

	r, err := Normalize(in, Options{})
	require.NoError(t, err)

	assert.Equal(t, SeverityCritical, r.Severity, "the computed score is authoritative for agents")
	assert.Equal(t, 9.8, r.CVSSScore)
	assert.Equal(t, rce, r.CVSSVector)
	require.Len(t, r.Notes, 1)
	assert.Contains(t, r.Notes[0], "severity set to critical")
}

func TestNormalize_ReviewerSeverityWins(t *testing.T) {
	in := valid()
	in.Severity = "medium" // business judgment: compensating controls exist
	in.CVSSVector = rce

	r, err := Normalize(in, Options{Reviewer: true})
	require.NoError(t, err)

	assert.Equal(t, SeverityMedium, r.Severity)
	assert.Equal(t, 9.8, r.CVSSScore, "the score is still computed, never taken on trust")
	assert.Empty(t, r.Notes)
}

func TestNormalize_AgreeingSeverityAddsNoNote(t *testing.T) {
	in := valid()
	in.Severity = "critical"
	in.CVSSVector = rce

	r, err := Normalize(in, Options{})
	require.NoError(t, err)
	assert.Empty(t, r.Notes)
}

func TestNormalize_InvalidCVSSIsRejectedNotIgnored(t *testing.T) {
	in := valid()
	in.CVSSVector = "CVSS:3.1/AV:N/AC:L"

	for _, opt := range []Options{{}, {Reviewer: true}} {
		_, err := Normalize(in, opt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid cvss_vector")
	}
}

func TestNormalize_StripsCharactersPostgresRejects(t *testing.T) {
	in := valid()
	in.Evidence = "nmap output\x00 with NUL and bad bytes \xff\xfe end"
	in.Description = "ok\x00"

	r, err := Normalize(in, Options{})
	require.NoError(t, err)

	assert.NotContains(t, r.Evidence, "\x00")
	assert.True(t, strings.ToValidUTF8(r.Evidence, "") == r.Evidence, "evidence must be valid UTF-8")
	assert.Equal(t, "ok", r.Description)
}

func TestNormalize_TruncatesOversizedTextWithoutSplittingRunes(t *testing.T) {
	in := valid()
	in.Evidence = strings.Repeat("é", MaxEvidenceLen) // 2 bytes per rune

	r, err := Normalize(in, Options{})
	require.NoError(t, err)

	assert.LessOrEqual(t, len(r.Evidence), MaxEvidenceLen)
	assert.True(t, strings.HasSuffix(r.Evidence, TruncatedMarker))
	assert.True(t, strings.ToValidUTF8(r.Evidence, "") == r.Evidence, "truncation must not split a multi-byte rune")
	require.NotEmpty(t, r.Notes)
	assert.Contains(t, r.Notes[0], "evidence truncated")
}

func TestNormalize_RejectsOverlongTitleAndAsset(t *testing.T) {
	in := valid()
	in.Title = strings.Repeat("a", MaxTitleLen+1)
	in.Asset = strings.Repeat("b", MaxAssetLen+1)

	_, err := Normalize(in, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "title is too long")
	assert.Contains(t, err.Error(), "asset is too long")
}

func TestNormalize_References(t *testing.T) {
	in := valid()
	in.References = []string{"CVE-2021-44228", " cve-2021-44228 ", "", "CWE-89", "https://owasp.org/Top10/A03_2021-Injection/"}

	r, err := Normalize(in, Options{})
	require.NoError(t, err)

	assert.Equal(t, []string{"CVE-2021-44228", "CWE-89", "https://owasp.org/Top10/A03_2021-Injection/"}, r.References,
		"duplicates (case-insensitive) and blanks are dropped, order preserved")
}

func TestNormalize_CapsReferencesAndLength(t *testing.T) {
	in := valid()
	for i := range MaxRefs + 5 {
		in.References = append(in.References, "CVE-2020-"+strings.Repeat("1", i+1))
	}
	in.References = append(in.References, "https://example.org/"+strings.Repeat("é", MaxRefLen))

	r, err := Normalize(in, Options{})
	require.NoError(t, err)

	assert.Len(t, r.References, MaxRefs)
	require.NotEmpty(t, r.Notes)
	assert.Contains(t, r.Notes[len(r.Notes)-1], "references were kept")

	long := valid()
	long.References = []string{"https://example.org/" + strings.Repeat("é", MaxRefLen)}
	r, err = Normalize(long, Options{})
	require.NoError(t, err)
	require.Len(t, r.References, 1)
	assert.LessOrEqual(t, len(r.References[0]), MaxRefLen)
	assert.True(t, strings.ToValidUTF8(r.References[0], "") == r.References[0], "reference truncation must not split a rune")
}
