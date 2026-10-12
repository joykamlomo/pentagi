package report

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

func finding(id int64, title, sev, status string, score float64, reviewed bool) Finding {
	f := Finding{
		ID: id, Title: title, Asset: "https://app.example.com/" + title, Severity: sev, Status: status,
		CVSSScore: score, Description: "desc " + title, Impact: "impact", Remediation: "fix it",
		Evidence: "curl -i https://app.example.com/", Reviewed: reviewed,
	}
	if score > 0 {
		f.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	}
	return f
}

func sample() []Finding {
	return []Finding{
		finding(1, "low-issue", "low", "confirmed", 3.1, true),
		finding(2, "crit-b", "critical", "confirmed", 9.1, true),
		finding(3, "noise", "high", "false_positive", 8.0, true),
		finding(4, "crit-a", "critical", "confirmed", 9.8, true),
		finding(5, "med-potential", "medium", "potential", 0, true),
		finding(6, "info-note", "info", "confirmed", 0, true),
	}
}

func TestBuild_OrdersNumbersAndCounts(t *testing.T) {
	d := Build(Meta{GeneratedAt: testTime}, sample())

	var titles, numbers []string
	for _, e := range d.Findings {
		titles = append(titles, e.Title)
		numbers = append(numbers, e.Number)
	}
	assert.Equal(t, []string{"crit-a", "crit-b", "med-potential", "low-issue", "info-note"}, titles,
		"severity first, then CVSS score; false positives dropped")
	assert.Equal(t, []string{"F-01", "F-02", "F-03", "F-04", "F-05"}, numbers)

	assert.Equal(t, map[string]int{"critical": 2, "medium": 1, "low": 1, "info": 1}, d.Counts)
	assert.Equal(t, 4, d.Confirmed)
	assert.Equal(t, 1, d.Potential)
	assert.Equal(t, "Critical", d.Overall)
	assert.False(t, d.Draft)
}

func TestBuild_NormalizesUnknownValues(t *testing.T) {
	d := Build(Meta{}, []Finding{
		{ID: 1, Title: "a", Severity: " HIGH ", Status: "CONFIRMED"},
		{ID: 2, Title: "b", Severity: "catastrophic", Status: "whatever"},
	})

	require.Len(t, d.Findings, 2)
	assert.Equal(t, "high", d.Findings[0].Severity)
	assert.Equal(t, "confirmed", d.Findings[0].Status)
	assert.Equal(t, "info", d.Findings[1].Severity, "an unknown severity must not be silently promoted")
	assert.Equal(t, "potential", d.Findings[1].Status, "an unknown status must not be reported as confirmed")
}

func TestBuild_StableForEqualScores(t *testing.T) {
	in := []Finding{
		finding(9, "z", "high", "confirmed", 7.5, true),
		finding(3, "a", "high", "confirmed", 7.5, true),
	}
	d := Build(Meta{}, in)
	assert.Equal(t, int64(3), d.Findings[0].ID, "ties break on id so numbering is reproducible")
}

func TestOverall(t *testing.T) {
	assert.Equal(t, "None", Build(Meta{}, nil).Overall)
	assert.Equal(t, "None", Build(Meta{}, []Finding{finding(1, "x", "high", "false_positive", 8, true)}).Overall)
	assert.Equal(t, "Low", Build(Meta{}, []Finding{finding(1, "x", "low", "confirmed", 3, true)}).Overall)
	assert.Equal(t, "Informational", Build(Meta{}, []Finding{finding(1, "x", "info", "confirmed", 0, true)}).Overall)
}

func TestSummary(t *testing.T) {
	assert.Equal(t, "No security findings were recorded during this assessment.", Build(Meta{}, nil).Summary())

	one := Build(Meta{}, []Finding{finding(1, "RCE in upload", "critical", "confirmed", 9.8, true)}).Summary()
	assert.Equal(t,
		"This assessment identified 1 finding: 1 critical. The overall risk rating is Critical, set by the most severe finding. "+
			"1 was confirmed with evidence. The most significant: RCE in upload (F-01, critical).", one)

	mixed := Build(Meta{}, sample()).Summary()
	assert.Contains(t, mixed, "identified 5 findings: 2 critical, 1 medium, 1 low, 1 informational")
	assert.Contains(t, mixed, "4 were confirmed with evidence; 1 issue is indicated but could not be verified")
	assert.Contains(t, mixed, "crit-a (F-01, critical); crit-b (F-02, critical); med-potential (F-03, medium)")
	assert.NotContains(t, mixed, "info-note", "informational items are not 'most significant'")
}

func TestReviewNotice(t *testing.T) {
	assert.Equal(t, "", Build(Meta{}, nil).ReviewNotice())

	in := []Finding{finding(1, "a", "high", "confirmed", 7, true), finding(2, "b", "low", "confirmed", 3, false)}
	d := Build(Meta{}, in)
	assert.True(t, d.Draft)
	assert.Contains(t, d.ReviewNotice(), "DRAFT: 1 of 2 findings have been reviewed")

	in[1].Reviewed = true
	d = Build(Meta{}, in)
	assert.False(t, d.Draft)
	assert.Equal(t, "All findings in this report were reviewed by a consultant.", d.ReviewNotice())
}

func TestFalsePositivesDoNotAffectDraftStatus(t *testing.T) {
	d := Build(Meta{}, []Finding{
		finding(1, "a", "high", "confirmed", 7, true),
		finding(2, "ignored", "low", "false_positive", 0, false), // never reviewed, but not in the report
	})
	assert.False(t, d.Draft)
}

// hostile content must be inert in every place a user-controlled value appears.
const (
	scriptPayload = `<script>alert(1)</script>`
	imgPayload    = `"><img src=x onerror=alert(1)>`
)

func hostileDoc() Document {
	f := Finding{
		ID: 1, Severity: "high", Status: "confirmed", CVSSScore: 8.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" + scriptPayload,
		Title:       "Title " + scriptPayload,
		Asset:       "host " + imgPayload,
		Description: "Desc " + scriptPayload + "\nsecond line",
		Impact:      "Impact " + imgPayload,
		Evidence:    "HTTP/1.1 200 OK\n\n" + scriptPayload + imgPayload,
		Remediation: "Fix " + scriptPayload,
		References:  []string{"javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "CVE-2021-44228", "https://example.org/a?b=1&c=<x>"},
		Reviewed:    true,
	}
	return Build(Meta{
		Title:   "Engagement " + scriptPayload,
		Client:  "Client " + imgPayload,
		Company: "Company " + scriptPayload,
		Scope:   []string{"10.0.0.0/24", "evil" + scriptPayload},
	}, []Finding{f})
}

func TestHTML_EscapesEveryUserControlledField(t *testing.T) {
	out, err := hostileDoc().HTML()
	require.NoError(t, err)

	assert.NotContains(t, out, "<script", "no script element may ever appear in the report")
	assert.NotContains(t, strings.ToLower(out), "<img", "injected markup must be escaped")
	assert.NotContains(t, out, "onerror=alert(1)>", "raw event-handler markup must not survive unescaped")
	assert.Contains(t, out, "&lt;script&gt;alert(1)&lt;/script&gt;", "hostile text is shown, escaped")

	// the only <script-like text in the output is escaped text; and no script is allowed by policy
	assert.Contains(t, out, `Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"`)
}

func TestHTML_OnlyHTTPAndKnownIDsBecomeLinks(t *testing.T) {
	out, err := hostileDoc().HTML()
	require.NoError(t, err)

	assert.NotContains(t, out, `href="javascript:`)
	assert.NotContains(t, out, `href="data:`)
	assert.NotContains(t, strings.ToLower(out), "href=\"#zgotmplz")
	assert.Contains(t, out, `href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"`)
	assert.Contains(t, out, `href="https://example.org/a?b=1&amp;c=%3cx%3e"`)
	assert.Contains(t, out, `rel="noopener noreferrer"`)
	// rejected references are still shown to the reader as plain text
	assert.Contains(t, out, "javascript:alert(1)")
}

func TestHTML_Structure(t *testing.T) {
	out, err := Build(Meta{
		Title: "Acme external test", Company: "Sec Co", Client: "Acme", Scope: []string{"10.0.0.0/24"},
		TestStart: testTime, TestEnd: testTime.Add(48 * time.Hour), GeneratedAt: testTime,
	}, sample()).HTML()
	require.NoError(t, err)

	for _, want := range []string{
		"<h1>Penetration Test Report</h1>", "Acme external test", "Testing period:</strong> 2026-10-12 to 2026-10-14",
		"Report date:</strong> 2026-10-12", "Executive summary", "Scope and methodology", "<code>10.0.0.0/24</code>",
		"Findings overview", "Detailed findings", `id="F-01"`, "Disclaimer",
		"All findings in this report were reviewed by a consultant.",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, `class="watermark"`, "a fully reviewed report carries no draft watermark")
	assert.NotContains(t, out, "noise", "false positives never reach the client")
}

func TestHTML_DraftWatermark(t *testing.T) {
	in := sample()
	in[0].Reviewed = false
	out, err := Build(Meta{}, in).HTML()
	require.NoError(t, err)

	assert.Contains(t, out, `class="watermark"`)
	assert.Contains(t, out, "DRAFT: ")
}

func TestHTML_Empty(t *testing.T) {
	out, err := Build(Meta{Title: "t"}, nil).HTML()
	require.NoError(t, err)

	assert.Contains(t, out, "No security findings were recorded")
	assert.Contains(t, out, "No findings.")
	assert.NotContains(t, out, "Detailed findings")
}

func TestMarkdown_Structure(t *testing.T) {
	md := Build(Meta{
		Title: "Acme", Company: "Sec Co", Client: "Acme Ltd", Scope: []string{"10.0.0.0/24"}, GeneratedAt: testTime,
	}, sample()).Markdown()

	for _, want := range []string{
		"# Penetration Test Report", "**Client:** Acme Ltd", "**Prepared by:** Sec Co", "**Report date:** 2026-10-12",
		"## Executive summary", "| Critical | 2 |", "| High | 0 |", "## Scope and methodology", "- `10.0.0.0/24`",
		"## Findings overview", "| F-01 | Critical | crit-a |", "## Detailed findings", "### F-01: crit-a",
		"- **CVSS v3.1:** 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)", "**Remediation**", "## Disclaimer",
	} {
		assert.Contains(t, md, want)
	}
	assert.NotContains(t, md, "noise")
	assert.Contains(t, md, "Potential (not verified)")
}

// outsideFences returns the document with fenced code blocks removed. Inside a
// fence, CommonMark treats content literally, so evidence is kept verbatim there.
func outsideFences(md string) string {
	var keep []string
	inFence, fence := false, ""
	for _, l := range strings.Split(md, "\n") {
		trimmed := strings.TrimLeft(l, " ")
		switch {
		case !inFence && strings.HasPrefix(trimmed, "```"):
			inFence = true
			fence = trimmed[:len(trimmed)-len(strings.TrimLeft(trimmed, "`"))]
		case inFence && strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, "`") == "":
			inFence = false
		case !inFence:
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func TestMarkdown_NeutralizesRawHTML(t *testing.T) {
	md := hostileDoc().Markdown()
	prose := outsideFences(md)

	assert.NotContains(t, prose, "<script", "raw HTML in prose, tables, headings and code spans must be neutralized")
	assert.NotContains(t, prose, "<img")
	assert.Contains(t, prose, "&lt;script>alert(1)")

	// evidence is quoted verbatim inside its fence
	assert.Contains(t, md, "```\nHTTP/1.1 200 OK\n\n<script>alert(1)</script>")
}

func TestMarkdown_EvidenceCannotBreakOutOfItsFence(t *testing.T) {
	f := finding(1, "x", "high", "confirmed", 7, true)
	f.Evidence = "before\n```\n# INJECTED HEADING\n```\n````\nmore"

	md := Build(Meta{}, []Finding{f}).Markdown()

	// find the evidence fence: it must be longer than the longest backtick run inside the evidence (4)
	lines := strings.Split(md, "\n")
	open, closeAt := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "`````") && open == -1 {
			open = i
		} else if strings.HasPrefix(l, "`````") && open != -1 {
			closeAt = i
			break
		}
	}
	require.NotEqual(t, -1, open, "expected a 5-backtick fence around evidence:\n%s", md)
	require.NotEqual(t, -1, closeAt)

	inside := strings.Join(lines[open+1:closeAt], "\n")
	assert.Contains(t, inside, "# INJECTED HEADING", "injected text stays inside the code block")

	// and nothing outside the fence became a heading
	outside := strings.Join(append(append([]string{}, lines[:open]...), lines[closeAt+1:]...), "\n")
	assert.NotContains(t, outside, "# INJECTED HEADING")
}

func TestMarkdown_AgentProseCannotOpenAFence(t *testing.T) {
	f := finding(1, "x", "high", "confirmed", 7, true)
	f.Description = "Intro\n```\nstill description\n  ~~~\nmore"

	md := Build(Meta{}, []Finding{f}).Markdown()
	section := md[strings.Index(md, "**Description**"):strings.Index(md, "**Impact**")]

	for _, l := range strings.Split(section, "\n") {
		assert.False(t, strings.HasPrefix(strings.TrimLeft(l, " \t"), "```"), "unescaped fence in prose: %q", l)
		assert.False(t, strings.HasPrefix(strings.TrimLeft(l, " \t"), "~~~"), "unescaped fence in prose: %q", l)
	}
}

func TestMarkdown_TableCellsStayOnOneRow(t *testing.T) {
	f := finding(1, "has | pipe\nand newline", "high", "confirmed", 7, true)
	f.Asset = "a|b\nc"

	md := Build(Meta{}, []Finding{f}).Markdown()

	var row string
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "| F-01 |") {
			row = l
		}
	}
	require.NotEmpty(t, row, md)
	unescaped := regexp.MustCompile(`[^\\]\|`).FindAllString(row, -1)
	assert.Len(t, unescaped, 6, "exactly the 6 column separators (plus none from content) must be unescaped: %q", row)
	assert.Contains(t, row, `has \| pipe and newline`)
}

func TestMarkdown_Empty(t *testing.T) {
	md := Build(Meta{}, nil).Markdown()
	assert.Contains(t, md, "No security findings were recorded")
	assert.Contains(t, md, "No findings.")
	assert.NotContains(t, md, "## Detailed findings")
}

func TestRendering_IsDeterministic(t *testing.T) {
	a := Build(Meta{GeneratedAt: testTime, Scope: []string{"a", "b"}}, sample())
	b := Build(Meta{GeneratedAt: testTime, Scope: []string{"a", "b"}}, sample())

	assert.Equal(t, a.Markdown(), b.Markdown())
	ha, err := a.HTML()
	require.NoError(t, err)
	hb, err := b.HTML()
	require.NoError(t, err)
	assert.Equal(t, ha, hb)
}
