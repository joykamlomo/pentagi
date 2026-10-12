package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"pentagi/pkg/brand"
	"pentagi/pkg/findings"
	"pentagi/pkg/report"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/models"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

const (
	maxFindingRequestBytes = 512 * 1024
	maxClientNameLen       = 200
)

var findingSeverityRank = map[string]int{
	findings.SeverityCritical: 0,
	findings.SeverityHigh:     1,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      3,
	findings.SeverityInfo:     4,
}

type findingsList struct {
	Findings []models.Finding `json:"findings"`
	Total    uint64           `json:"total"`
}

// updateFindingRequest carries a reviewer's edits. Omitted fields keep their
// current value.
type updateFindingRequest struct {
	Title       *string   `json:"title"`
	Asset       *string   `json:"asset"`
	Severity    *string   `json:"severity"`
	Status      *string   `json:"status"`
	CVSSVector  *string   `json:"cvss_vector"`
	Description *string   `json:"description"`
	Impact      *string   `json:"impact"`
	Evidence    *string   `json:"evidence"`
	Remediation *string   `json:"remediation"`
	References  *[]string `json:"references"`
}

// FindingService serves findings recorded during a flow and the client report
// built from them.
type FindingService struct {
	db      *gorm.DB
	company string
	scope   []string
}

// NewFindingService creates the service. company is the issuer shown on
// reports (empty falls back to the product name); scope lists the authorized
// targets printed in the report.
func NewFindingService(db *gorm.DB, company string, scope []string) *FindingService {
	if strings.TrimSpace(company) == "" {
		company = brand.Name
	}
	return &FindingService{db: db, company: strings.TrimSpace(company), scope: scope}
}

// GetFlowFindings is a function to return the findings recorded in a flow
// @Summary Retrieve findings list by flow id
// @Tags Findings
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 200 {object} response.successResp{data=findingsList} "findings list received successful"
// @Failure 400 {object} response.errorResp "invalid query request data"
// @Failure 403 {object} response.errorResp "getting findings not permitted"
// @Failure 404 {object} response.errorResp "flow not found"
// @Failure 500 {object} response.errorResp "internal error on getting findings"
// @Router /flows/{flowID}/findings/ [get]
func (s *FindingService) GetFlowFindings(c *gin.Context) {
	flow, ok := s.flowOrAbort(c, false)
	if !ok {
		return
	}

	list, err := s.loadFindings(flow.ID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error loading findings")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, findingsList{Findings: list, Total: uint64(len(list))})
}

// UpdateFlowFinding is a function to edit a finding as a reviewer
// @Summary Review or edit a finding
// @Description Applies a reviewer's edits and marks the finding as reviewed, after which agents no longer overwrite it. Set status to false_positive to exclude it from the report.
// @Tags Findings
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Param findingID path int true "finding id" minimum(0)
// @Param json body updateFindingRequest true "fields to change"
// @Success 200 {object} response.successResp{data=models.Finding} "finding updated successful"
// @Failure 400 {object} response.errorResp "invalid finding data"
// @Failure 403 {object} response.errorResp "updating finding not permitted"
// @Failure 404 {object} response.errorResp "finding not found"
// @Failure 409 {object} response.errorResp "another finding already has this title and asset"
// @Failure 500 {object} response.errorResp "internal error on updating finding"
// @Router /flows/{flowID}/findings/{findingID} [put]
func (s *FindingService) UpdateFlowFinding(c *gin.Context) {
	flow, ok := s.flowOrAbort(c, true)
	if !ok {
		return
	}

	findingID, err := strconv.ParseUint(c.Param("findingID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing finding id")
		response.Error(c, response.ErrFindingsInvalidRequest, err)
		return
	}

	var req updateFindingRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxFindingRequestBytes)
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error binding finding update")
		response.Error(c, response.ErrFindingsInvalidRequest, err)
		return
	}

	var current models.Finding
	if err := s.db.Where("id = ? AND flow_id = ?", findingID, flow.ID).Take(&current).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			response.Error(c, response.ErrFindingsNotFound, err)
			return
		}
		logger.FromContext(c).WithError(err).Errorf("error loading finding")
		response.Error(c, response.ErrInternal, err)
		return
	}
	current.DecodeRefs()

	merged := mergeFindingEdit(current, req)
	res, err := findings.Normalize(merged, findings.Options{Reviewer: true})
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("invalid finding update")
		response.Error(c, response.ErrFindingsInvalidRequest, err)
		return
	}

	refs, err := json.Marshal(res.References)
	if err != nil {
		response.Error(c, response.ErrInternal, err)
		return
	}

	updates := map[string]any{
		"title":       res.Title,
		"asset":       res.Asset,
		"severity":    res.Severity,
		"status":      res.Status,
		"cvss_vector": res.CVSSVector,
		"cvss_score":  res.CVSSScore,
		"description": res.Description,
		"impact":      res.Impact,
		"evidence":    res.Evidence,
		"remediation": res.Remediation,
		"refs":        string(refs),
		"reviewed_at": time.Now().UTC(),
	}
	err = s.db.Model(&models.Finding{}).Where("id = ? AND flow_id = ?", findingID, flow.ID).Updates(updates).Error
	if err != nil {
		if isUniqueViolation(err) {
			response.Error(c, response.ErrFindingsConflict, err)
			return
		}
		logger.FromContext(c).WithError(err).Errorf("error updating finding")
		response.Error(c, response.ErrInternal, err)
		return
	}

	var updated models.Finding
	if err := s.db.Where("id = ? AND flow_id = ?", findingID, flow.ID).Take(&updated).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error reloading finding")
		response.Error(c, response.ErrInternal, err)
		return
	}
	updated.DecodeRefs()

	response.Success(c, http.StatusOK, updated)
}

// GetFlowReport is a function to render the penetration test report of a flow
// @Summary Download the pentest report for a flow
// @Description Renders recorded findings as a client report. The report is marked DRAFT until every included finding has been reviewed.
// @Tags Findings
// @Produce html,plain,json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Param format query string false "html (default), md or json" Enums(html, md, json)
// @Param client query string false "client name to print on the report"
// @Param download query bool false "send as an attachment instead of displaying inline"
// @Success 200 {string} string "report"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "getting report not permitted"
// @Failure 404 {object} response.errorResp "flow not found"
// @Failure 500 {object} response.errorResp "internal error on building report"
// @Router /flows/{flowID}/report [get]
func (s *FindingService) GetFlowReport(c *gin.Context) {
	flow, ok := s.flowOrAbort(c, false)
	if !ok {
		return
	}

	format := strings.ToLower(strings.TrimSpace(c.DefaultQuery("format", "html")))
	if format != "html" && format != "md" && format != "json" {
		response.Error(c, response.ErrFindingsInvalidRequest, fmt.Errorf("unsupported format %q (use html, md or json)", format))
		return
	}

	client := strings.TrimSpace(c.Query("client"))
	if len(client) > maxClientNameLen {
		response.Error(c, response.ErrFindingsInvalidRequest, fmt.Errorf("client name is too long (max %d characters)", maxClientNameLen))
		return
	}

	list, err := s.loadFindings(flow.ID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error loading findings for report")
		response.Error(c, response.ErrInternal, err)
		return
	}

	if format == "json" {
		response.Success(c, http.StatusOK, findingsList{Findings: list, Total: uint64(len(list))})
		return
	}

	doc := report.Build(report.Meta{
		Title:       flow.Title,
		Company:     s.company,
		Client:      client,
		Scope:       s.scope,
		TestStart:   flow.CreatedAt,
		TestEnd:     flow.UpdatedAt,
		GeneratedAt: time.Now(),
	}, toReportFindings(list))

	// Reports contain client vulnerabilities: never cache them, and never let a
	// browser sniff them into something executable.
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")

	attach := c.Query("download") == "true"
	filename := fmt.Sprintf("pentest-report-flow-%d", flow.ID)

	switch format {
	case "md":
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.md"`, filename))
		c.Data(http.StatusOK, "text/markdown; charset=utf-8", []byte(doc.Markdown()))
	default:
		page, err := doc.HTML()
		if err != nil {
			logger.FromContext(c).WithError(err).Errorf("error rendering report")
			response.Error(c, response.ErrInternal, err)
			return
		}
		// Defense in depth: the page is escaped and script-free, and this policy
		// forbids scripts, frames and network access even if that ever regressed.
		c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		if attach {
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.html"`, filename))
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
	}
}

// flowOrAbort resolves the flow for the caller or writes the error response.
func (s *FindingService) flowOrAbort(c *gin.Context, write bool) (models.Flow, bool) {
	var flow models.Flow

	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, response.ErrFindingsInvalidRequest, err)
		return flow, false
	}

	scope := flowScopeForFindings(c.GetStringSlice("prm"), c.GetUint64("uid"), flowID, write)
	if scope == nil {
		logger.FromContext(c).Errorf("error filtering user role permissions: permission not found")
		response.Error(c, response.ErrNotPermitted, nil)
		return flow, false
	}

	if err := s.db.Model(&flow).Scopes(scope).Take(&flow).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			response.Error(c, response.ErrFlowsNotFound, err)
			return flow, false
		}
		logger.FromContext(c).WithError(err).Errorf("error loading flow")
		response.Error(c, response.ErrInternal, err)
		return flow, false
	}

	return flow, true
}

func (s *FindingService) loadFindings(flowID uint64) ([]models.Finding, error) {
	var list []models.Finding
	if err := s.db.Where("flow_id = ?", flowID).Find(&list).Error; err != nil {
		return nil, err
	}

	for i := range list {
		list[i].DecodeRefs()
	}

	// Sorted here, not in SQL: the severity column is an enum whose order the
	// database defines, and the report must not depend on that.
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		ra, rb := severityRankOf(a.Severity), severityRankOf(b.Severity)
		if ra != rb {
			return ra < rb
		}
		if a.CVSSScore != b.CVSSScore {
			return a.CVSSScore > b.CVSSScore
		}
		return a.ID < b.ID
	})

	return list, nil
}

func severityRankOf(s string) int {
	if r, ok := findingSeverityRank[s]; ok {
		return r
	}
	return len(findingSeverityRank)
}

// mergeFindingEdit overlays the reviewer's changes on the stored finding.
func mergeFindingEdit(cur models.Finding, req updateFindingRequest) findings.Input {
	in := findings.Input{
		Title:       cur.Title,
		Asset:       cur.Asset,
		Severity:    cur.Severity,
		Status:      cur.Status,
		Description: cur.Description,
		Impact:      cur.Impact,
		Evidence:    cur.Evidence,
		Remediation: cur.Remediation,
		CVSSVector:  cur.CVSSVector,
		References:  cur.References,
	}

	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&in.Title, req.Title)
	set(&in.Asset, req.Asset)
	set(&in.Severity, req.Severity)
	set(&in.Status, req.Status)
	set(&in.Description, req.Description)
	set(&in.Impact, req.Impact)
	set(&in.Evidence, req.Evidence)
	set(&in.Remediation, req.Remediation)
	set(&in.CVSSVector, req.CVSSVector)
	if req.References != nil {
		in.References = *req.References
	}

	// A new vector without an explicit severity re-derives the severity from the
	// new score; clearing the vector keeps the current severity.
	if req.CVSSVector != nil && req.Severity == nil && strings.TrimSpace(*req.CVSSVector) != "" {
		in.Severity = ""
	}

	return in
}

func toReportFindings(list []models.Finding) []report.Finding {
	out := make([]report.Finding, 0, len(list))
	for _, f := range list {
		out = append(out, report.Finding{
			ID:          int64(f.ID),
			Title:       f.Title,
			Asset:       f.Asset,
			Severity:    f.Severity,
			Status:      f.Status,
			CVSSVector:  f.CVSSVector,
			CVSSScore:   f.CVSSScore,
			Description: f.Description,
			Impact:      f.Impact,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
			References:  f.References,
			Reviewed:    f.ReviewedAt != nil,
		})
	}
	return out
}

// flowScopeForFindings limits flow lookups by privilege: admins see every flow,
// everyone else only their own, and editing needs the edit privilege.
func flowScopeForFindings(privs []string, uid, flowID uint64, write bool) func(db *gorm.DB) *gorm.DB {
	if slices.Contains(privs, "findings.admin") {
		return func(db *gorm.DB) *gorm.DB { return db.Where("id = ?", flowID) }
	}

	need := "findings.view"
	if write {
		need = "findings.edit"
	}
	if slices.Contains(privs, need) {
		return func(db *gorm.DB) *gorm.DB { return db.Where("id = ? AND user_id = ?", flowID, uid) }
	}

	return nil
}
