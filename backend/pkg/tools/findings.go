package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pentagi/pkg/cvss"
	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

const (
	maxFindingTitleLen  = 200
	maxFindingAssetLen  = 300
	maxFindingTextLen   = 20_000
	maxFindingEvidence  = 50_000
	maxFindingRefs      = 20
	maxFindingRefLen    = 300
	truncatedMarkerText = "\n[truncated]"
)

type findingsTool struct {
	flowID    int64
	taskID    *int64
	subtaskID *int64
	db        database.Querier
}

// NewFindingsTool returns the tool agents use to record structured findings.
func NewFindingsTool(flowID int64, taskID, subtaskID *int64, db database.Querier) Tool {
	return &findingsTool{flowID: flowID, taskID: taskID, subtaskID: subtaskID, db: db}
}

func (t *findingsTool) IsAvailable() bool {
	return t.db != nil
}

func (t *findingsTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	if name != ReportFindingToolName {
		return "", fmt.Errorf("unknown tool: %s", name)
	}

	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(t.flowID, t.taskID, t.subtaskID, logrus.Fields{
		"tool": name,
	}))

	var action ReportFindingAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal report finding action")
		return "", fmt.Errorf("failed to unmarshal %s action arguments: %w", name, err)
	}

	f, err := normalizeFinding(action)
	if err != nil {
		// A problem the agent can fix: explain it as a normal result instead of
		// failing the tool call, so the agent corrects it and tries again.
		logger.WithError(err).Warn("finding rejected")
		return fmt.Sprintf("Finding NOT recorded: %v. Fix this and call %s again.", err, ReportFindingToolName), nil
	}

	row, err := t.db.UpsertFinding(ctx, database.UpsertFindingParams{
		FlowID:      t.flowID,
		TaskID:      nullInt64(t.taskID),
		SubtaskID:   nullInt64(t.subtaskID),
		Title:       f.title,
		Severity:    f.severity,
		Status:      f.status,
		CvssVector:  f.cvssVector,
		CvssScore:   fmt.Sprintf("%.1f", f.cvssScore),
		Asset:       f.asset,
		Description: f.description,
		Impact:      f.impact,
		Evidence:    f.evidence,
		Remediation: f.remediation,
		Refs:        f.refs,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// The conflicting row was reviewed by a person; their edits take precedence.
		return fmt.Sprintf("A finding titled %q on %s was already reviewed by a person and was left unchanged.", f.title, f.asset), nil
	}
	if err != nil {
		logger.WithError(err).Error("failed to store finding")
		return "", fmt.Errorf("failed to store finding: %w", err)
	}

	msg := fmt.Sprintf("Finding #%d recorded: [%s] %s on %s (status: %s", row.ID, strings.ToUpper(string(f.severity)), f.title, f.asset, f.status)
	if f.cvssVector != "" {
		msg += fmt.Sprintf(", CVSS %.1f", f.cvssScore)
	}
	msg += ")."
	if len(f.notes) > 0 {
		msg += " Notes: " + strings.Join(f.notes, "; ") + "."
	}

	return msg, nil
}

// finding is a validated, normalized report_finding payload.
type finding struct {
	title       string
	asset       string
	severity    database.FindingSeverity
	status      database.FindingStatus
	description string
	impact      string
	evidence    string
	remediation string
	cvssVector  string
	cvssScore   float64
	refs        json.RawMessage
	notes       []string // adjustments made on the agent's behalf, echoed back to it
}

// normalizeFinding validates a payload and applies the server-side rules:
// severity follows the CVSS score when a vector is given, confirmed findings
// need evidence, and text is made safe for storage. Problems the agent can fix
// are returned as a single error listing all of them.
func normalizeFinding(a ReportFindingAction) (finding, error) {
	f := finding{
		title:       cleanText(a.Title),
		asset:       cleanText(a.Asset),
		description: cleanText(a.Description),
		impact:      cleanText(a.Impact),
		evidence:    cleanText(a.Evidence),
		remediation: cleanText(a.Remediation),
	}

	var problems []string

	var missing []string
	for _, field := range []struct{ name, value string }{
		{"title", f.title}, {"asset", f.asset}, {"description", f.description},
		{"impact", f.impact}, {"remediation", f.remediation},
	} {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		problems = append(problems, "missing required field(s): "+strings.Join(missing, ", "))
	}
	if len(f.title) > maxFindingTitleLen {
		problems = append(problems, fmt.Sprintf("title is too long (%d > %d characters)", len(f.title), maxFindingTitleLen))
	}
	if len(f.asset) > maxFindingAssetLen {
		problems = append(problems, fmt.Sprintf("asset is too long (%d > %d characters)", len(f.asset), maxFindingAssetLen))
	}

	switch strings.ToLower(strings.TrimSpace(a.Severity.String())) {
	case "critical":
		f.severity = database.FindingSeverityCritical
	case "high":
		f.severity = database.FindingSeverityHigh
	case "medium":
		f.severity = database.FindingSeverityMedium
	case "low":
		f.severity = database.FindingSeverityLow
	case "info", "informational":
		f.severity = database.FindingSeverityInfo
	default:
		problems = append(problems, fmt.Sprintf("severity %q is invalid (use critical, high, medium, low or info)", a.Severity))
	}

	switch strings.ToLower(strings.TrimSpace(a.Status.String())) {
	case "confirmed":
		f.status = database.FindingStatusConfirmed
		if f.evidence == "" {
			problems = append(problems, "status 'confirmed' requires evidence (the exact command/request and output that prove it); "+
				"use status 'potential' if you have not reproduced it")
		}
	case "potential", "":
		f.status = database.FindingStatusPotential
	default:
		problems = append(problems, fmt.Sprintf("status %q is invalid (use confirmed or potential)", a.Status))
	}

	if vec := strings.TrimSpace(a.CVSSVector); vec != "" {
		res, err := cvss.Parse(vec)
		if err != nil {
			problems = append(problems, fmt.Sprintf("invalid cvss_vector: %v", err))
		} else {
			f.cvssVector = res.Vector
			f.cvssScore = res.Score

			derived := severityFromCVSS(res.Severity)
			if f.severity != "" && f.severity != derived {
				f.notes = append(f.notes, fmt.Sprintf("severity set to %s to match CVSS %.1f", derived, res.Score))
			}
			f.severity = derived
		}
	}

	if len(problems) > 0 {
		return finding{}, errors.New(strings.Join(problems, "; "))
	}

	var note string
	if f.description, note = capText(f.description, maxFindingTextLen, "description"); note != "" {
		f.notes = append(f.notes, note)
	}
	if f.impact, note = capText(f.impact, maxFindingTextLen, "impact"); note != "" {
		f.notes = append(f.notes, note)
	}
	if f.remediation, note = capText(f.remediation, maxFindingTextLen, "remediation"); note != "" {
		f.notes = append(f.notes, note)
	}
	if f.evidence, note = capText(f.evidence, maxFindingEvidence, "evidence"); note != "" {
		f.notes = append(f.notes, note)
	}

	refs, refNote := normalizeRefs(a.References)
	if refNote != "" {
		f.notes = append(f.notes, refNote)
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return finding{}, fmt.Errorf("failed to encode references: %w", err)
	}
	f.refs = raw

	return f, nil
}

func severityFromCVSS(s cvss.Severity) database.FindingSeverity {
	switch s {
	case cvss.SeverityCritical:
		return database.FindingSeverityCritical
	case cvss.SeverityHigh:
		return database.FindingSeverityHigh
	case cvss.SeverityMedium:
		return database.FindingSeverityMedium
	case cvss.SeverityLow:
		return database.FindingSeverityLow
	default:
		return database.FindingSeverityInfo
	}
}

// cleanText trims and makes text storable: PostgreSQL rejects NUL bytes and
// invalid UTF-8, and terminal output pasted as evidence can contain both.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

func capText(s string, limit int, field string) (string, string) {
	if len(s) <= limit {
		return s, ""
	}
	cut := limit - len(truncatedMarkerText)
	// do not split a multi-byte character
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + truncatedMarkerText, fmt.Sprintf("%s truncated to %d characters", field, limit)
}

func normalizeRefs(in Strings) ([]string, string) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	dropped := 0

	for _, r := range in {
		r = cleanText(r)
		if r == "" {
			continue
		}
		if len(r) > maxFindingRefLen {
			r = r[:maxFindingRefLen]
			for len(r) > 0 && !isValidUTF8Tail(r) {
				r = r[:len(r)-1]
			}
		}
		key := strings.ToLower(r)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if len(out) >= maxFindingRefs {
			dropped++
			continue
		}
		out = append(out, r)
	}

	if dropped > 0 {
		return out, fmt.Sprintf("only the first %d references were kept", maxFindingRefs)
	}
	return out, ""
}

func isValidUTF8Tail(s string) bool {
	return s == strings.ToValidUTF8(s, "")
}

func nullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}
