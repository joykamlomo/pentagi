package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pentagi/pkg/database"
	"pentagi/pkg/findings"

	"github.com/sirupsen/logrus"
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

	f, err := findings.Normalize(findings.Input{
		Title:       action.Title,
		Asset:       action.Asset,
		Severity:    action.Severity.String(),
		Status:      action.Status.String(),
		Description: action.Description,
		Impact:      action.Impact,
		Evidence:    action.Evidence,
		Remediation: action.Remediation,
		CVSSVector:  action.CVSSVector,
		References:  action.References,
	}, findings.Options{})
	if err != nil {
		// A problem the agent can fix: explain it as a normal result instead of
		// failing the tool call, so the agent corrects it and tries again.
		logger.WithError(err).Warn("finding rejected")
		return fmt.Sprintf("Finding NOT recorded: %v. Fix this and call %s again.", err, ReportFindingToolName), nil
	}

	refs, err := json.Marshal(f.References)
	if err != nil {
		return "", fmt.Errorf("failed to encode references: %w", err)
	}

	row, err := t.db.UpsertFinding(ctx, database.UpsertFindingParams{
		FlowID:      t.flowID,
		TaskID:      nullInt64(t.taskID),
		SubtaskID:   nullInt64(t.subtaskID),
		Title:       f.Title,
		Severity:    database.FindingSeverity(f.Severity),
		Status:      database.FindingStatus(f.Status),
		CvssVector:  f.CVSSVector,
		CvssScore:   fmt.Sprintf("%.1f", f.CVSSScore),
		Asset:       f.Asset,
		Description: f.Description,
		Impact:      f.Impact,
		Evidence:    f.Evidence,
		Remediation: f.Remediation,
		Refs:        refs,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// The conflicting row was reviewed by a person; their edits take precedence.
		return fmt.Sprintf("A finding titled %q on %s was already reviewed by a person and was left unchanged.", f.Title, f.Asset), nil
	}
	if err != nil {
		logger.WithError(err).Error("failed to store finding")
		return "", fmt.Errorf("failed to store finding: %w", err)
	}

	msg := fmt.Sprintf("Finding #%d recorded: [%s] %s on %s (status: %s", row.ID, strings.ToUpper(f.Severity), f.Title, f.Asset, f.Status)
	if f.CVSSVector != "" {
		msg += fmt.Sprintf(", CVSS %.1f", f.CVSSScore)
	}
	msg += ")."
	if len(f.Notes) > 0 {
		msg += " Notes: " + strings.Join(f.Notes, "; ") + "."
	}

	return msg, nil
}

func nullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}
