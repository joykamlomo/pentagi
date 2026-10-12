-- name: GetFlowFindings :many
SELECT
  fi.*
FROM findings fi
INNER JOIN flows f ON fi.flow_id = f.id
WHERE fi.flow_id = $1 AND f.deleted_at IS NULL
ORDER BY fi.severity ASC, fi.cvss_score DESC, fi.created_at ASC;

-- name: GetUserFlowFindings :many
SELECT
  fi.*
FROM findings fi
INNER JOIN flows f ON fi.flow_id = f.id
INNER JOIN users u ON f.user_id = u.id
WHERE fi.flow_id = $1 AND f.user_id = $2 AND f.deleted_at IS NULL
ORDER BY fi.severity ASC, fi.cvss_score DESC, fi.created_at ASC;

-- name: GetFlowFinding :one
SELECT
  fi.*
FROM findings fi
INNER JOIN flows f ON fi.flow_id = f.id
WHERE fi.id = $1 AND fi.flow_id = $2 AND f.deleted_at IS NULL;

-- name: GetUserFlowFinding :one
SELECT
  fi.*
FROM findings fi
INNER JOIN flows f ON fi.flow_id = f.id
INNER JOIN users u ON f.user_id = u.id
WHERE fi.id = $1 AND fi.flow_id = $2 AND f.user_id = $3 AND f.deleted_at IS NULL;

-- Agents record a finding with this query. Re-reporting the same issue on the same
-- asset updates the existing row, except once a person has reviewed it: then the
-- row is left untouched (no row is returned) so human edits are never overwritten.
-- A confirmed finding is never downgraded back to potential by a later report.
-- name: UpsertFinding :one
INSERT INTO findings (
  flow_id,
  task_id,
  subtask_id,
  title,
  severity,
  status,
  cvss_vector,
  cvss_score,
  asset,
  description,
  impact,
  evidence,
  remediation,
  refs
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
)
ON CONFLICT (flow_id, lower(title), lower(asset)) DO UPDATE SET
  task_id     = EXCLUDED.task_id,
  subtask_id  = EXCLUDED.subtask_id,
  severity    = EXCLUDED.severity,
  status      = CASE WHEN findings.status = 'confirmed' THEN findings.status ELSE EXCLUDED.status END,
  cvss_vector = EXCLUDED.cvss_vector,
  cvss_score  = EXCLUDED.cvss_score,
  description = EXCLUDED.description,
  impact      = EXCLUDED.impact,
  evidence    = EXCLUDED.evidence,
  remediation = EXCLUDED.remediation,
  refs        = EXCLUDED.refs
WHERE findings.reviewed_at IS NULL
RETURNING *;

-- A reviewer's edit. Marks the finding as reviewed so agents stop overwriting it.
-- name: UpdateFinding :one
UPDATE findings
SET
  title       = $1,
  severity    = $2,
  status      = $3,
  cvss_vector = $4,
  cvss_score  = $5,
  asset       = $6,
  description = $7,
  impact      = $8,
  evidence    = $9,
  remediation = $10,
  refs        = $11,
  reviewed_at = CURRENT_TIMESTAMP
WHERE id = $12 AND flow_id = $13
RETURNING *;

-- name: DeleteFlowFinding :exec
DELETE FROM findings
WHERE id = $1 AND flow_id = $2;
