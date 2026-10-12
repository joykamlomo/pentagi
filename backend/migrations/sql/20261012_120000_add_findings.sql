-- +goose Up
-- +goose StatementBegin

-- Structured pentest findings recorded by agents and reviewed by a human before
-- they are delivered to a client.
CREATE TYPE FINDING_SEVERITY AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE FINDING_STATUS AS ENUM ('potential', 'confirmed', 'false_positive');

CREATE TABLE findings (
  id           BIGINT            PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  flow_id      BIGINT            NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  -- The planner rewrites and deletes subtasks during a run; a finding must outlive them.
  task_id      BIGINT            NULL REFERENCES tasks(id) ON DELETE SET NULL,
  subtask_id   BIGINT            NULL REFERENCES subtasks(id) ON DELETE SET NULL,
  title        TEXT              NOT NULL,
  severity     FINDING_SEVERITY  NOT NULL,
  status       FINDING_STATUS    NOT NULL DEFAULT 'potential',
  cvss_vector  TEXT              NOT NULL DEFAULT '',
  cvss_score   NUMERIC(3,1)      NOT NULL DEFAULT 0,
  asset        TEXT              NOT NULL,
  description  TEXT              NOT NULL,
  impact       TEXT              NOT NULL DEFAULT '',
  evidence     TEXT              NOT NULL DEFAULT '',
  remediation  TEXT              NOT NULL,
  refs         JSON              NOT NULL DEFAULT '[]',
  -- Set when a person has reviewed or edited the finding; agents no longer overwrite it.
  reviewed_at  TIMESTAMPTZ       NULL,
  created_at   TIMESTAMPTZ       DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMPTZ       DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX findings_flow_id_idx ON findings(flow_id);
CREATE INDEX findings_task_id_idx ON findings(task_id);
CREATE INDEX findings_subtask_id_idx ON findings(subtask_id);
CREATE INDEX findings_severity_idx ON findings(severity);

-- One finding per issue per asset in a flow: agents that rediscover or re-report
-- an issue update the existing row instead of piling up duplicates.
CREATE UNIQUE INDEX findings_flow_issue_uniq ON findings(flow_id, lower(title), lower(asset));

CREATE OR REPLACE TRIGGER update_findings_modified
  BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

INSERT INTO privileges (role_id, name) VALUES
  (1, 'findings.admin'),
  (1, 'findings.view'),
  (1, 'findings.edit'),
  (2, 'findings.view'),
  (2, 'findings.edit')
  ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM privileges WHERE name IN ('findings.admin', 'findings.view', 'findings.edit');

DROP TRIGGER IF EXISTS update_findings_modified ON findings;
DROP TABLE IF EXISTS findings;
DROP TYPE IF EXISTS FINDING_STATUS;
DROP TYPE IF EXISTS FINDING_SEVERITY;

-- +goose StatementEnd
