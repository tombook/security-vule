BEGIN;

CREATE TABLE detection.engines (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID,
  name            TEXT NOT NULL,
  engine_type     engine_type_enum NOT NULL,
  version         TEXT NOT NULL,
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  health_status   engine_health_enum NOT NULL DEFAULT 'unknown',
  last_health_check_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_engines__tenant ON detection.engines(tenant_id) WHERE enabled;

CREATE TABLE detection.engine_health_checks (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  engine_id       UUID NOT NULL REFERENCES detection.engines(id) ON DELETE CASCADE,
  tenant_id       UUID,
  health_status   engine_health_enum NOT NULL,
  latency_ms      INT,
  check_payload   JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message   TEXT,
  checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_engine_health__engine_time ON detection.engine_health_checks(engine_id, checked_at DESC);
CREATE INDEX idx_engine_health__time_brin ON detection.engine_health_checks USING BRIN (checked_at);

CREATE TABLE detection.rules (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  engine_id       UUID NOT NULL REFERENCES detection.engines(id),
  rule_external_id TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  cwe_ids         TEXT[] NOT NULL DEFAULT '{}',
  owasp_ids       TEXT[] NOT NULL DEFAULT '{}',
  severity        severity_enum NOT NULL,
  default_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  rule_metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_rules__engine_external UNIQUE (engine_id, rule_external_id)
);
CREATE INDEX idx_rules__cwe ON detection.rules USING GIN (cwe_ids);
CREATE INDEX idx_rules__owasp ON detection.rules USING GIN (owasp_ids);

CREATE TABLE detection.policy_configs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  scope           policy_scope_enum NOT NULL,
  customer_id     UUID,
  project_id      UUID,
  name            TEXT NOT NULL,
  enabled_engines UUID[] NOT NULL DEFAULT '{}',
  enabled_rules   UUID[] NOT NULL DEFAULT '{}',
  severity_threshold severity_enum NOT NULL DEFAULT 'low',
  incremental_mode incremental_mode_enum NOT NULL DEFAULT 'call_graph',
  auto_scan_on_sync BOOLEAN NOT NULL DEFAULT FALSE,
  scan_schedule_cron TEXT,
  include_paths   TEXT[] NOT NULL DEFAULT '{}',
  exclude_paths   TEXT[] NOT NULL DEFAULT '{}',
  is_default      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ,
  CONSTRAINT chk_policy_scope CHECK (
    (scope = 'tenant' AND customer_id IS NULL AND project_id IS NULL)
    OR (scope = 'customer' AND customer_id IS NOT NULL AND project_id IS NULL)
    OR (scope = 'project' AND project_id IS NOT NULL)
  )
);

CREATE TABLE detection.policy_versions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  policy_id       UUID NOT NULL REFERENCES detection.policy_configs(id),
  snapshot        JSONB NOT NULL,
  changed_by      UUID NOT NULL REFERENCES core.users(id),
  change_note     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_policy_versions__policy ON detection.policy_versions(policy_id, created_at DESC);

CREATE TABLE detection.snapshots (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  project_id      UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  branch          TEXT NOT NULL,
  commit_sha      TEXT NOT NULL,
  asset_hash      TEXT NOT NULL,
  file_count      INT NOT NULL,
  total_size_bytes BIGINT NOT NULL,
  language_stats  JSONB NOT NULL DEFAULT '{}'::jsonb,
  framework_stats JSONB NOT NULL DEFAULT '{}'::jsonb,
  dependency_list JSONB NOT NULL DEFAULT '{}'::jsonb,
  call_graph_ref  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_snapshots__project_branch_commit UNIQUE (project_id, branch, commit_sha)
);
CREATE INDEX idx_snapshots__project_branch ON detection.snapshots(project_id, branch, created_at DESC);

CREATE TABLE detection.scan_runs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  snapshot_id     UUID NOT NULL REFERENCES detection.snapshots(id),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  policy_version_id UUID,
  trigger_type    scan_trigger_enum NOT NULL,
  triggered_by    UUID REFERENCES core.users(id),
  incremental_mode incremental_mode_enum NOT NULL,
  status          scan_status_enum NOT NULL DEFAULT 'queued',
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  duration_ms     INT,
  findings_total  INT NOT NULL DEFAULT 0,
  findings_new    INT NOT NULL DEFAULT 0,
  findings_fixed  INT NOT NULL DEFAULT 0,
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scan_runs__project_status ON detection.scan_runs(project_id, status, created_at DESC);

CREATE TABLE detection.scan_run_engines (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  scan_run_id     UUID NOT NULL REFERENCES detection.scan_runs(id) ON DELETE CASCADE,
  engine_id       UUID NOT NULL REFERENCES detection.engines(id),
  status          engine_run_status_enum NOT NULL,
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  duration_ms     INT,
  findings_count  INT NOT NULL DEFAULT 0,
  rules_executed  INT,
  files_analyzed  INT,
  bytes_analyzed  BIGINT,
  retry_count     INT NOT NULL DEFAULT 0,
  error_code      TEXT,
  error_message   TEXT,
  raw_output_uri  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE detection.findings (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  scan_run_id     UUID NOT NULL REFERENCES detection.scan_runs(id),
  snapshot_id     UUID NOT NULL REFERENCES detection.snapshots(id),
  rule_id         UUID NOT NULL REFERENCES detection.rules(id),
  fingerprint     TEXT NOT NULL,
  severity        severity_enum NOT NULL,
  status          finding_status_enum NOT NULL DEFAULT 'open',
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT NOT NULL,
  start_line      INT NOT NULL,
  end_line        INT NOT NULL,
  code_snippet    TEXT,
  cwe_ids         TEXT[] NOT NULL DEFAULT '{}',
  owasp_ids       TEXT[] NOT NULL DEFAULT '{}',
  confidence      confidence_enum NOT NULL DEFAULT 'medium',
  engines         TEXT[] NOT NULL DEFAULT '{}',
  dfg_path        JSONB,
  ai_triage_hint  BOOLEAN,
  ai_triage_score REAL,
  confirmed_by    UUID REFERENCES core.users(id),
  confirmed_at    TIMESTAMPTZ,
  assigned_to     UUID REFERENCES core.users(id),
  ticket_ref      JSONB,
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  fixed_at        TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_finding_lines CHECK (start_line > 0 AND end_line >= start_line),
  CONSTRAINT uq_findings__project_fingerprint UNIQUE (project_id, fingerprint)
);
CREATE INDEX idx_findings__project_severity ON detection.findings(project_id, severity, last_seen_at DESC);
CREATE INDEX idx_findings__cwe ON detection.findings USING GIN (cwe_ids);
CREATE INDEX idx_findings__dfg_path ON detection.findings USING GIN (dfg_path);

CREATE TABLE detection.finding_state_history (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  finding_id      UUID NOT NULL REFERENCES detection.findings(id) ON DELETE CASCADE,
  from_status     finding_status_enum,
  to_status       finding_status_enum NOT NULL,
  change_source   state_change_source_enum NOT NULL,
  changed_by      UUID REFERENCES core.users(id),
  reason          TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_finding_state_history__finding_time ON detection.finding_state_history(finding_id, occurred_at DESC);

CREATE TABLE detection.finding_comments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  finding_id      UUID NOT NULL REFERENCES detection.findings(id) ON DELETE CASCADE,
  author_user_id  UUID NOT NULL REFERENCES core.users(id),
  body            TEXT NOT NULL,
  comment_type    comment_type_enum NOT NULL DEFAULT 'note',
  mentioned_user_ids UUID[] NOT NULL DEFAULT '{}',
  attachments     JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_edited       BOOLEAN NOT NULL DEFAULT FALSE,
  edited_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_finding_comments__finding_time ON detection.finding_comments(finding_id, created_at DESC)
  WHERE deleted_at IS NULL;

CREATE TABLE detection.pr_scan_checks (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  scan_run_id     UUID NOT NULL REFERENCES detection.scan_runs(id) ON DELETE CASCADE,
  source_type     pr_source_type_enum NOT NULL,
  external_id     TEXT NOT NULL,
  external_node_id TEXT,
  repo_full_name  TEXT NOT NULL,
  ref             TEXT NOT NULL,
  head_sha        TEXT NOT NULL,
  base_sha        TEXT NOT NULL,
  status          pr_check_status_enum NOT NULL,
  conclusion      pr_check_conclusion_enum,
  blocking        BOOLEAN NOT NULL DEFAULT FALSE,
  blocking_threshold severity_enum,
  external_check_run_id TEXT,
  external_check_url   TEXT,
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_pr_scan_checks__scan_run ON detection.pr_scan_checks(scan_run_id);
CREATE INDEX idx_pr_scan_checks__repo_external ON detection.pr_scan_checks(repo_full_name, external_id, created_at DESC);

COMMIT;
