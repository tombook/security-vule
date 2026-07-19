BEGIN;

CREATE TABLE poc.poc_runs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  finding_id      UUID NOT NULL REFERENCES detection.findings(id),
  source          poc_source_enum NOT NULL,
  poc_library_id  UUID,
  poc_script      TEXT NOT NULL,
  poc_script_hash TEXT NOT NULL,
  status          poc_status_enum NOT NULL DEFAULT 'pending',
  approved_by     UUID REFERENCES core.users(id),
  approved_at     TIMESTAMPTZ,
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  duration_ms     INT,
  exploit_proven  BOOLEAN NOT NULL DEFAULT FALSE,
  exit_code       INT,
  stdout_log      TEXT,
  stderr_log      TEXT,
  behavior_report JSONB,
  evidence_url    TEXT,
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_poc_runs__finding ON poc.poc_runs(finding_id, created_at DESC);
CREATE INDEX idx_poc_runs__pending_review ON poc.poc_runs(tenant_id, customer_id, status)
  WHERE status IN ('pending', 'approved', 'running');

CREATE TABLE poc.poc_sandboxes (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  poc_run_id      UUID NOT NULL UNIQUE REFERENCES poc.poc_runs(id) ON DELETE CASCADE,
  container_id    TEXT NOT NULL,
  runtime         sandbox_runtime_enum NOT NULL DEFAULT 'docker',
  cpu_limit       TEXT NOT NULL DEFAULT '1.0',
  memory_limit    TEXT NOT NULL DEFAULT '1Gi',
  network_mode    TEXT NOT NULL DEFAULT 'none',
  status          sandbox_status_enum NOT NULL DEFAULT 'pending',
  started_at      TIMESTAMPTZ,
  destroyed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE poc.poc_library (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  title           TEXT NOT NULL,
  description     TEXT,
  cwe_ids         TEXT[] NOT NULL DEFAULT '{}',
  framework_tags  TEXT[] NOT NULL DEFAULT '{}',
  language        TEXT,
  poc_script      TEXT NOT NULL,
  poc_script_hash TEXT NOT NULL,
  reuse_count     INT NOT NULL DEFAULT 0,
  last_reused_at  TIMESTAMPTZ,
  created_by      UUID NOT NULL REFERENCES core.users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ
);

CREATE TABLE poc.exploit_chains (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  name            TEXT NOT NULL,
  description     TEXT,
  chain_nodes     JSONB NOT NULL,
  created_by      UUID NOT NULL REFERENCES core.users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE poc.poc_chat_messages (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id         UUID NOT NULL,
  customer_id       UUID NOT NULL,
  project_id        UUID NOT NULL REFERENCES core.projects(id),
  poc_run_id        UUID REFERENCES poc.poc_runs(id) ON DELETE SET NULL,
  finding_id        UUID REFERENCES detection.findings(id) ON DELETE SET NULL,
  thread_id         UUID NOT NULL,
  parent_message_id UUID REFERENCES poc.poc_chat_messages(id) ON DELETE SET NULL,
  role              chat_role_enum NOT NULL,
  content           TEXT NOT NULL,
  content_redacted  BOOLEAN NOT NULL DEFAULT FALSE,
  prompt_tokens     INT NOT NULL DEFAULT 0,
  completion_tokens INT NOT NULL DEFAULT 0,
  model             TEXT,
  latency_ms        INT,
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_poc_chat__thread_time ON poc.poc_chat_messages(thread_id, occurred_at);
CREATE INDEX idx_poc_chat__poc_run ON poc.poc_chat_messages(poc_run_id, occurred_at) WHERE poc_run_id IS NOT NULL;

COMMIT;
