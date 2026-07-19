BEGIN;

CREATE TABLE meta.schema_migrations (
  version         TEXT PRIMARY KEY,
  description     TEXT NOT NULL,
  applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  checksum        TEXT NOT NULL,
  rolled_back_at  TIMESTAMPTZ
);

CREATE TABLE meta.app_settings (
  key         TEXT PRIMARY KEY,
  value       JSONB NOT NULL,
  updated_by  UUID REFERENCES core.users(id),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE meta.app_settings IS '平台级配置(套餐价格、计费系数、限流阈值等)';

CREATE TABLE meta.scheduled_jobs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  job_type        TEXT NOT NULL,
  queue_name      TEXT NOT NULL DEFAULT 'default',
  status          job_status_enum NOT NULL DEFAULT 'pending',
  priority        INT NOT NULL DEFAULT 0,
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  result          JSONB,
  attempts        INT NOT NULL DEFAULT 0,
  max_attempts    INT NOT NULL DEFAULT 3,
  scheduled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  duration_ms     INT,
  locked_by       TEXT,
  locked_until    TIMESTAMPTZ,
  error_message   TEXT,
  tenant_id       UUID,
  customer_id     UUID,
  project_id      UUID,
  correlation_id  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scheduled_jobs__runnable ON meta.scheduled_jobs(queue_name, priority DESC, scheduled_at)
  WHERE status = 'pending';
CREATE INDEX idx_scheduled_jobs__stale_locks ON meta.scheduled_jobs(locked_until)
  WHERE status = 'running';

COMMIT;
