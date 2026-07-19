BEGIN;

CREATE TABLE governance.audit_logs (
  id                UUID DEFAULT uuid_generate_v7(),
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tenant_id         UUID,
  customer_id       UUID,
  actor_user_id     UUID,
  actor_email       TEXT,
  actor_ip          INET,
  actor_user_agent  TEXT,
  event_type        audit_event_enum NOT NULL,
  resource_type     TEXT,
  resource_id       UUID,
  action            TEXT NOT NULL,
  request_id        TEXT,
  before_state      JSONB,
  after_state       JSONB,
  metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash         BYTEA NOT NULL,
  entry_hash        BYTEA NOT NULL,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE governance.audit_logs IS '哈希链式审计;SHA-256(prev_hash||canonical(entry)),CLI audit verify 校验完整性';

CREATE TABLE governance.audit_logs_2026_07 PARTITION OF governance.audit_logs
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE governance.audit_logs_2026_08 PARTITION OF governance.audit_logs
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE governance.audit_logs_2026_09 PARTITION OF governance.audit_logs
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE INDEX idx_audit_logs__tenant_time ON governance.audit_logs(tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_logs__actor_time ON governance.audit_logs(actor_user_id, occurred_at DESC) WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_logs__resource ON governance.audit_logs(resource_type, resource_id, occurred_at DESC);

CREATE TABLE governance.notifications (
  id                UUID DEFAULT uuid_generate_v7(),
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tenant_id         UUID NOT NULL,
  recipient_user_id UUID NOT NULL REFERENCES core.users(id),
  type              notification_type_enum NOT NULL,
  title             TEXT NOT NULL,
  body              TEXT,
  link_url          TEXT,
  payload           JSONB NOT NULL DEFAULT '{}'::jsonb,
  read_at           TIMESTAMPTZ,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE governance.notifications_2026_07 PARTITION OF governance.notifications
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE governance.notifications_2026_08 PARTITION OF governance.notifications
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE governance.notifications_2026_09 PARTITION OF governance.notifications
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE TABLE governance.webhooks (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id           UUID NOT NULL REFERENCES core.tenants(id),
  customer_id         UUID,
  url                 TEXT NOT NULL,
  secret_ciphertext   BYTEA NOT NULL,
  event_types         TEXT[] NOT NULL DEFAULT '{}',
  enabled             BOOLEAN NOT NULL DEFAULT TRUE,
  created_by          UUID NOT NULL REFERENCES core.users(id),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at          TIMESTAMPTZ
);
CREATE INDEX idx_webhooks__tenant_enabled ON governance.webhooks(tenant_id, enabled) WHERE deleted_at IS NULL;

CREATE TABLE governance.webhook_deliveries (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  webhook_id        UUID NOT NULL REFERENCES governance.webhooks(id) ON DELETE CASCADE,
  event_type        TEXT NOT NULL,
  payload           JSONB NOT NULL,
  attempt           INT NOT NULL DEFAULT 1,
  status            webhook_delivery_status_enum NOT NULL DEFAULT 'pending',
  http_status       INT,
  response_body     TEXT,
  duration_ms       INT,
  error_message     TEXT,
  next_retry_at     TIMESTAMPTZ,
  delivered_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_deliveries__webhook ON governance.webhook_deliveries(webhook_id, created_at DESC);
CREATE INDEX idx_webhook_deliveries__pending_retry ON governance.webhook_deliveries(next_retry_at)
  WHERE status = 'pending' AND next_retry_at IS NOT NULL;

CREATE TABLE governance.tenant_data_exports (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id           UUID NOT NULL REFERENCES core.tenants(id),
  customer_id         UUID REFERENCES core.customers(id) ON DELETE SET NULL,
  request_type        data_export_type_enum NOT NULL,
  requested_by        UUID NOT NULL REFERENCES core.users(id) ON DELETE SET NULL,
  requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status              data_export_status_enum NOT NULL DEFAULT 'pending',
  scope               JSONB NOT NULL,
  artifact_uri        TEXT,
  artifact_expires_at TIMESTAMPTZ,
  artifact_sha256     TEXT,
  artifact_size_bytes BIGINT,
  record_counts       JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message       TEXT,
  started_at          TIMESTAMPTZ,
  completed_at        TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_data_exports__tenant_time ON governance.tenant_data_exports(tenant_id, requested_at DESC);
CREATE INDEX idx_data_exports__pending ON governance.tenant_data_exports(status, requested_at)
  WHERE status IN ('pending', 'processing');

COMMIT;
