BEGIN;

CREATE TABLE core.customers (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  industry        TEXT,
  sla_tier        sla_tier_enum NOT NULL DEFAULT 'standard',
  status          customer_status_enum NOT NULL DEFAULT 'active',
  contact_email   CITEXT,
  contact_phone   TEXT,
  billing_account_id UUID,
  white_label     JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ,
  CONSTRAINT uq_customers__tenant_slug UNIQUE (tenant_id, slug)
);
CREATE INDEX idx_customers__tenant_status ON core.customers(tenant_id, status) WHERE deleted_at IS NULL;

CREATE TABLE core.contacts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL REFERENCES core.customers(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  role            contact_role_enum NOT NULL DEFAULT 'other',
  email           CITEXT NOT NULL,
  phone           TEXT,
  is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
  notification_preference JSONB NOT NULL DEFAULT '{}'::jsonb,
  invited_at      TIMESTAMPTZ,
  last_login_at   TIMESTAMPTZ,
  user_id         UUID REFERENCES core.users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_contacts__customer ON core.contacts(customer_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_contacts__customer_primary ON core.contacts(customer_id) WHERE is_primary AND deleted_at IS NULL;
COMMENT ON TABLE core.contacts IS '客户 1:N 联系人';

CREATE TABLE core.projects (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  customer_id     UUID NOT NULL REFERENCES core.customers(id),
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  description     TEXT,
  labels          TEXT[] NOT NULL DEFAULT '{}',
  status          project_status_enum NOT NULL DEFAULT 'configuring',
  sla_tier        sla_tier_enum NOT NULL DEFAULT 'standard',
  default_branch  TEXT,
  branch_policy   JSONB,
  ignore_paths    TEXT[] NOT NULL DEFAULT '{}',
  data_retention_days INT NOT NULL DEFAULT 90,
  owner_user_id   UUID REFERENCES core.users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ,
  CONSTRAINT uq_projects__customer_slug UNIQUE (customer_id, slug)
);
CREATE INDEX idx_projects__customer ON core.projects(customer_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_projects__owner ON core.projects(owner_user_id) WHERE deleted_at IS NULL;

CREATE TABLE core.sources (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  project_id      UUID NOT NULL UNIQUE REFERENCES core.projects(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  source_type     source_type_enum NOT NULL,
  repo_full_name  TEXT,
  repo_url        TEXT,
  external_id     TEXT,
  branch          TEXT,
  webhook_id      TEXT,
  webhook_secret_ciphertext BYTEA,
  access_token_ciphertext BYTEA,
  refresh_token_ciphertext BYTEA,
  token_expires_at TIMESTAMPTZ,
  upload_object_key TEXT,
  upload_size_bytes BIGINT,
  upload_etag     TEXT,
  status          source_status_enum NOT NULL DEFAULT 'active',
  last_synced_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON COLUMN core.sources.access_token_ciphertext IS 'KMS envelope encrypted';

CREATE TABLE core.source_sync_history (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  source_id       UUID NOT NULL REFERENCES core.sources(id) ON DELETE CASCADE,
  triggered_by    UUID REFERENCES core.users(id),
  trigger_type    sync_trigger_enum NOT NULL,
  status          sync_status_enum NOT NULL,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ,
  duration_ms     INT,
  commit_sha      TEXT,
  branch          TEXT,
  file_count      INT,
  total_size_bytes BIGINT,
  asset_hash      TEXT,
  snapshot_id     UUID,
  error_code      TEXT,
  error_message   TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_source_sync__source_time ON core.source_sync_history(source_id, started_at DESC);
CREATE INDEX idx_source_sync__failed ON core.source_sync_history(source_id, started_at DESC)
  WHERE status IN ('failed', 'timeout');

CREATE TABLE core.api_keys (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  key_prefix      TEXT NOT NULL UNIQUE,
  key_hash        TEXT NOT NULL,
  scopes          TEXT[] NOT NULL DEFAULT '{}',
  last_used_at    TIMESTAMPTZ,
  last_used_ip    INET,
  expires_at      TIMESTAMPTZ,
  created_by      UUID NOT NULL REFERENCES core.users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at      TIMESTAMPTZ,
  revoked_by      UUID REFERENCES core.users(id)
);
CREATE INDEX idx_api_keys__project_active ON core.api_keys(project_id)
  WHERE revoked_at IS NULL;

CREATE TABLE core.reports (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL REFERENCES core.customers(id),
  project_id      UUID REFERENCES core.projects(id),
  finding_id      UUID,
  report_type     TEXT NOT NULL,
  format          TEXT NOT NULL,
  period_start    DATE,
  period_end      DATE,
  file_object_key TEXT,
  file_size_bytes BIGINT,
  generated_by    UUID REFERENCES core.users(id),
  status          TEXT NOT NULL DEFAULT 'pending',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_reports__customer_time ON core.reports(customer_id, created_at DESC);

COMMIT;
