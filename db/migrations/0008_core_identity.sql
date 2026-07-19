BEGIN;

CREATE TABLE core.tenants (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL UNIQUE,
  plan            tenant_plan_enum NOT NULL DEFAULT 'starter',
  status          tenant_status_enum NOT NULL DEFAULT 'pending',
  sso_config      JSONB,
  white_label     JSONB,
  application_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ
);
COMMENT ON TABLE core.tenants IS '服务商账户(平台最高层租户)';

CREATE TABLE core.users (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  customer_id     UUID,
  portal          portal_enum NOT NULL,
  email           CITEXT NOT NULL,
  password_hash   TEXT NOT NULL,
  full_name       TEXT,
  role            user_role_enum NOT NULL,
  status          user_status_enum NOT NULL DEFAULT 'pending',
  mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret_ciphertext BYTEA,
  last_login_at   TIMESTAMPTZ,
  failed_login_count INT NOT NULL DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  notification_prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at      TIMESTAMPTZ,
  CONSTRAINT uq_users__tenant_email UNIQUE (tenant_id, email)
);
CREATE INDEX idx_users__tenant_customer ON core.users(tenant_id, customer_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users__notification_prefs_gin ON core.users USING GIN (notification_prefs jsonb_path_ops);
COMMENT ON TABLE core.users IS '平台用户(可登录双门户)';

CREATE TABLE core.sessions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  user_id         UUID NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL,
  refresh_token_hash TEXT UNIQUE,
  user_agent      TEXT,
  ip_address      INET,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sessions__user_active ON core.sessions(user_id)
  WHERE revoked_at IS NULL;

CREATE TABLE core.invites (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  customer_id     UUID,
  email           CITEXT NOT NULL,
  role            user_role_enum NOT NULL,
  token_hash      TEXT NOT NULL UNIQUE,
  invited_by      UUID NOT NULL REFERENCES core.users(id),
  status          invite_status_enum NOT NULL DEFAULT 'pending',
  expires_at      TIMESTAMPTZ NOT NULL,
  accepted_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invites__pending ON core.invites(tenant_id, email) WHERE status = 'pending';

CREATE TABLE core.password_reset_tokens (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  user_id         UUID NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
  token_hash      TEXT NOT NULL UNIQUE,
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ,
  ip_address      INET,
  user_agent      TEXT,
  requested_via   password_reset_via_enum NOT NULL DEFAULT 'web_form',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_password_reset__user_active ON core.password_reset_tokens(user_id)
  WHERE used_at IS NULL;
CREATE INDEX idx_password_reset__expiry_cleanup ON core.password_reset_tokens(expires_at)
  WHERE used_at IS NULL;

COMMIT;
