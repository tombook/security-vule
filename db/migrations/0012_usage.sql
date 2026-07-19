BEGIN;

CREATE TABLE usage.usage_events (
  id                UUID DEFAULT uuid_generate_v7(),
  tenant_id         UUID NOT NULL,
  customer_id       UUID,
  project_id        UUID,
  finding_id        UUID,
  poc_run_id        UUID,
  capability        ai_capability_enum NOT NULL,
  provider          ai_provider_enum NOT NULL,
  model             TEXT NOT NULL,
  prompt_tokens     INT NOT NULL DEFAULT 0,
  completion_tokens INT NOT NULL DEFAULT 0,
  total_tokens      INT NOT NULL DEFAULT 0,
  cost_usd          NUMERIC(10,6) NOT NULL DEFAULT 0,
  request_id        TEXT,
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE usage.usage_events IS 'AI token 用量事件流;按月分区,旧分区归档至冷存储';

CREATE TABLE usage.usage_events_2026_07 PARTITION OF usage.usage_events
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE usage.usage_events_2026_08 PARTITION OF usage.usage_events
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE usage.usage_events_2026_09 PARTITION OF usage.usage_events
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE INDEX idx_usage_events__tenant_customer_time ON usage.usage_events(tenant_id, customer_id, occurred_at DESC);
CREATE INDEX idx_usage_events__project_time ON usage.usage_events(project_id, occurred_at DESC) WHERE project_id IS NOT NULL;
CREATE INDEX idx_usage_events__capability_time ON usage.usage_events(capability, occurred_at DESC);

CREATE TABLE usage.quota_policies (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id             UUID NOT NULL REFERENCES core.tenants(id),
  customer_id           UUID NOT NULL REFERENCES core.customers(id),
  capability            ai_capability_enum NOT NULL,
  monthly_token_limit   BIGINT,
  daily_token_limit     BIGINT,
  per_call_token_limit  BIGINT,
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  effective_from        DATE NOT NULL,
  effective_to          DATE,
  created_by            UUID NOT NULL REFERENCES core.users(id),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_quota_policies__capability_period UNIQUE (customer_id, capability, effective_from)
);
CREATE INDEX idx_quota_policies__customer_cap ON usage.quota_policies(customer_id, capability)
  WHERE enabled;

CREATE TABLE usage.quota_alerts (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id             UUID NOT NULL,
  customer_id           UUID NOT NULL REFERENCES core.customers(id),
  capability            ai_capability_enum,
  alert_level           quota_alert_level_enum NOT NULL,
  period_start          DATE NOT NULL,
  used_tokens           BIGINT NOT NULL,
  limit_tokens          BIGINT NOT NULL,
  notification_sent     BOOLEAN NOT NULL DEFAULT FALSE,
  notification_channels TEXT[] NOT NULL DEFAULT '{}',
  occurred_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_quota_alerts__period_level UNIQUE (customer_id, capability, period_start, alert_level)
);
CREATE INDEX idx_quota_alerts__tenant_customer_time ON usage.quota_alerts(tenant_id, customer_id, occurred_at DESC);

COMMIT;
