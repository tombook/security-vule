-- 0023_ticket_sync_log.sql
-- Loop 4 协作闭环:工单集成同步记录

BEGIN;

DO $$ BEGIN
  CREATE TYPE ticket_sync_status_enum AS ENUM ('pending', 'success', 'failed', 'rate_limited');
EXCEPTION WHEN duplicate_object THEN null; END $$;

CREATE TABLE IF NOT EXISTS integration.ticket_sync_log (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id         UUID NOT NULL,
  customer_id       UUID NOT NULL,
  integration_id    UUID NOT NULL REFERENCES integration.ticket_integrations(id) ON DELETE CASCADE,
  finding_id        UUID NOT NULL REFERENCES detection.findings(id) ON DELETE CASCADE,
  external_ref      TEXT,
  direction         ticket_sync_direction_enum NOT NULL DEFAULT 'outbound_only',
  status            ticket_sync_status_enum NOT NULL DEFAULT 'pending',
  http_status       INT,
  response_body     TEXT,
  duration_ms       INT,
  error_message     TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ticket_sync__tenant_time
  ON integration.ticket_sync_log(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ticket_sync__finding
  ON integration.ticket_sync_log(finding_id);

CREATE INDEX IF NOT EXISTS idx_ticket_sync__integration
  ON integration.ticket_sync_log(integration_id, created_at DESC);

ALTER TABLE integration.ticket_sync_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY ticket_sync_log_tenant ON integration.ticket_sync_log
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE integration.ticket_sync_log IS
  '工单同步记录;出站/入站均记,失败可重试';

COMMIT;