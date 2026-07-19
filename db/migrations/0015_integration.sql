BEGIN;

CREATE TABLE integration.ticket_integrations (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id               UUID NOT NULL,
  customer_id             UUID NOT NULL REFERENCES core.customers(id) ON DELETE CASCADE,
  system                  ticket_system_enum NOT NULL,
  display_name            TEXT NOT NULL,
  api_base_url            TEXT,
  repo_full_name          TEXT,
  project_key             TEXT,
  oauth_token_ciphertext  BYTEA,
  api_token_ciphertext    BYTEA,
  webhook_secret_ciphertext BYTEA,
  event_mapping           JSONB NOT NULL DEFAULT '{}'::jsonb,
  default_labels          TEXT[] NOT NULL DEFAULT '{}',
  default_assignees       TEXT[] NOT NULL DEFAULT '{}',
  sync_direction          ticket_sync_direction_enum NOT NULL DEFAULT 'outbound_only',
  sync_state              BOOLEAN NOT NULL DEFAULT TRUE,
  enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
  last_sync_at            TIMESTAMPTZ,
  last_sync_status        sync_status_enum,
  last_sync_error         TEXT,
  created_by              UUID NOT NULL REFERENCES core.users(id),
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at              TIMESTAMPTZ
);
CREATE INDEX idx_ticket_integrations__customer ON integration.ticket_integrations(customer_id)
  WHERE deleted_at IS NULL AND enabled;
CREATE UNIQUE INDEX uq_ticket_integrations__customer_system ON integration.ticket_integrations(customer_id, system)
  WHERE deleted_at IS NULL;

COMMIT;
