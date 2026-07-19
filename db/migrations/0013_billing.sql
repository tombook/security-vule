BEGIN;

CREATE TABLE billing.billing_accounts (
  id                      UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id               UUID NOT NULL REFERENCES core.tenants(id),
  customer_id             UUID NOT NULL UNIQUE REFERENCES core.customers(id),
  plan                    billing_plan_enum NOT NULL DEFAULT 'starter',
  monthly_token_quota     BIGINT NOT NULL DEFAULT 100000,
  overage_rate_usd_per_1k NUMERIC(10,6) NOT NULL DEFAULT 0.020,
  balance_usd             NUMERIC(12,2) NOT NULL DEFAULT 0,
  currency                CHAR(3) NOT NULL DEFAULT 'USD',
  status                  billing_status_enum NOT NULL DEFAULT 'active',
  current_period_start    DATE NOT NULL,
  current_period_end      DATE NOT NULL,
  auto_renew              BOOLEAN NOT NULL DEFAULT TRUE,
  payment_method_id       TEXT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE billing.plans (
  id                       UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  code                     plan_code_enum NOT NULL UNIQUE,
  display_name             TEXT NOT NULL,
  description              TEXT,
  monthly_token_quota      BIGINT,
  monthly_customer_limit   INT,
  monthly_project_limit    INT,
  overage_rate_usd_per_1k  NUMERIC(10,6) NOT NULL DEFAULT 0.020,
  price_usd                NUMERIC(12,2) NOT NULL DEFAULT 0,
  currency                 CHAR(3) NOT NULL DEFAULT 'USD',
  billing_period           billing_period_enum NOT NULL DEFAULT 'monthly',
  features                 JSONB NOT NULL DEFAULT '{}'::jsonb,
  status                   plan_status_enum NOT NULL DEFAULT 'active',
  effective_from           DATE NOT NULL,
  effective_to             DATE,
  is_public                BOOLEAN NOT NULL DEFAULT TRUE,
  display_order            INT NOT NULL DEFAULT 0,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_plans__active_public ON billing.plans(status, is_public, display_order)
  WHERE status = 'active';

CREATE TABLE billing.allocation_rules (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  billing_account_id UUID NOT NULL REFERENCES billing.billing_accounts(id),
  strategy          allocation_strategy_enum NOT NULL,
  flat_amount_usd   NUMERIC(12,2),
  custom_multiplier NUMERIC(6,3) NOT NULL DEFAULT 1.000,
  effective_from    DATE NOT NULL,
  effective_to      DATE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE billing.invoices (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id         UUID NOT NULL,
  customer_id       UUID NOT NULL REFERENCES core.customers(id),
  billing_account_id UUID NOT NULL REFERENCES billing.billing_accounts(id),
  invoice_number    TEXT NOT NULL UNIQUE,
  period_start      DATE NOT NULL,
  period_end        DATE NOT NULL,
  subtotal_usd      NUMERIC(12,2) NOT NULL,
  tax_usd           NUMERIC(12,2) NOT NULL DEFAULT 0,
  total_usd         NUMERIC(12,2) NOT NULL,
  status            invoice_status_enum NOT NULL DEFAULT 'draft',
  issued_at         TIMESTAMPTZ,
  due_at            TIMESTAMPTZ,
  paid_at           TIMESTAMPTZ,
  pdf_object_key    TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invoices__customer_period ON billing.invoices(customer_id, period_start DESC);

CREATE TABLE billing.invoice_line_items (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  invoice_id        UUID NOT NULL REFERENCES billing.invoices(id) ON DELETE CASCADE,
  description       TEXT NOT NULL,
  capability        ai_capability_enum,
  quantity          BIGINT NOT NULL,
  unit_price_usd    NUMERIC(10,6) NOT NULL,
  amount_usd        NUMERIC(12,2) NOT NULL,
  usage_event_ids   UUID[] NOT NULL DEFAULT '{}',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invoice_line_items__invoice ON billing.invoice_line_items(invoice_id);

COMMIT;
