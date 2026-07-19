#!/usr/bin/env bash
# scripts/healthcheck.sh
# security-vule 全栈健康检查 — 覆盖 Phase 1-3 所有关键 endpoint + DB 状态 + 哈希链触发器
#
# 用法:
#   ./scripts/healthcheck.sh                # 默认检查 localhost:3000
#   API_BASE=https://api.example.com ./scripts/healthcheck.sh
#   PG_CONTAINER=sv_prod_postgres ./scripts/healthcheck.sh

set -uo pipefail

API_BASE="${API_BASE:-http://localhost:3000}"
PG_CONTAINER="${PG_CONTAINER:-sv_prod_postgres}"
PG_USER="${PG_USER:-security_vule}"
PG_DB="${PG_DB:-security_vule}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass=0
fail=0
warn_count=0

ok()   { echo -e "  ${GREEN}✓${NC} $1"; pass=$((pass+1)); }
bad()  { echo -e "  ${RED}✗${NC} $1"; fail=$((fail+1)); }
note() { echo -e "  ${YELLOW}⚠${NC} $1"; warn_count=$((warn_count+1)); }
hdr()  { echo -e "\n${BLUE}[$1]${NC}"; }

http_status() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" 2>/dev/null || echo "000"
}

check_get() {
  local path="$1" expected_codes="$2" desc="$3"
  local code
  code=$(http_status "${API_BASE}${path}")
  if [[ "$expected_codes" == *"$code"* ]]; then
    ok "$code  $path  ($desc)"
  elif [[ "$code" == "000" ]]; then
    bad "$code  $path  ($desc) — API not reachable on ${API_BASE}"
  else
    bad "$code  $path  ($desc) — expected $expected_codes"
  fi
}

check_post() {
  local path="$1" expected_codes="$2" desc="$3" data="${4:-}"
  local code
  if [[ -n "$data" ]]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -X POST -H "Content-Type: application/json" \
      -d "$data" "${API_BASE}${path}" 2>/dev/null || echo "000")
  else
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -X POST "${API_BASE}${path}" 2>/dev/null || echo "000")
  fi
  if [[ "$expected_codes" == *"$code"* ]]; then
    ok "$code  POST $path  ($desc)"
  else
    bad "$code  POST $path  ($desc) — expected $expected_codes"
  fi
}

# ============================================================
# Phase 1 — Core
# ============================================================
hdr "Phase 1 — Core (DB schema + API skeleton)"

check_get "/api/health" "200" "API health"
check_post "/api/auth/login" "400 401" "auth login endpoint exists"
check_get "/api/auth/sso/metadata?tenant_id=default" "200" "SAML SP metadata (Phase 3A)"
check_get "/mock-idp" "200" "Mock SAML IdP (Phase 3A dev tool)"

# ============================================================
# Phase 2A — Validation/PoC engine
# ============================================================
hdr "Phase 2A — Validation (PoC generator + runner)"

check_get "/api/provider/v1/validation/queue" "401 403 200" "validation queue (auth required)"
check_post "/api/provider/v1/validation/run" "401 403 422" "validation run (auth required)" \
  '{"vulnType":"sqli","targetUrl":"http://localhost:8081"}'

# ============================================================
# Phase 2B — Detection engines/rules/policies
# ============================================================
hdr "Phase 2B — Detection engines/rules/policies"

check_get "/api/provider/v1/detection/engines" "401 403 200" "detection engines (auth required)"
check_get "/api/provider/v1/detection/rules" "401 403 200" "detection rules (auth required)"

# ============================================================
# Phase 2C — Customer portal routes
# ============================================================
hdr "Phase 2C — Customer portal"

check_get "/api/customer/v1/dashboard" "401 403 200" "customer dashboard (auth required)"
check_get "/api/customer/v1/projects" "401 403 200" "customer projects (auth required)"
check_get "/api/customer/v1/findings" "401 403 200" "customer findings (auth required)"

# ============================================================
# Phase 2D — Stripe billing
# ============================================================
hdr "Phase 2D — Stripe (mock)"

check_post "/api/provider/v1/billing/stripe/checkout" "401 403" "Stripe checkout session"
check_get "/api/provider/v1/billing/plans" "401 403 200" "Billing plans"

# ============================================================
# Phase 2E — Scan engine
# ============================================================
hdr "Phase 2E — Scan engine"

check_post "/api/provider/v1/scan/projects" "401 403" "Create scan project"
check_get "/api/provider/v1/scan/scans" "401 403 200" "List scans"

# ============================================================
# Phase 3A — SSO
# ============================================================
hdr "Phase 3A — SAML SSO"

check_get "/api/auth/sso/metadata?tenant_id=default" "200" "SP metadata XML"
check_get "/api/auth/sso/login?tenant_id=default" "200" "SP-initiated login redirect"
check_get "/mock-idp/sso?SAMLRequest=&RelayState=/" "400" "Mock IdP rejects empty SAMLRequest"

# ============================================================
# Phase 3B — Whitelabel
# ============================================================
hdr "Phase 3B — Whitelabel theming"

check_get "/api/customer/v1/whitelabel" "401 403 200" "Customer white-label (3-layer merge)"
check_get "/api/provider/v1/whitelabel" "401 403 200" "Provider white-label CRUD"

# ============================================================
# Phase 3C — Audit export + GDPR
# ============================================================
hdr "Phase 3C — Audit export + GDPR"

check_get "/api/provider/v1/governance/audit" "401 403 200" "audit log list (auth required)"
check_get "/api/provider/v1/governance/audit/export?format=json" "401 403 200" "audit export JSON"
check_get "/api/provider/v1/governance/audit/export?format=csv" "401 403 200" "audit export CSV"
check_get "/api/provider/v1/governance/audit/integrity" "401 403 200" "audit hash chain integrity"
check_get "/api/provider/v1/governance/gdpr/status" "401 403 200" "GDPR status"
check_post "/api/provider/v1/governance/gdpr/request" "401 403" "GDPR request"

# ============================================================
# DB state — schema + hash chain trigger + RLS
# ============================================================
hdr "DB state — schema + trigger + RLS"

if ! docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
  note "container ${PG_CONTAINER} not running; skipping DB checks"
else
  local_count() {
    docker exec "${PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" -tAc "$1" 2>/dev/null
  }

  table_count=$(local_count "SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('core','detection','poc','usage','billing','governance','integration','meta')")
  if [[ "$table_count" -ge 50 ]]; then
    ok "$table_count tables across 8 schemas (≥50 expected)"
  else
    bad "$table_count tables — expected ≥50"
  fi

  enum_count=$(local_count "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typcategory = 'E' AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')")
  if [[ "$enum_count" -ge 50 ]]; then
    ok "$enum_count enums in app schemas (≥50 expected)"
  else
    bad "$enum_count enums — expected ≥50"
  fi

  rls_count=$(local_count "SELECT count(*) FROM pg_tables WHERE schemaname IN ('core','detection','poc','usage','billing','governance','integration') AND rowsecurity = true")
  if [[ "$rls_count" -ge 30 ]]; then
    ok "$rls_count tables with RLS enabled (≥30 expected)"
  else
    note "$rls_count tables with RLS — check 0018_rls.sql"
  fi

  trigger_count=$(local_count "SELECT count(*) FROM pg_proc WHERE proname = 'tg_audit_log_sign'")
  if [[ "$trigger_count" -eq 1 ]]; then
    ok "hash chain trigger function governance.tg_audit_log_sign exists"
  else
    bad "trigger function tg_audit_log_sign missing (count=$trigger_count)"
  fi

  enabled=$(local_count "SELECT tgenabled FROM pg_trigger WHERE tgname = 'trg_audit_log_sign' AND tgrelid = 'governance.audit_logs'::regclass")
  if [[ "$enabled" == "O" ]]; then
    ok "trigger trg_audit_log_sign ENABLED on governance.audit_logs (O=origin)"
  else
    bad "trigger trg_audit_log_sign not enabled (tgenabled=$enabled)"
  fi

  audit_count=$(local_count "SELECT count(*) FROM governance.audit_logs")
  if [[ "$audit_count" -gt 0 ]]; then
    ok "audit_logs has $audit_count entries"
    ok "  → run scripts/verify-audit-chain.sh to check integrity"
  else
    note "audit_logs is empty — chain check not meaningful yet"
  fi
fi

# ============================================================
# Summary
# ============================================================
hdr "Summary"
total=$((pass + fail + warn_count))
echo -e "  ${GREEN}passed${NC}  $pass"
echo -e "  ${RED}failed${NC}  $fail"
echo -e "  ${YELLOW}warned${NC}  $warn_count"
echo -e "  total   $total"

if [[ $fail -gt 0 ]]; then
  echo ""
  echo -e "${RED}✗ healthcheck FAILED${NC}"
  exit 1
fi

echo ""
echo -e "${GREEN}✓ healthcheck passed${NC}"
exit 0