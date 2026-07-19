#!/usr/bin/env bash
# scripts/verify-audit-chain.sh
# 校验 governance.audit_logs 哈希链完整性 — Phase 3D 交付
#
# 用法:
#   ./scripts/verify-audit-chain.sh                       # 检查所有 tenant
#   ./scripts/verify-audit-chain.sh <tenant_uuid>          # 检查单个 tenant
#   PG_CONTAINER=sv_prod_postgres ./scripts/verify-audit-chain.sh

set -uo pipefail

PG_CONTAINER="${PG_CONTAINER:-sv_prod_postgres}"
PG_USER="${PG_USER:-security_vule}"
PG_DB="${PG_DB:-security_vule}"
TARGET_TENANT="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if ! docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
  echo -e "${RED}ERROR${NC}: container ${PG_CONTAINER} not running"
  echo "  override with: PG_CONTAINER=sv_postgres $0"
  exit 2
fi

psql_q() {
  docker exec "${PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" -tAc "$1" 2>/dev/null
}

if [[ -n "$TARGET_TENANT" ]]; then
  tenant_filter="WHERE tenant_id = '$TARGET_TENANT'"
  echo -e "${BLUE}[verify-audit-chain]${NC} 单 tenant 模式: $TARGET_TENANT"
else
  tenant_filter=""
  echo -e "${BLUE}[verify-audit-chain]${NC} 全 tenant 模式"
fi

# Get all tenant_ids with audit_logs (or just the target)
tenants=()
if [[ -n "$TARGET_TENANT" ]]; then
  tenants=("$TARGET_TENANT")
else
  while IFS= read -r t; do
    [[ -n "$t" ]] && tenants+=("$t")
  done < <(psql_q "SELECT DISTINCT tenant_id FROM governance.audit_logs ORDER BY tenant_id")
fi

if [[ ${#tenants[@]} -eq 0 ]]; then
  echo -e "${YELLOW}⚠${NC} audit_logs 表为空,无 chain 可校验"
  exit 0
fi

total_entries=0
total_broken=0
tenant_results=()

for tenant in "${tenants[@]}"; do
  if [[ -z "$tenant" ]]; then
    continue
  fi

  count=$(psql_q "SELECT count(*) FROM governance.audit_logs WHERE tenant_id = '$tenant'")
  total_entries=$((total_entries + count))

  broken_count=$(psql_q "
    WITH ordered AS (
      SELECT id, occurred_at, prev_hash, entry_hash,
             lag(entry_hash) OVER (PARTITION BY tenant_id ORDER BY occurred_at, id) AS expected_prev,
             row_number() OVER (PARTITION BY tenant_id ORDER BY occurred_at, id) AS rn
      FROM governance.audit_logs
      WHERE tenant_id = '$tenant'
    )
    SELECT count(*) FROM ordered
    WHERE NOT (
      (rn = 1 AND prev_hash = decode(repeat('0', 64), 'hex'))
      OR (rn > 1 AND expected_prev IS NOT DISTINCT FROM prev_hash)
    )
  ")

  if [[ "$broken_count" -eq 0 ]]; then
    status="${GREEN}✓ Intact${NC}"
  else
    status="${RED}✗ BROKEN${NC} ($broken_count broken links)"
  fi

  tenant_results+=("$tenant | $count entries | $status")
  total_broken=$((total_broken + broken_count))
done

echo ""
echo "  Per-tenant results:"
echo ""
for r in "${tenant_results[@]}"; do
  echo "    $r"
done
echo ""

trigger_func=$(psql_q "SELECT count(*) FROM pg_proc WHERE proname = 'tg_audit_log_sign'")
trigger_status=$(psql_q "SELECT tgenabled FROM pg_trigger WHERE tgname = 'trg_audit_log_sign' AND tgrelid = 'governance.audit_logs'::regclass")

if [[ "$trigger_func" -eq 1 && "$trigger_status" == "O" ]]; then
  echo -e "  ${GREEN}✓${NC} trigger trg_audit_log_sign ENABLED on governance.audit_logs (auto-signing active)"
else
  echo -e "  ${RED}✗${NC} trigger not enabled (func=$trigger_func, status=$trigger_status)"
fi

echo ""
echo "  Total entries: $total_entries"
echo "  Total broken:  $total_broken"
echo ""

if [[ $total_broken -gt 0 ]]; then
  echo -e "${RED}✗ Chain integrity FAILED${NC}"
  echo ""
  echo "  Possible causes:"
  echo "    1. Direct INSERT/UPDATE bypassed the trigger (bypass RLS + role)"
  echo "    2. Database was restored from a backup that does not match canonical order"
  echo "    3. The trigger function definition was changed mid-deployment (avoid!)"
  echo ""
  echo "  Suggested actions:"
  echo "    - Run scripts/verify-audit-chain.sh to localize the broken row"
  echo "    - Query broken rows:"
  echo "      SELECT id, occurred_at, encode(prev_hash, 'hex'), encode(entry_hash, 'hex')"
  echo "      FROM governance.audit_logs ORDER BY occurred_at LIMIT 50"
  exit 1
fi

echo -e "${GREEN}✓ Chain integrity verified${NC}"
exit 0