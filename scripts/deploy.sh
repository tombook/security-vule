#!/usr/bin/env bash
# scripts/deploy.sh
# security-vule 一键生产部署脚本
#
# 前置条件:
#   1. cp .env.production.example .env.production 并填值
#   2. mkdir -p secrets && 创建 db_password.txt, jwt_secret.txt,
#      saml_idp_key.pem, saml_webhook_secret.txt, stripe_webhook_secret.txt
#   3. docker compose 已安装,host 可访问 Docker daemon
#
# 用法:
#   ./scripts/deploy.sh           # 完整部署 (默认)
#   ./scripts/deploy.sh migrate   # 只跑 migration
#   ./scripts/deploy.sh restart   # 重启 API + Web
#   ./scripts/deploy.sh health    # 只跑 healthcheck

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.prod.yml"
ENV_FILE="${PROJECT_ROOT}/.env.production"
SECRETS_DIR="${PROJECT_ROOT}/secrets"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[deploy]${NC} $*"; }
warn() { echo -e "${YELLOW}[deploy]${NC} $*"; }
err() { echo -e "${RED}[deploy]${NC} $*" >&2; }

# ============================================================
# Preflight checks
# ============================================================
preflight() {
  log "Step 0/7 — Preflight checks"

  local missing=0
  for cmd in docker docker compose openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      err "  ✗ missing required command: $cmd"
      missing=1
    fi
  done

  if [[ ! -f "${COMPOSE_FILE}" ]]; then
    err "  ✗ docker-compose.prod.yml not found at ${COMPOSE_FILE}"
    missing=1
  fi

  if [[ ! -f "${ENV_FILE}" ]]; then
    err "  ✗ .env.production not found at ${ENV_FILE}"
    err "    → cp .env.production.example .env.production && 编辑填值"
    missing=1
  fi

  local required_secrets=(db_password.txt jwt_secret.txt saml_idp_key.pem saml_webhook_secret.txt stripe_webhook_secret.txt)
  for s in "${required_secrets[@]}"; do
    if [[ ! -f "${SECRETS_DIR}/${s}" ]]; then
      err "  ✗ secrets/${s} missing"
      missing=1
    else
      local size
      size=$(wc -c < "${SECRETS_DIR}/${s}")
      if [[ "$size" -lt 16 ]]; then
        err "  ✗ secrets/${s} too small (${size} bytes; minimum 16)"
        missing=1
      else
        log "  ✓ secrets/${s} (${size} bytes)"
      fi
    fi
  done

  if [[ ! -f "${PROJECT_ROOT}/nginx.conf" ]]; then
    warn "  ⚠ nginx.conf not found — Phase 3F.7 阶段补全;当前 nginx 容器无法启动"
  fi

  if [[ $missing -ne 0 ]]; then
    err "Preflight FAILED; please fix above and retry"
    exit 1
  fi

  # Protect secrets
  chmod 600 "${SECRETS_DIR}"/*.{txt,pem} 2>/dev/null || true
  log "✓ preflight passed"
}

# ============================================================
# Build images (compose pull + build)
# ============================================================
build() {
  log "Step 1/7 — Building images"
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" build --pull
  log "✓ build complete"
}

# ============================================================
# Bring up infra (postgres + redis) and wait healthy
# ============================================================
infra() {
  log "Step 2/7 — Starting infrastructure (postgres + redis)"
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d postgres redis

  log "  waiting for postgres healthy..."
  local i=0
  while [[ $i -lt 60 ]]; do
    if docker exec sv_prod_postgres pg_isready -U security_vule -d security_vule >/dev/null 2>&1; then
      log "  ✓ postgres ready"
      break
    fi
    sleep 2
    i=$((i+1))
  done
  if [[ $i -eq 60 ]]; then
    err "postgres failed to become healthy in 120s"
    exit 1
  fi

  log "  waiting for redis healthy..."
  i=0
  while [[ $i -lt 30 ]]; do
    if docker exec sv_prod_redis redis-cli ping | grep -q PONG; then
      log "  ✓ redis ready"
      break
    fi
    sleep 1
    i=$((i+1))
  done
  if [[ $i -eq 30 ]]; then
    err "redis failed to become healthy in 30s"
    exit 1
  fi
}

# ============================================================
# Apply migrations
# ============================================================
migrate() {
  log "Step 3/7 — Applying database migrations"
  local db_pwd
  db_pwd="$(cat "${SECRETS_DIR}/db_password.txt")"
  docker run --rm \
    --network "$(basename "${PROJECT_ROOT}")_default" \
    -v "${PROJECT_ROOT}:/app:ro" \
    -e DATABASE_URL="postgresql://security_vule:${db_pwd}@sv_prod_postgres:5432/security_vule" \
    -w /app \
    oven/bun:1.1.30-alpine \
    bun run scripts/migrate.ts
  log "✓ migrations applied"
}

# ============================================================
# Seed initial data (idempotent, safe to re-run)
# ============================================================
seed() {
  log "Step 4/7 — Seeding initial data"
  local db_pwd
  db_pwd="$(cat "${SECRETS_DIR}/db_password.txt")"
  docker run --rm \
    --network "$(basename "${PROJECT_ROOT}")_default" \
    -v "${PROJECT_ROOT}:/app:ro" \
    -e DATABASE_URL="postgresql://security_vule:${db_pwd}@sv_prod_postgres:5432/security_vule" \
    -w /app \
    oven/bun:1.1.30-alpine \
    bun run apps/api/src/db/seed.ts || warn "seed skipped (already seeded?)"
  log "✓ seed complete"
}

# ============================================================
# Bring up services (api + web + nginx)
# ============================================================
services() {
  log "Step 5/7 — Starting API + Web + nginx"
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d api web nginx

  log "  waiting for API healthy..."
  local i=0
  while [[ $i -lt 60 ]]; do
    if curl -fsS http://localhost:3000/api/health >/dev/null 2>&1; then
      log "  ✓ api healthy"
      break
    fi
    sleep 2
    i=$((i+1))
  done
  if [[ $i -eq 60 ]]; then
    err "api failed to become healthy in 120s"
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" logs --tail=100 api
    exit 1
  fi

  log "  waiting for Web healthy..."
  i=0
  while [[ $i -lt 90 ]]; do
    if curl -fsS http://localhost:5173/ >/dev/null 2>&1; then
      log "  ✓ web healthy"
      break
    fi
    sleep 2
    i=$((i+1))
  done
  if [[ $i -eq 90 ]]; then
    warn "  web did not respond on :5173 within 180s — check logs"
  fi
}

# ============================================================
# Restart API + Web (without dropping DB)
# ============================================================
restart() {
  log "Restart — bouncing api + web"
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d --force-recreate api web
  sleep 5
  curl -fsS http://localhost:3000/api/health >/dev/null
  log "✓ api restarted and healthy"
}

# ============================================================
# Run full healthcheck
# ============================================================
health() {
  log "Step 6/7 — Running healthchecks"
  "${SCRIPT_DIR}/healthcheck.sh"
}

# ============================================================
# Summary
# ============================================================
summary() {
  log "Step 7/7 — Deployment complete"
  echo ""
  echo "  API:    http://localhost:3000/api/health"
  echo "  Web:    http://localhost:5173/"
  echo "  Audit:  ./scripts/verify-audit-chain.sh"
  echo ""
  echo "  后续:"
  echo "    docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} logs -f api"
  echo "    docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} ps"
}

# ============================================================
# Main dispatcher
# ============================================================
case "${1:-all}" in
  preflight) preflight ;;
  build) build ;;
  infra) infra ;;
  migrate) preflight && infra && migrate ;;
  seed) seed ;;
  services) services ;;
  restart) restart ;;
  health) health ;;
  all|"") preflight && build && infra && migrate && seed && services && health && summary ;;
  *)
    err "Unknown subcommand: $1"
    echo "Usage: $0 [preflight|build|infra|migrate|seed|services|restart|health|all]"
    exit 1
    ;;
esac