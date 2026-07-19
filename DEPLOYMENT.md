# security-vule 生产部署指南

> 适用版本: v0.2.0 · 最后更新: 2026-06-26

本指南描述 security-vule **MSSP 平台** (Phase 1-3 + 3F 部署整合) 的生产部署方法。
覆盖内容: 数据库 schema (19 migrations + 1 trigger)、API、Vue 3 前端、SAML SSO、Stripe 集成、白标、审计导出、GDPR、哈希链审计、nginx 反代。

---

## 1. 系统概览

### 1.1 部署的 Phase 列表

| Phase | 功能 | 关键端点 |
|---|---|---|
| **1** | 核心 schema (55 张表 + 56 枚举 + 43 RLS) | `/api/auth`, `/api/provider/v1/*`, `/api/customer/v1/*` |
| **2A** | PoC 护城河 (generator + runner + 验证队列) | `/api/provider/v1/validation/*` |
| **2B** | Provider 剩余页 (5 路由) | `/api/provider/v1/{detection,settings}/*` |
| **2C** | Customer 8 页 (深蓝色 portal) | `/api/customer/v1/*` |
| **2D** | Stripe (mock + 真切换路径) | `/api/provider/v1/billing/stripe/*` |
| **2E** | 扫描引擎 (项目/源/扫描触发) | `/api/provider/v1/scan/*` |
| **3A** | SAML SSO + Mock IdP (开发) | `/api/auth/sso/*`, `/mock-idp` |
| **3B** | 白标定制 (3 层 theme 合并) | `/api/{customer,provider}/v1/whitelabel` |
| **3C** | 审计导出 (JSON+CSV+完整性) + GDPR (30 天恢复) | `/api/provider/v1/governance/{audit,gdpr}/*` |
| **3D** | 哈希链触发器 (BEFORE INSERT, 自动签名) | `governance.audit_logs` 上 `trg_audit_log_sign` |
| **3F** | 生产部署 (本文档) | `docker-compose.prod.yml` + 4 个脚本 |

### 1.2 服务拓扑

```
                          ┌─────────────────────┐
                          │   nginx (:80/:443)  │  ← TLS + reverse proxy
                          └──────────┬──────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
       ┌─────────────┐      ┌─────────────────┐    ┌────────────┐
       │ Web (:5173) │      │  API (:3000)     │    │ 其它直连   │
       │ Vue 3 + Vite│      │ Hono + Drizzle   │    │ Stripe     │
       └─────────────┘      └────────┬─────────┘    └────────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
              ┌─────────────────┐       ┌─────────────────┐
              │ Postgres (:5432)│       │  Redis (:6379)  │
              │ 19 migrations   │       │ 限流 + 缓存     │
              │ + hash chain trg │       └─────────────────┘
              └─────────────────┘
```

### 1.3 资源占用 (建议基线)

| 服务 | CPU limit | Memory limit | 磁盘 |
|---|---|---|---|
| postgres | 1.5 | 2 GB | 100 GB+ (audit_logs 增长) |
| redis | 0.5 | 384 MB | 1 GB |
| api | 1.0 | 768 MB | - |
| web | 0.5 | 512 MB | - |
| nginx | 0.3 | 128 MB | - |
| **合计** | **3.8** | **~4 GB** | **~100 GB** |

---

## 2. 前置条件

### 2.1 主机要求

- **OS**: Linux (Ubuntu 22.04+ / Debian 12+) 或 macOS 13+ (开发/测试)
- **Docker**: 24.0+, Docker Compose v2 (即 `docker compose` 子命令)
- **CPU**: 4 核+ (生产建议 8 核+)
- **内存**: 8 GB+ (生产建议 16 GB+)
- **磁盘**: 100 GB+ SSD
- **网络**: 公网入站 80/443; 出站 HTTPS (Stripe / SMTP / SAML)

### 2.2 域名与证书

- 准备两个域名: `app.example.com` (前端) 和 `api.example.com` (API)
- TLS 证书 (`fullchain.pem` + `privkey.pem`) 放在 `./certs/`
- 若使用 Let's Encrypt: `certbot certonly --standalone -d app.example.com -d api.example.com`

### 2.3 必须准备的 secrets

`./secrets/` 目录 (脚本会校验) 需要 5 个文件,全部 chmod 600:

```bash
mkdir -p secrets
chmod 700 secrets

# 1. DB 密码 (32 字节 hex)
openssl rand -hex 32 > secrets/db_password.txt

# 2. JWT 签名密钥 (32 字节 hex)
openssl rand -hex 32 > secrets/jwt_secret.txt

# 3. SAML IdP 私钥 (RSA-2048 PEM, 真实部署从 IdP 导出)
openssl genrsa -out secrets/saml_idp_key.pem 2048

# 4. SAML webhook 签名密钥 (任意长度 hex)
openssl rand -hex 32 > secrets/saml_webhook_secret.txt

# 5. Stripe webhook 签名密钥 (Stripe Dashboard → Webhooks → Signing secret)
echo "whsec_xxxx" > secrets/stripe_webhook_secret.txt
```

> **警告**: `secrets/` 目录绝不能提交到 git;确保 `.gitignore` 包含该目录。

---

## 3. 一键部署

### 3.1 完整流程

```bash
# 1. 克隆代码
git clone https://github.com/security-vule/security-vule.git
cd security-vule

# 2. 编辑环境变量
cp .env.production.example .env.production
$EDITOR .env.production   # 改 FRONTEND_URL, VITE_API_BASE, STRIPE_MODE 等

# 3. 准备 secrets (见 §2.3)
mkdir -p secrets && cd secrets
  openssl rand -hex 32 > db_password.txt
  openssl rand -hex 32 > jwt_secret.txt
  openssl genrsa -out saml_idp_key.pem 2048
  openssl rand -hex 32 > saml_webhook_secret.txt
  echo "whsec_xxxx" > stripe_webhook_secret.txt
cd .. && chmod 600 secrets/*

# 4. nginx 反代配置 (见 §6)
cp nginx.conf.example nginx.conf  # 或从仓库示例拷贝
$EDITOR nginx.conf               # 改 server_name 与证书路径

# 5. 一键部署
chmod +x scripts/deploy.sh
./scripts/deploy.sh

# 6. 验证
./scripts/healthcheck.sh
./scripts/verify-audit-chain.sh
```

### 3.2 deploy.sh 子命令

```bash
./scripts/deploy.sh preflight   # 仅检查前置条件
./scripts/deploy.sh build       # 构建镜像
./scripts/deploy.sh infra       # 启动 postgres + redis
./scripts/deploy.sh migrate     # 应用 migrations
./scripts/deploy.sh seed        # 灌入种子数据
./scripts/deploy.sh services    # 启动 api + web + nginx
./scripts/deploy.sh restart     # 重启 api + web (不停 DB)
./scripts/deploy.sh health      # 仅跑 healthcheck
./scripts/deploy.sh             # 全部 (默认)
```

---

## 4. 数据库 Schema

### 4.1 Migrations 清单 (20 个)

```
0000_extensions.sql              -- pgcrypto, uuid-ossp
0001_enums_core.sql              -- 用户/客户/订阅相关枚举
0002_enums_detection.sql         -- 检测引擎/规则枚举
0003_enums_poc.sql               -- PoC 类型/状态枚举
0004_enums_usage_billing.sql     -- 用量/计费枚举
0005_enums_governance.sql        -- 审计/通知枚举
0006_enums_v2.sql                -- 二期枚举
0007_schemas.sql                 -- 8 个 schema 容器
0008_core_identity.sql           -- tenants, users, sessions
0009_core_business.sql           -- customers, projects
0010_detection.sql               -- engines, rules, policies
0011_poc.sql                     -- PoC 模板与运行记录
0012_usage.sql                   -- LLM 用量追踪
0013_billing.sql                 -- 订阅、发票、配额
0014_governance.sql              -- 审计 + 通知 + webhook + GDPR
0015_integration.sql             -- 第三方集成
0016_meta.sql                    -- app_settings, schema_migrations
0017_alter_users_notification.sql
0018_rls.sql                     -- 行级安全策略
0019_audit_hash_chain_trigger.sql -- 哈希链自动签名 (Phase 3D)
```

### 4.2 哈希链 (Phase 3D)

`governance.audit_logs` 表上 BEFORE INSERT 触发器自动:
- 查找同 tenant 最新 `entry_hash` 作为 `prev_hash` (创世行用 32 字节全 0)
- 拼接 canonical bytes (字段间用 `\x1f` 分隔)
- 计算 `entry_hash = sha256(prev_hash || canonical)`
- 写回 NEW 行

**校验工具**: `scripts/verify-audit-chain.sh` 遍历所有 tenant,确认每行 `prev_hash = 上一行 entry_hash`,**创世行 `prev_hash = 全 0`**。

```bash
$ ./scripts/verify-audit-chain.sh
[verify-audit-chain] 全 tenant 模式

  Per-tenant results:
    00000000-...-001 | 3 entries | ✓ Intact

  ✓ trigger trg_audit_log_sign ENABLED on governance.audit_logs (auto-signing active)
  ✓ Chain integrity verified
```

### 4.3 Migration 漂移检测

`scripts/migrate.ts` 用 SHA-256 校验文件 checksum;**已应用的 migration 不可修改**(会报 DRIFT 错误)。如需改 schema,新增 0020_xxx.sql。

```bash
$ bun run scripts/migrate.ts --status
[schema_migrations] 19 applied, 19 on disk
  ✓ 0000_extensions.sql
  ...
  ⚠ DRIFT  0014_governance.sql
      on-disk:    a1b2c3d4...
      in DB:      9z9z9z9z...
      applied at: 2026-06-15 03:00:00
```

---

## 5. 集成功能

### 5.1 SAML SSO (Phase 3A)

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/auth/sso/metadata?tenant_id=<uuid>` | GET | SP 元数据 XML (给 IdP 配) |
| `/api/auth/sso/login?tenant_id=<uuid>&relay_state=/` | GET | SP-initiated 登录(自动重定向到 IdP) |
| `/api/auth/sso/acs` | POST | Assertion Consumer Service (IdP SAMLResponse 回调) |
| `/api/provider/v1/sso/config/:tenantId` | GET/PUT | Provider 端 SSO 配置 CRUD |
| `/mock-idp` | GET | **仅开发环境**:自签 SAML IdP |

**生产切换到真 IdP**:
1. 关闭 nginx.conf 中对 `/mock-idp` 的代理(或只允许内网访问)
2. 在 `core.tenants.sso_config` 写入 `idpEntityId`, `idpSsoUrl`, `idpPublicKey` (PEM)
3. 测试: `curl https://api.example.com/api/auth/sso/metadata?tenant_id=<uuid>`

### 5.2 Stripe (Phase 2D)

默认 `STRIPE_MODE=mock` 跑本地假支付;**真切换**:

1. 在 Stripe Dashboard 创建 products + prices
2. 设 `STRIPE_MODE=real`, `STRIPE_SECRET_KEY=sk_live_xxx`
3. 在 Stripe Dashboard 创建 webhook 端点 `https://api.example.com/api/provider/v1/billing/stripe/webhook`
4. 把 signing secret 写入 `secrets/stripe_webhook_secret.txt`
5. 修改 `apps/api/src/services/stripe.ts` 的构造函数,改为 `new Stripe(secretKey)`

### 5.3 白标 (Phase 3B)

3 层 theme 合并:**DEFAULT → tenant.theme → customer.theme**。
- Provider 改自己主题: `PUT /api/provider/v1/whitelabel` (需 ProviderOwner 角色)
- Customer 改自己主题: `PUT /api/customer/v1/whitelabel`
- 客户看到的最终主题: `GET /api/customer/v1/whitelabel`

### 5.4 GDPR (Phase 3C)

- **30 天保留**: GDPR delete request 30 天内可恢复
- **导出**:`POST /api/provider/v1/governance/gdpr/request` (type=`tenant_full_export` 或 `customer_export`)
- **下载**:`GET /api/provider/v1/governance/gdpr/download/:exportId`
- **流式**:`GET /api/provider/v1/governance/gdpr/file/:exportId`
- **状态**:`GET /api/provider/v1/governance/gdpr/status`

---

## 6. nginx 反代

`./nginx.conf` 必须存在;**最小可用模板**:

```nginx
events { worker_connections 1024; }

http {
  upstream api_upstream { server sv_prod_api:3000; }
  upstream web_upstream { server sv_prod_web:5173; }

  server {
    listen 80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
  }

  server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    client_max_body_size 50M;

    location / {
      proxy_pass http://api_upstream;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }

  server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
      proxy_pass http://web_upstream;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
    }
  }
}
```

---

## 7. 持久化与备份

### 7.1 数据卷

| 卷名 | 内容 | 备份频率 |
|---|---|---|
| `sv_prod_pgdata` | Postgres 数据 | 每天 |
| `sv_prod_redisdata` | Redis 持久化 (AOF) | 不必单独备份(可重建) |

### 7.2 备份脚本示例

```bash
#!/usr/bin/env bash
# scripts/backup.sh - 每日备份
set -euo pipefail
BACKUP_DIR=/var/backups/security-vule
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

docker exec sv_prod_postgres pg_dump -U security_vule -d security_vule \
  --format=custom --compress=9 \
  > "$BACKUP_DIR/sv_${DATE}.dump"

# 保留 30 天
find "$BACKUP_DIR" -name "sv_*.dump" -mtime +30 -delete
```

### 7.3 恢复

```bash
# 停 API 防并发写入
docker compose -f docker-compose.prod.yml stop api web

# 恢复
cat /var/backups/security-vule/sv_20260620_030000.dump | \
  docker exec -i sv_prod_postgres pg_restore -U security_vule -d security_vule --clean --if-exists

# 验证
./scripts/healthcheck.sh
./scripts/verify-audit-chain.sh

# 启动
docker compose -f docker-compose.prod.yml start api web
```

---

## 8. 监控与日志

### 8.1 日志

所有服务用 `json-file` driver,最大 20 MB × 5 文件:

```bash
docker compose -f docker-compose.prod.yml logs -f --tail=100 api
```

### 8.2 关键指标

| 指标 | 阈值 | 查询 |
|---|---|---|
| API 错误率 | < 0.5% | 看 `X-Response-Time` header |
| DB 连接数 | < 150 (max 200) | `pg_stat_activity` |
| audit_logs 增长 | 监控周环比 | 每日 `count(*)` 写监控 |
| 哈希链破损 | 必须为 0 | `verify-audit-chain.sh` |
| 磁盘使用 | < 80% | `df -h /var/lib/docker` |

### 8.3 升级

```bash
git pull
docker compose -f docker-compose.prod.yml build --pull api web
docker compose -f docker-compose.prod.yml up -d --force-recreate api web
docker exec -e DATABASE_URL=... sv_prod_postgres ... bun run scripts/migrate.ts
./scripts/healthcheck.sh
```

---

## 9. 故障排查

| 现象 | 排查命令 | 修复 |
|---|---|---|
| API 502 | `docker compose logs api` | 检查 `DATABASE_URL` 与 `JWT_SECRET_FILE` |
| 健康检查 401/403 | 检查是否在 nginx 后面用 `https://` 而非 `http://` | 改 VITE_API_BASE |
| Migration 漂移 | `bun run scripts/migrate.ts` | 修改是新增 0020,而非改 0014 |
| 哈希链破损 | `verify-audit-chain.sh` | 找到破损行,确认是否人为 DELETE 触发 |
| 端口冲突 5433 | `lsof -i :5433` | 改 `docker-compose.prod.yml` 端口 |
| SAML 签名错误 | `apps/api/src/services/saml.ts` | IdP 私钥与 SP 公钥不匹配 → 重导 |

---

## 10. 安全检查清单 (部署前必过)

- [ ] `secrets/*` 全部 `chmod 600`,`secrets/` 目录 `chmod 700`
- [ ] `secrets/` 加入 `.gitignore`
- [ ] `.env.production` 排除 `__CHANGE_ME__` 占位符
- [ ] `nginx.conf` 强制 HTTPS 301
- [ ] TLS 证书链完整 (`fullchain.pem` + `privkey.pem`)
- [ ] Postgres 仅监听内网(不暴露 5432 到 0.0.0.0)
- [ ] `STRIPE_MODE=mock` 时禁外网回调
- [ ] `JWT_SECRET` ≥ 32 字节随机
- [ ] DB 用户 `security_vule` 仅有 `INSERT/UPDATE/SELECT` on `governance.audit_logs`(无 DELETE)
- [ ] `verify-audit-chain.sh` 输出 `✓ Intact`
- [ ] `healthcheck.sh` 输出 `✓ healthcheck passed`

---

## 11. 支持与联系

- **文档**: `docs/` 目录
- **设计 spec**: `docs/superpowers/specs/2026-06-24-mssp-platform-redesign-design.md` (6,439 行)
- **CLI 文档**: `docs/cli-reference.md`
- **审计 CLI**: `bun run src/cli.ts audit verify`

---

## 12. 版本历史

- **v0.2.0** (2026-06-26): Phase 1-3 全功能 + 3F 生产部署整合
  - 19 migrations + 1 trigger (0019_audit_hash_chain_trigger)
  - SAML SSO + Mock IdP
  - 白标 3 层合并
  - 审计 JSON+CSV 导出 + 完整性校验
  - GDPR 30 天保留 + 导出/删除
  - Stripe mock + 真切换路径
  - Hash chain 自动签名触发器
  - 一键 deploy + healthcheck + verify-audit-chain