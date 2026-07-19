# 多租户多用户功能测试方案(MSSP 平台)

> **状态**: v1.0-draft
> **日期**: 2026-06-27
> **基于设计文档**: `docs/superpowers/specs/2026-06-24-mssp-platform-redesign-design.md`(v1.0-draft,6439 行)
> **对接代码库**: `apps/api`(Hono on Bun)、`apps/web`(Vue 3 + Element Plus)
> **对接现有测试资产**:
> - `tests/integration/multi_tenant_isolation.test.ts`(MT-01..10 + RLS-01..10 + MTI-01..04,414 行)
> - `tests/integration/rbac_matrix.test.ts`(12 × 7 = 84 + 6 × 7 = 42 = 126 cells)
> - `tests/helpers/{db,auth,seed,api}.ts`(392 行基础设施)

---

## 0. 文档元信息

| 项 | 内容 |
|---|---|
| 文档类型 | 测试方案(Test Plan) |
| 测试目标 | 验证设计文档 §1.3 双门户、§1.4 三层实体、§1.5 RBAC 7 角色、§2.8 多租户隔离、§13.3 RLS 等多租户/多用户能力的功能正确性与安全兜底 |
| 测试层级 | 单元 → 集成(DB+API) → E2E → 安全 → 性能 |
| 主框架 | Bun Test(现有)+ Playwright(新增,E2E) |
| 关联规范 | 决策 #1(MSSP)、#6(纯 SaaS 多租户)、#2(双门户) |

---

## 1. 测试目标(Test Objectives)

### 1.1 功能目标

| ID | 目标 | 验收度量 |
|---|---|---|
| **OBJ-1** | 双门户账号体系隔离:服务商门户账号(`portal='provider'`)无法登录客户门户,反之亦然 | 跨门户登录 100% 拒绝,返回 401/403,审计记录 |
| **OBJ-2** | 跨租户隔离:`tenant_id` 在 DB 层、应用层、UI 层均强制隔离 | 任意 8 种跨租户访问场景读/写/改/删全部 0 行影响 |
| **OBJ-3** | 跨客户隔离:同租户下客户 A 不可见/不可改客户 B 的任何资源 | 12 种核心资源 7 角色访问全部符合 RBAC 矩阵 |
| **OBJ-4** | RBAC 7 角色权限矩阵严格落地(见 §1.5) | 126 cells 全绿,无 allow/deny 偏差 |
| **OBJ-5** | 越权防护:任何 API 携带不属于当前 tenant/customer 的 resource id,统一返回 **404**(避免泄露资源存在性) | 所有 404 用例命中,无 403 与 404 混用导致存在性泄露 |
| **OBJ-6** | 审计兜底:任何跨租户/跨客户越权尝试、敏感操作均落入 `governance.audit_logs` 且哈希链完整 | `audit verify` 通过,无断链 |
| **OBJ-7** | 客户门户硬隔离:客户用户 JWT 内嵌 `customer_id`,查询自动命中本人 customer 域 | 跨 customer API 调用 100% 返回 0 行或 404 |
| **OBJ-8** | 双层防护(应用层中间件 + DB RLS 兜底)即使代码漏写 `WHERE` 也安全 | 故意构造无过滤 SQL 经 RLS 后返回 0 行 |

### 1.2 安全目标

| ID | 目标 | 验收度量 |
|---|---|---|
| **SEC-1** | JWT 鉴权:签名、过期、租户绑定、角色绑定、跨门户拒签 | 篡改、过期、跨租户绑定全部 401 |
| **SEC-2** | 密码策略:bcrypt cost=12、长度 ≥10、含大小写+数字、失败 5 次锁定 15min | 弱口令拒绝、暴力破解锁定、风控触发 |
| **SEC-3** | 凭证安全:客户 GitHub/GitLab Token KMS 加密存储,API 层绝不返回明文 | API 响应无明文 token;KMS 字段在 DB 中只见密文 |
| **SEC-4** | 软删除合规:客户/项目软删除保留 90/30 天可恢复,数据可导出 | 软删除后 90 天内可恢复;导出 JSON/CSV 含完整审计链 |
| **SEC-5** | 哈希链审计:任何 `audit_logs` 写入触发 SHA-256(prev‖canonical) | `audit verify` CLI 100% 通过,篡改后立即可检测 |

### 1.3 非功能目标

| ID | 目标 | 验收度量 |
|---|---|---|
| **NFR-1** | 性能:每客户 50+ ev/s 写入,单查询 P95 < 100ms(分页/聚合/时间范围) | k6 压测达标 |
| **NFR-2** | 并发隔离:单客户突发 100 并发扫描不影响其他客户队列 | 调度器限流生效,无队列积压到全局 |
| **NFR-3** | 可观测:每次越权、登录、Token 解密均有结构化审计 + 告警 | 关键事件 100% 入库,延迟 < 5s |

---

## 2. 测试范围(Scope)

### 2.1 In Scope(对应设计文档章节)

| 章节 | 测试范围 | 优先级 |
|---|---|---|
| **§1.4 三层实体模型** | Provider → Customer → Project → Source 层级关系、唯一性、引用完整性 | P0 |
| **§1.5 + §2.9 RBAC 矩阵** | 7 角色 × 30+ 资源/动作矩阵全覆盖 | P0 |
| **§2 身份与组织** | 服务商入驻、登录、会话、密码、邀请、团队管理、客户组织、RBAC、审计 | P0 |
| **§2.8 + §13.3 多租户隔离** | 应用层中间件 + DB RLS 双层防护,跨租户/跨客户拒绝 | P0 |
| **§3 接入客户与代码源** | 项目创建(快创+详配)、GitHub/GitLab/上传连接器、快照、状态机 | P1 |
| **§4 持续白盒漏洞挖掘** | 主动拉取、CI/CD 门控、检测引擎、策略配置、快照、调度 | P1 |
| **§5 AI 辅助 PoC 验证** | PoC 生成、沙箱执行、利用证明、预算闸 | P2(依赖阶段 2) |
| **§6 结果处理与协作** | Finding 状态机、Triage、报告、协作、状态流转 | P1 |
| **§7 计费与用量** | 套餐、用量事件、账单、成本分摊、预算预警 | P1 |
| **§8 客户门户** | 客户 IA、成员管理、只读浏览、白标 | P1 |
| **§9 治理与合规** | 审计日志、权限治理、软删除、可观测 | P0 |
| **§13 PostgreSQL** | RLS 策略、分区、KMS、哈希链 | P0 |

### 2.2 Out of Scope(对应设计文档明确推迟)

| 章节 | 排除原因 |
|---|---|
| **§1.6 / §11 SSO/SAML + 2FA** | 阶段 3 才上线,MVP 不含 |
| **§1.6 / §11 白标(自定义域名/品牌色全替换)** | 阶段 3 才上线 |
| **§5 AI PoC 生成(LLM 调用)** | 阶段 2 才上线,只测"按钮灰化 + 手动上传 PoC"路径 |
| **§1.10 引擎层自定义实现(DFG 自研)** | 集成测试只验调度/产出,DFG 自身走单独 spec |

---

## 3. 测试策略(Test Strategy)

### 3.1 分层测试

```
                       ┌──────────────┐
                       │   E2E (P2)   │ Playwright:双门户完整旅程
                       └──────┬───────┘
                              │
                ┌─────────────┴─────────────┐
                │   API 集成 (P0-P1)         │ Bun Test + fetch/axios:端到端 HTTP 调用
                └─────────────┬─────────────┘
                              │
                ┌─────────────┴─────────────┐
                │   DB 集成 (P0)             │ Bun Test + pg:直接 SQL 验 RLS/约束
                └─────────────┬─────────────┘
                              │
                ┌─────────────┴─────────────┐
                │   单元 (P0-P2)             │ Bun Test:纯函数、校验器、序列化
                └────────────────────────────┘
```

### 3.2 测试金字塔分布(目标)

| 层级 | 用例数目标 | 执行时长目标 | 触发频率 |
|---|---|---|---|
| 单元 | 200+ | < 30s | 每次 commit |
| DB 集成 | 80+ | < 60s | 每次 commit |
| API 集成 | 150+ | < 120s | 每次 PR |
| E2E | 30+ | < 5min | 每次 release / nightly |
| 安全/渗透 | 20+ | 手动 + 自动 | 每次 release |

### 3.3 测试隔离原则

1. **每 test 独立 tenant**:避免 RLS 跨测试相互污染(沿用现有 `TENANT_A` / `TENANT_B` 模式)
2. **truncateAll in beforeAll**:保证测试运行幂等(已有模式)
3. **JWT 临时签发**:使用 `signTestJwt` 注入任意 tenant_id/customer_id/role 组合
4. **superuser bypass 测试单独标记**:仅用于"白盒验证 RLS 是否真正生效"(`RLS-10` 已实现)

### 3.4 测试数据策略

| 资源 | 数量 | 用途 |
|---|---|---|
| Tenants | 2 (A, B) | 跨租户隔离测试 |
| Customers per Tenant | 3 (A→C, A→D, A→E;B→F, B→G) | 跨客户隔离测试 |
| Users per Tenant | 7 全角色 × 2 租户 = 14 | RBAC 全矩阵 |
| Projects per Customer | 2-5 | 跨项目隔离 |
| Findings per Project | 5-10 | Finding 流与状态机 |
| Webhooks per Tenant | 1-2 | 跨租户 webhook 隔离 |
| Audit Logs | 随操作自动产生 | 审计完整性 |

---

## 4. 测试环境(Test Environment)

### 4.1 现有环境(沿用)

| 组件 | 配置 | 来源 |
|---|---|---|
| PostgreSQL | `postgresql://localhost:5433/security_vule`(Docker `db` 容器) | `docker-compose.yml` |
| API | `http://localhost:3000`(Bun + Hono) | `apps/api` |
| Redis | `localhost:6379`(可选,KMS 缓存) | `docker-compose.yml` |
| 测试账号 | `tests/helpers/seed.ts` 中 `seedAll()` 预置 | 现有 |

### 4.2 新增环境需求

| 工具 | 用途 | 安装命令 |
|---|---|---|
| **Playwright** | E2E(双门户 UI 旅程) | `bun add -d @playwright/test` |
| **k6** | 性能/并发压测 | `brew install k6` |
| **OWASP ZAP** | 自动化安全扫描(基线) | `docker pull owasp/zap2docker-stable` |
| **jest-bench / vitest bench** | 微基准(unit 性能) | 内置 |

### 4.3 环境清单(测试前必检)

```bash
# 1. DB 健康
docker compose -f docker-compose.yml up -d db redis
bun run db:migrate
bun run db:seed

# 2. API 健康
bun --cwd apps/api run dev &
curl http://localhost:3000/healthz

# 3. 测试连通
bun test tests/integration/multi_tenant_isolation.test.ts
```

---

## 5. 测试矩阵(Test Matrix)

### 5.1 角色清单(来自设计文档 §1.5 + §2.9)

| # | 角色 | portal | 范围 |
|---|---|---|---|
| 1 | **ProviderOwner** | provider | 服务商全权(白标/计费/团队) |
| 2 | **ProviderAdmin** | provider | 服务商全权(不含白标) |
| 3 | **ProviderEngineer** | provider | 检测/PoC/Finding(限授权客户) |
| 4 | **ProviderViewer** | provider | 全局只读 |
| 5 | **ProviderBilling** | provider | 仅计费/账单 |
| 6 | **CustomerAdmin** | customer | 本客户全权 |
| 7 | **CustomerDeveloper** | customer | 本客户项目 + Finding |
| 8 | **CustomerViewer** | customer | 本客户只读 |

### 5.2 资源 × 动作矩阵(P0 必测资源)

下表标识每个 (资源,动作) 组合在每种角色下的期望(✅ allow · 👁 read-only · ❌ deny),用于派生 RBAC 单元测试。

#### 5.2.1 服务商门户资源(/api/provider/v1/...)

| 资源 | 动作 | Owner | Admin | Engineer | Viewer | Billing | CustAdmin | CustDev | CustViewer |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `/customers` GET | 列表 | ✅ | ✅ | ✅ | ✅ | 👁 | ❌ | ❌ | ❌ |
| `/customers` POST | 新建 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/customers/:id` GET | 详情 | ✅ | ✅ | ✅ | ✅ | 👁 | ❌ | ❌ | ❌ |
| `/customers/:id` PATCH | 编辑 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/customers/:id` DELETE | 软删除 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/customers/:id/restore` POST | 恢复 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/projects` POST | 新建项目 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/projects/:id` PATCH | 编辑项目 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/projects/:id/source` POST | 配置代码源 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/scans/trigger` POST | 触发扫描 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/scans/:id` GET | 扫描详情 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/findings` GET | 列表 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/findings/:id` GET | 详情 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/findings/:id/triage` PATCH | 状态流转 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/findings/bulk` POST | 批量操作 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/poc` POST | 启动 PoC | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/poc/:id` GET | PoC 详情 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/usage` GET | 用量 | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `/billing/plans` GET | 套餐 | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `/billing/invoices` GET | 账单 | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `/billing/plans` PATCH | 改套餐 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/team` GET | 团队成员 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/team` POST | 邀请成员 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/team/:userId/role` PATCH | 改角色 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/team/:userId` DELETE | 禁用 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/governance/audit` GET | 审计日志 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/governance/security` PATCH | 安全设置 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/webhooks` GET | Webhook | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/webhooks` POST | 创建 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/apikeys` GET | API Key | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `/apikeys` POST | 生成 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

#### 5.2.2 客户门户资源(/api/customer/v1/...)

| 资源 | 动作 | Owner | Admin | Engineer | Viewer | Billing | CustAdmin | CustDev | CustViewer |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `/dashboard` GET | 首页 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/projects` GET | 项目列表 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/projects/:id` GET | 项目详情 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/scans/trigger` POST | 触发扫描 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| `/findings` GET | Finding 列表 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/findings/:id` GET | Finding 详情 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/findings/:id/comment` POST | 评论 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| `/findings/:id/triage` PATCH | 状态流转 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| `/reports` GET | 报告列表 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/reports/:id` GET | 报告下载 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `/usage` GET | 用量 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | 👁 | 👁 |
| `/settings/members` GET | 成员 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| `/settings/members` POST | 邀请 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| `/settings/integrations` GET | 集成 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| `/settings/integrations` POST | 配置 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

> **统计**: 服务商 31 行 × 8 角色 = 248 cells + 客户 15 行 × 8 角色 = 120 cells = **368 cells 总矩阵**
> 现有 `rbac_matrix.test.ts` 已覆盖 12+6 = 18 cells × 7 角色 = 126 cells,**待扩展 ~242 cells**

---

## 6. 测试用例设计(Test Cases)

### 6.1 模块 A · 多租户隔离(对齐 §2.8 + §13.3)

> 已有基础:`MT-01..10`、`RLS-01..10`、`MTI-01..04`(28 cases)。本模块补充 ~30 cases。

#### 6.1.1 跨租户读/写/改/删

| ID | 用例 | 前置 | 步骤 | 期望 |
|---|---|---|---|---|
| **MT-101** | 租户 A 用户 GET 租户 B 客户详情 | 2 tenant,各 1 客户 | 用 A JWT 调 `GET /customers/{B's customer id}` | HTTP 404(资源不存在,**不暴露存在性**) |
| **MT-102** | 租户 A 用户 PATCH 租户 B 客户名 | 同上 | `PATCH /customers/{B's customer id}` body=`{name:'X'}` | 404;B 客户名未变 |
| **MT-103** | 租户 A 用户 DELETE 租户 B 项目 | 2 tenant 各 1 项目 | `DELETE /projects/{B's project id}` | 404;B 项目仍存在 |
| **MT-104** | 租户 A 用户读租户 B Finding 列表 | 各 1 finding | `GET /findings?customerId={B's customer id}` | 列表为空(0 rows) |
| **MT-105** | 租户 A 用户 POST 创建 Finding 到租户 B 项目 | 各 1 项目 | body 注入 `tenant_id=B`,绕过中间件 | 404 / 400;B 项目无新 finding |
| **MT-106** | 租户 A 用户调租户 B 的 PoC 沙箱 | 各 1 PoCRun | `GET /poc/{B's PoCRun id}` | 404 |
| **MT-107** | 租户 A 用户读租户 B 用量 | 各有 usage_events | `GET /usage?customerId={B's customer id}` | 列表为空 |
| **MT-108** | 租户 A 用户改租户 B 套餐 | 各 1 套餐 | `PATCH /billing/plans/{B's plan id}` | 404 |
| **MT-109** | 租户 A 用户读租户 B 审计日志 | 各有 audit | `GET /governance/audit?tenantId=B` | 0 rows |
| **MT-110** | 租户 A 用户读租户 B API Key 明文 | 各 1 API Key | `GET /apikeys` | 仅见自己租户的 key |

#### 6.1.2 跨客户隔离(同租户下)

| ID | 用例 | 前置 | 步骤 | 期望 |
|---|---|---|---|---|
| **MC-101** | 客户 C 用户 GET 客户 D 项目详情 | 同 tenant A 下 C、D 各 1 项目 | `GET /projects/{D's project id}` 用 C JWT | 404 |
| **MC-102** | 客户 C 用户 LIST 客户 D Findings | 各有 finding | `GET /findings` 用 C JWT | 仅见 C 的 finding |
| **MC-103** | 客户 C 用户 PATCH 客户 D Finding 状态 | 各有 finding | `PATCH /findings/{D's finding id}` body=`{status:'fixed'}` | 404;D finding 未变 |
| **MC-104** | 客户 C 用户看客户 D 用量仪表盘 | 各有 usage | `GET /usage` | 仅见 C 的用量 |
| **MC-105** | 客户 C 用户下载客户 D 报告 | 各有 report | `GET /reports/{D's report id}` | 404 |
| **MC-106** | 客户 C 用户评论客户 D Finding | 各有 finding | `POST /findings/{D's id}/comment` | 404 |
| **MC-107** | 客户 C 用户邀请成员加入客户 D | 各有客户 | `POST /settings/members` body=`{customer_id: D}` | 400/403(无 D 越权邀请) |
| **MC-108** | 服务商 Owner 跨客户操作(允许场景) | Owner 跨 A 下所有客户 | `GET /customers/{any in A}` | 200 |
| **MC-109** | 服务商 Engineer 跨客户操作(限授权) | Engineer 仅授权 C | `GET /customers/{D's id}` | 403 / 404(未授权) |
| **MC-110** | 服务商 Billing 仅看用量不看项目 | 各客户有 project | `GET /projects` | 404 / 403 |

#### 6.1.3 RLS 策略直查(扩展 §13.3 验证)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **RLS-101** | 所有 28 张业务表均启用 RLS | `SELECT relname FROM pg_class WHERE relrowsecurity = true AND relnamespace IN (...schemas...)` | 计数 = 28(零未启用) |
| **RLS-102** | 所有 RLS 表均有 policy | 沿用现有 `RLS-08` SQL | 计数 = 0(零漏配) |
| **RLS-103** | 故意绕中间件直接 SQL(无 `WHERE tenant_id`) | 用 superuser 连,`SELECT * FROM core.customers` | 看到所有租户(正常) |
| **RLS-104** | 同样 SQL 用 `authenticated_app` 角色 | 切角色 + 不设 GUC | 0 rows(RLS 兜底) |
| **RLS-105** | `SET LOCAL ROLE authenticated_app` 后省略 `app.current_tenant` | 模拟应用漏设 GUC | 0 rows(防止 NULL 通过) |
| **RLS-106** | 注入 GUC 为对方 tenant_id 模拟 token 篡改 | `SET LOCAL app.current_tenant = 'B'; SET ... role = ProviderOwner; SELECT * FROM A's customers` | 0 rows(RLS 严格按 GUC) |
| **RLS-107** | SystemBot 角色可跨租户读(后台任务合法) | `SET LOCAL app.current_user_role = 'SystemBot'` | 看到所有租户(白名单放行) |
| **RLS-108** | 分区表(`audit_logs_2026_06`)继承父表 RLS | `RLS-09` 已实现 | 子分区查询同样被 RLS 过滤 |

#### 6.1.4 双层防护(应用 + DB)失效注入

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **DP-101** | 应用中间件未注入 `tenant_id`(代码 bug 模拟) | 直接调 SQL helper 跳过中间件 | 0 rows(RLS 兜底) |
| **DP-102** | 应用中间件注入错误的 tenant_id | 中间件用 B,GUC 设 A | 0 rows(GUC 决定可见性,中间件失误被 RLS 兜底) |
| **DP-103** | DB 账号意外有 BYPASSRLS | 创建带 `BYPASSRLS` 属性的角色,执行 `SELECT` | 应被代码层拒(账号策略禁止) |

#### 6.1.5 越权防护 = 404(避免存在性泄露)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **EN-101** | 跨租户 GET 已知存在的 ID | 用 A JWT 调 B 的 customer id | 404(**非 403**) |
| **EN-102** | 跨租户 GET 已知不存在的 ID | 用 A JWT 调 random UUID | 404(同 404,响应时间差异 < 50ms 防 timing attack) |
| **EN-103** | 跨租户 PATCH 已知存在的 ID | 用 A JWT PATCH B 的项目 | 404(无 400/403 暴露) |
| **EN-104** | 跨租户 DELETE 已知存在的 ID | 用 A JWT DELETE B 的项目 | 404 |
| **EN-105** | 越权尝试均落入审计 | 上述 EN-101..104 全部 | `audit_logs.event_type IN ('unauthorized_access','cross_tenant_attempt')` 各 1 条 |

#### 6.1.6 审计兜底

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **AU-101** | 跨租户 SELECT 失败时写 audit | 见 EN-101 | audit 有 1 条记录 |
| **AU-102** | 跨客户 PATCH 失败时写 audit | 见 MC-103 | audit 有 1 条记录 |
| **AU-103** | 客户 C 用户越权访问客户 D 资源均写 audit | EN-101..104 全跑 | 计数 = 4 |
| **AU-104** | 审计记录包含关键字段 | 查 audit row | 含 actor_user_id, actor_email, target_resource_id, denial_reason, ip, ua |
| **AU-105** | 审计链哈希连续(沿用现有 `tests/unit/audit`) | `audit verify` CLI | 通过 |

---

### 6.2 模块 B · 多用户 RBAC(对齐 §1.5 + §2.9)

> 已有基础:`rbac_matrix.test.ts`(126 cells)。本模块扩展 242 cells + 新增 ~25 个边界用例。

#### 6.2.1 角色矩阵完整化(扩展现有)

| ID | 用例 | 期望 cells |
|---|---|---|
| **RB-101** | 服务商完整资源矩阵 | 31 行 × 8 角色 = 248 cells(现有 12 行,新增 19 行) |
| **RB-102** | 客户门户完整资源矩阵 | 15 行 × 8 角色 = 120 cells(现有 6 行,新增 9 行) |
| **RB-103** | 跨 portal 错误调用 | 服务商 token 调 customer API / 反之,均 403 |
| **RB-104** | ProviderBilling 仅访问计费域 | 调 `/customers` 返 403,调 `/billing/*` 返 200 |
| **RB-105** | ProviderViewer 所有写操作均 deny | 全部 PATCH/POST/DELETE 返 403/404 |

#### 6.2.2 角色变更即时生效

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **RC-101** | Owner 将 Engineer 改为 Viewer | `PATCH /team/:userId/role {role:Viewer}` | 下次请求该用户立即无权写 |
| **RC-102** | 角色变更入审计 | 同上 | audit_logs 有 `role_changed` 事件 |
| **RC-103** | Owner 改自己为 Engineer 后失去 Owner 权 | `PATCH /team/{self id} {role:Engineer}` | 下次请求 403(避免单 Owner 自降风险) |
| **RC-104** | 转让 Owner 后原 Owner 失去超管权 | `POST /team/transfer {to:userId}` | 新 Owner 有超管权,旧 Owner 失去 |
| **RC-105** | 最后一名 Owner 被禁用 | `DELETE /team/{last Owner}` | 拒绝(必须保留 ≥1 Owner) |
| **RC-106** | 客户管理员禁用某客户用户 | `PATCH /customer/v1/settings/members/{id} {status:disabled}` | 该用户下次请求 401/403 |

#### 6.2.3 权限矩阵 §2.9 双向校验

每行(资源 × 角色)既测正向(允许的角色真能访问),又测反向(不允许的角色返回 403/404)。

| ID | 用例 | 模式 |
|---|---|---|
| **PM-101..PM-368** | 5.2 矩阵中每个 cell 一正一反 2 用例 | 共 ~370 用例,部分现有已覆盖 |

---

### 6.3 模块 C · 认证与会话(对齐 §2.2-2.3)

#### 6.3.1 登录

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **LG-101** | 正常登录返回 access + refresh | `POST /auth/login {email, password}` | 200 + JWT(30min)+ Refresh(7d) |
| **LG-102** | 错误密码 1-4 次允许 | 连续 4 次错 | 401;5 次后 423 Locked |
| **LG-103** | 5 次失败锁定 15min | 第 5 次 | 423 + `locked_until` 字段写入 |
| **LG-104** | 锁定期间正确密码也被拒 | locked 状态下用对密码 | 423 + 审计 |
| **LG-105** | 15min 后自动解锁 | 等待 + 重试 | 200 |
| **LG-106** | 弱口令拒绝 | `password: 'password123'` | 400 + 详细错误 |
| **LG-107** | 跨门户登录尝试 | 用服务商账号登录 customer.app.com | 401 + 审计 |
| **LG-108** | 客户账号尝试登录服务商门户 | 同上反向 | 401 + 审计 |
| **LG-109** | 同邮箱在两个门户分别注册互不影响 | 服务商门户 user_a@x.com + 客户门户 user_a@x.com | 两个账号独立存在 |

#### 6.3.2 会话与设备管理

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **SE-101** | 列出活跃会话 | `GET /auth/sessions` | 含 IP / UA / 最后活跃时间 |
| **SE-102** | 强制下线某设备 | `DELETE /auth/sessions/:sessionId` | 该 refresh token 失效 |
| **SE-103** | 强制下线所有设备 | `POST /auth/sessions/revoke-all` | 所有 sessions revoked |
| **SE-104** | Refresh token 轮换 | 用 refresh 换新 access | 新 access 有效,旧 refresh 失效 |
| **SE-105** | Token 吊销后旧 access 仍可短时使用 | (注:JWT 设计权衡,设计文档未明确) | 文档化决策;测试当前行为 |
| **SE-106** | 30min 无操作自动登出 | 等待 30min + 重试 | 401(无会话过期) |

#### 6.3.3 密码策略(§2.3)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **PW-101** | 长度 ≥10 | `password: 'Abc1!defg'` | 通过 |
| **PW-102** | 长度 <10 拒绝 | `password: 'Abc1!'` | 400 |
| **PW-103** | 必须含大小写+数字 | `password: 'abcdefghij'(无大小写)` | 400 |
| **PW-104** | bcrypt cost=12 验证 | 查 DB `password_hash` | 以 `$2b$12$` 开头 |
| **PW-105** | 数据库无明文密码 | 查 DB | 无明文 password 字段 |
| **PW-106** | 忘记密码邮件一次性链接 | `POST /auth/forgot` | 邮件含 1h 一次性 token |
| **PW-107** | 重置后所有 refresh 失效 | reset 后用旧 refresh | 401 |
| **PW-108** | 不强制周期轮换 | 等 90 天 | 不强制要求改密 |

---

### 6.4 模块 D · 用户管理(对齐 §2.5、§2.7、§2.10)

#### 6.4.1 团队邀请

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **IN-101** | Owner 邀请 Engineer | `POST /team {email, role:Engineer}` | 200 + 邀请邮件发送 |
| **IN-102** | 邀请 token 7 天有效 | 7 天前 token | 仍可用 |
| **IN-103** | 邀请 token 7 天后过期 | 8 天前 token | 410 Gone |
| **IN-104** | 重发邀请使旧 token 失效 | 同一邮箱发 2 次 | 旧 token 不可用 |
| **IN-105** | 撤销未接受邀请 | `DELETE /invites/:id` | 后续点击拒绝 |
| **IN-106** | 邀请时角色降级尝试 | Engineer 邀请 Owner | 403 |
| **IN-107** | 邀请已存在邮箱 | 同邮箱再次邀请 | 400 |

#### 6.4.2 客户门户账号体系(§2.7)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **CP-101** | 服务商创建首个 CustomerAdmin | `POST /customers/:id/admin` | 邀请邮件发出 |
| **CP-102** | CustomerAdmin 邀请 Developer | `POST /customer/v1/settings/members {email, role:Developer}` | 邀请邮件发出 |
| **CP-103** | CustomerAdmin 不能邀请 CustomerAdmin(权限限制) | body `{role:CustomerAdmin}` | 403 |
| **CP-104** | CustomerDeveloper 不能邀请任何人 | Developer 调邀请 API | 403 |
| **CP-105** | 服务商强制重置客户管理员密码 | `POST /customers/:id/admin/reset` | 邮件发出 + audit |
| **CP-106** | 服务商禁用某客户用户 | `PATCH /customer-portal/users/:id {disabled}` | 客户用户下次请求 401 |

#### 6.4.3 离职/禁用处理

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **OF-101** | Engineer 离职,Owner 禁用 | `PATCH /team/:userId {status:disabled}` | 该用户立即 401 |
| **OF-102** | 禁用账号保留审计记录 | 查 audit_logs | 仍可见该用户历史操作 |
| **OF-103** | 禁用账号可恢复(7 天内) | `PATCH /team/:userId {status:active}` | 恢复访问 |
| **OF-104** | 禁用账号 7 天后清除(可配置) | 等 7 天 | 物理删除或匿名化 |

---

### 6.5 模块 E · 双门户边界(对齐 §1.3)

#### 6.5.1 跨门户 API 隔离

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **CP-201** | 服务商 token 调 customer API | `GET /customer/v1/dashboard` 用 Owner token | 403 |
| **CP-202** | 客户 token 调 provider API | `GET /provider/v1/customers` 用 CustomerAdmin token | 403 |
| **CP-203** | 服务商 token 含 portal=provider 但访问 customer 域 | middleware 解析 JWT | 403 |
| **CP-204** | 客户 token 含 portal=customer 但访问 provider 域 | 同上反向 | 403 |
| **CP-205** | 两套 JWT 独立签名密钥(隔离风险) | 改 provider secret 后客户登录 | 仍有效 |

#### 6.5.2 跨门户数据可见性

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **CP-301** | 客户 user 看服务商内部审计 | `GET /governance/audit` 用客户 token | 403 |
| **CP-302** | 客户 user 看其他客户的用量 | `GET /usage?customerId=other` | 仅见自己 customer |
| **CP-303** | 客户 user 调 PoC 执行(服务商域功能) | `POST /provider/v1/poc` | 403 |
| **CP-304** | 客户 user 改项目(仅服务商可改) | `PATCH /provider/v1/projects/:id` | 403 |

---

### 6.6 模块 F · 用量与计费隔离(对齐 §7)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **BL-101** | UsageEvent 写入带正确 tenant_id + customer_id | 触发 PoC 生成 | usage_events.tenant_id 与 JWT 一致 |
| **BL-102** | 跨租户读 usage_events | 用 A JWT 读 B usage | 0 rows |
| **BL-103** | 同租户跨客户读 usage_events | Owner 跨 A 下 C/D 看 usage | 可见所有客户(CustomerAdmin 仅见自己) |
| **BL-104** | 配额扣减按 customer 聚合 | C 用完配额,D 不受影响 | D 仍可调 AI |
| **BL-105** | 配额耗尽 AI 按钮灰化 | C 用尽,C 客户用户 UI 看 PoC 按钮 | disabled |
| **BL-106** | 配额耗尽允许手工上传 PoC | C 用尽后 Engineer 上传 PoC | 允许(降级路径) |
| **BL-107** | 账单仅本租户可见 | Owner 看 A 账单 | 不见 B |
| **BL-108** | 服务商 Billing 角色跨客户看账单 | ProviderBilling 看所有客户账单 | 可见 |
| **BL-109** | 成本分摊:usage_proportional | 设规则后查客户分摊 | 按 token 比例 |
| **BL-110** | 成本分摊:flat_rate | 设固定费率 | 与用量解耦 |
| **BL-111** | 客户软删除后 usage_events 保留 | `DELETE /customers/:id` | 90 天内 usage 仍可查 |

---

### 6.7 模块 G · 软删除与恢复(对齐 §2.6 + §13.10)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **SD-101** | 客户软删除后状态变 `deleted` | `DELETE /customers/:id` | DB 中 `deleted_at` 非空 |
| **SD-102** | 软删除客户 90 天内可恢复 | 立即 `POST /customers/:id/restore` | 200,状态变 `active` |
| **SD-103** | 软删除客户 90 天后不可恢复 | (测试中模拟时间) | 410 Gone |
| **SD-104** | 软删除客户列表默认隐藏 | `GET /customers` 默认不含 deleted | 仅 `active` + `suspended` |
| **SD-105** | 含 `?includeDeleted=true` 才见 | 见上 | 可见 |
| **SD-106** | 软删除客户的所有项目暂停扫描 | 删客户 → 检查项目状态 | `paused` |
| **SD-107** | 项目软删除保留 30 天 | `DELETE /projects/:id` | 30 天可恢复 |
| **SD-108** | 恢复客户触发审计 | 恢复后查 audit | `customer_restored` 事件 |
| **SD-109** | 软删除客户的所有 sessions 失效 | 删客户后该客户用户登录 | 401 |
| **SD-110** | 数据导出端点(GDPR) | `GET /customers/:id/export` | 返回 JSON + 审计链 manifest |

---

### 6.8 模块 H · API Key / Webhook / 集成(对齐 §1.9 + §3.3 + §3.11)

#### 6.8.1 API Key

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **AK-101** | 生成项目级 API Key | `POST /projects/:id/apikeys` | 返回明文一次 + DB 存 hash |
| **AK-102** | API Key 仅本项目可用 | 用项目 A 的 Key 访问项目 B | 403/404 |
| **AK-103** | API Key 跨租户不可用 | 同上反向 | 403 |
| **AK-104** | 吊销 API Key | `DELETE /apikeys/:id` | 立即失效 |
| **AK-105** | API Key 解密使用入审计 | 调 Key 一次 | audit 含 key_id + 用途 |

#### 6.8.2 Webhook

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **WH-101** | 创建 Webhook 仅本租户可见 | Owner A 创建 webhook | B 不可见 |
| **WH-102** | Webhook 推送触发事件时仅本租户触发 | 推 Finding 变更 | 仅触发 A 的 webhook |
| **WH-103** | Webhook secret 签名校验失败拒收 | 篡改 signature 头 | 401 + 不投递 |
| **WH-104** | Webhook 重试机制(网络失败) | 模拟 5xx | 指数退避重试 |
| **WH-105** | Webhook secret 加密存储 | DB 查 | `secret_ciphertext` BYTEA |

#### 6.8.3 凭证安全

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **CR-101** | GitHub Token KMS 加密 | `POST /sources` body 含 token | DB `ref_token` BYTEA 密文 |
| **CR-102** | API 响应不含明文 token | `GET /sources/:id` | 无明文 token 字段 |
| **CR-103** | Token 自动续期 | access_token 过期前 24h | 平台自动调 refresh_token |
| **CR-104** | Token 续期失败告警 | refresh_token 失效 | audit + 通知 Owner |
| **CR-105** | 项目删除/客户冻结时主动撤销 Token | 删项目 | GitHub/GitLab revoke API 被调 |

---

### 6.9 模块 I · 审计日志完整性(对齐 §9.2 + §13.11)

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **AH-101** | 每次写操作触发 audit row 写入 | 任一 mutation | audit_logs + 1 |
| **AH-102** | 审计链哈希连续(沿用 §13.11 触发器) | `audit verify` | 通过 |
| **AH-103** | 篡改任一 audit row 触发 verify 失败 | `UPDATE audit_logs SET action='xxx'` 绕过触发器 | verify 失败 |
| **AH-104** | 按 tenant_id 筛选 audit | `GET /governance/audit?tenantId=A` | 仅 A 的 |
| **AH-105** | 按时间范围筛选 | `GET /governance/audit?from=...&to=...` | 区间内 |
| **AH-106** | 按事件类型筛选 | `?eventType=login_success` | 仅匹配 |
| **AH-107** | 审计导出 CSV | `GET /governance/audit/export.csv` | 含完整字段 |
| **AH-108** | 审计导出 JSON 含 manifest | `?format=json` | 含 SHA-256 manifest |
| **AH-109** | 审计保留期 2 年(可配置) | 检查分区策略 | 分区按月,保留 24 月 |
| **AH-110** | 审计不可被应用修改 | 应用调 `UPDATE audit_logs` | 触发器拒绝 / 无权限 |

---

### 6.10 模块 J · 性能 / 并发(对齐 §1.10 + §13.14)

> 测试方法:k6 + 单元 bench,非功能目标。

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **PF-101** | 单查询 P95 < 100ms(分页) | k6 `GET /customers?size=20` 100 RPS | p95 ≤ 100ms |
| **PF-102** | 单查询 P95 < 100ms(时间范围) | k6 `GET /usage?range=30d` | 同上 |
| **PF-103** | 单查询 P95 < 100ms(聚合) | k6 `GET /usage/summary?by=customer` | 同上 |
| **PF-104** | usage_events 写入 ≥ 100k 行/天 < 50ms | k6 50 ev/s/客户 × 10 客户 | p95 ≤ 50ms |
| **PF-105** | 索引命中率 ≥ 95% | pg_stat_user_indexes | ≥ 95% |
| **PF-106** | 单租户突发 100 并发扫描不影响其他租户 | k6 单租户打满 100 并发 | 其他租户 P95 不劣化 > 10% |
| **PF-107** | 调度器削峰:定时全量错峰 | 检查调度记录 | 同一时刻不打满全局队列 |
| **PF-108** | RLS 过滤额外开销 ≤ 20% | 对比有/无 RLS 同查询 | ≤ 20% 退化 |

---

### 6.11 模块 K · 端到端(E2E)双门户旅程(Playwright,P2)

> 仅在阶段 1 MVP 收尾前跑全套。

| ID | 用例 | 步骤 | 期望 |
|---|---|---|---|
| **E2E-101** | 服务商入驻 → 创建客户 → 创建项目 → 首次扫描 → Finding → PoC | 全链路 30+ 步 | 全程成功 |
| **E2E-102** | 客户管理员被邀请 → 激活 → 登录客户门户 → 看 Finding | 12 步 | 全程成功 |
| **E2E-103** | 服务商 Engineer 越权访问客户 D,被 RLS 拒绝 | 5 步 | UI 显示"无权访问" |
| **E2E-104** | 服务商软删除客户 → 客户用户登录被拒 | 8 步 | 401 + 友好提示 |
| **E2E-105** | 用量超 90% 触发通知 + UI 预警 | 模拟 | 工作台用量卡变橙 + 邮件 |
| **E2E-106** | 邀请新成员 → 接受 → 角色生效 | 6 步 | 新成员能访问授权域 |
| **E2E-107** | 客户跨门户误登录(provider portal URL 输 customer URL) | 3 步 | 提示"该账号不在此门户" |
| **E2E-108** | 服务商 Owner 转让 → 新 Owner 立即生效 | 5 步 | 旧 Owner 失去超管 |

---

## 7. 用例汇总(派生覆盖率)

| 模块 | 新增 cases | 现有 cases | 合计 |
|---|---:|---:|---:|
| A. 多租户隔离 | ~45 | 28 | ~73 |
| B. 多用户 RBAC | ~270 | 126 | ~396 |
| C. 认证与会话 | ~25 | 0 | ~25 |
| D. 用户管理 | ~17 | 0 | ~17 |
| E. 双门户边界 | ~9 | 2 | ~11 |
| F. 用量与计费隔离 | ~11 | 0 | ~11 |
| G. 软删除与恢复 | ~10 | 0 | ~10 |
| H. API Key / Webhook / 凭证 | ~15 | 0 | ~15 |
| I. 审计完整性 | ~10 | 5 | ~15 |
| J. 性能 / 并发 | ~8 | 0 | ~8 |
| K. E2E | ~8 | 0 | ~8 |
| **合计** | **~428** | **161** | **~589 cases** |

> 完整落地后预计测试套件 ~590 cases,执行时间 < 5 分钟(除性能/E2E)。

---

## 8. 测试工具与框架

### 8.1 现有工具(沿用)

| 工具 | 用途 | 版本 |
|---|---|---|
| **Bun Test** | 单元 + 集成 | Bun ≥ 1.x |
| **pg(直接 SQL)** | DB 集成 / RLS 直查 | 现有 |
| **fetch / 自签 JWT** | API 集成 | `signTestJwt` helper |

### 8.2 新增工具

| 工具 | 用途 | 安装 |
|---|---|---|
| **Playwright** | E2E 双门户 UI 旅程 | `bun add -d @playwright/test && bunx playwright install` |
| **k6** | 性能 / 并发压测 | `brew install k6` |
| **OWASP ZAP** | 自动化安全扫描 | Docker 镜像 |
| **testcontainers-node** | 隔离测试 DB | 可选(避免本地 DB 污染) |
| **faker-js** | 测试数据生成 | `bun add -d @faker-js/faker` |

### 8.3 CI 集成

```yaml
# .github/workflows/test.yml(片段)
name: tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - run: docker compose -f docker-compose.yml up -d db redis
      - run: bun install
      - run: bun run db:migrate
      # P0: 跑全量(本计划 §6.1-6.9)
      - run: bun test tests/integration tests/unit
      # P2: 仅 release 跑
      - run: bunx playwright test tests/e2e
        if: github.ref == 'refs/heads/main'
      # P2: nightly
      - run: k6 run tests/perf/api.js
        if: github.event.schedule == 'nightly'
```

---

## 9. 入口 / 出口 / 通过标准

### 9.1 入口标准(Entry Criteria)

测试开始前必须满足:

- [ ] 代码 `bun run build` 通过
- [ ] DB schema 全部迁移完成(`bun run db:migrate` exit 0)
- [ ] `seedAll()` 预置数据完成
- [ ] API 进程启动健康(`curl http://localhost:3000/healthz` 200)
- [ ] 现有 `multi_tenant_isolation.test.ts` + `rbac_matrix.test.ts` 全绿(基线确认)

### 9.2 出口标准(Exit Criteria)

测试完成判通过:

- [ ] **P0 用例 100% 通过**(模块 A 多租户隔离 + 模块 B RBAC 矩阵 + 模块 I 审计)
- [ ] **P1 用例 ≥ 95% 通过**(模块 C-H)
- [ ] **P2 用例 ≥ 90% 通过**(模块 J 性能 / K E2E)
- [ ] **0 个 P0/P1 级别 Bug Open**(允许 P2/P3 遗留,需有 ticket)
- [ ] **测试报告自动生成**(`bun test --reporter=junit` → `test-results.xml`)
- [ ] **`audit verify` 通过**
- [ ] **`bun run lint && bun run typecheck` 通过**

### 9.3 暂停 / 恢复标准

**暂停条件**:
- 任意 P0 用例失败 → 立即暂停,定位根因(沿用 `/investigate` skill)
- DB 迁移失败 → 暂停
- 关键 helper 函数被破坏 → 暂停

**恢复条件**:
- 修复后同一用例连续 3 次通过
- 相关回归测试全绿

---

## 10. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 测试数据污染跨 run | 中 | 高 | `truncateAll` + `beforeAll`;不依赖跨 run 状态 |
| RLS 策略与代码不同步(漂移) | 中 | 极高 | 自动化 `RLS-08`(零漏配)+ PR checklist 强制 |
| JWT 签名密钥泄露(测试) | 低 | 高 | `JWT_SECRET` 走 env,test 用 `.env.test` 单独密钥 |
| 并发压测影响开发 DB | 中 | 中 | 用 `testcontainers` 或独立 `TEST_DATABASE_URL` |
| 现有 126 cells RBAC 矩阵已与设计 §2.9 不一致 | 高 | 中 | 优先本计划 §5.2 重构 → 单源真理(spec → matrix.ts → tests) |
| AI/LLM 真实调用测试不稳定 | 高 | 中 | 阶段 1 不测 AI,只测降级路径;阶段 2 引入 mock LLM |
| 审计链哈希性能瓶颈 | 低 | 低 | 提前 bench;优化 hash 算法 |
| 越权返回 403 vs 404 不一致 | 中 | 高 | 强制 404(代码层统一转换);新增 EN-105 自动化校验 |

---

## 11. 测试组织与责任人

> 实际开发按域分配。本计划仅给推荐分工。

| 模块 | 负责类型测试 | 推荐执行人 |
|---|---|---|
| A. 多租户隔离 | DB + API | 后端 + DB |
| B. RBAC | API + 单元 | 后端 |
| C. 认证 | API + 单元 | 后端 |
| D. 用户管理 | API + E2E | 后端 + 前端 |
| E. 双门户边界 | API + E2E | 全栈 |
| F. 计费 | API | 后端 |
| G. 软删除 | API | 后端 |
| H. API Key/Webhook | API + 单元 | 后端 |
| I. 审计 | DB + CLI | 后端 + DBA |
| J. 性能 | k6 | SRE |
| K. E2E | Playwright | 前端 + QA |

---

## 12. 附录 A · 现有测试资产盘点

```
tests/
├── integration/
│   ├── multi_tenant_isolation.test.ts   [414 lines, MT-01..10 + RLS-01..10 + MTI-01..04]
│   ├── rbac_matrix.test.ts              [283 lines, 126 cells, RBAC matrix]
│   └── poc-mock.test.ts                 [PoC 验证测试]
├── unit/
│   ├── audit/                           [审计哈希链单元测试]
│   ├── detection/ engine/ ...
│   ├── llm/ ...
│   └── ... (其他域)
└── helpers/
    ├── db.ts                            [Pool + GUC + truncateAll,93 行]
    ├── seed.ts                          [seedAll() 预置 tenants/customers/users,119 行]
    ├── auth.ts                          [JWT 签发,33 行]
    └── api.ts                           [httpGet/Post/Patch/Delete + ensureApiRunning,148 行]
```

---

## 13. 附录 B · 派生文件清单

落地本计划需要新增/修改:

```
tests/integration/
├── auth.test.ts                                  [新增,模块 C ~25 cases]
├── invitations.test.ts                           [新增,模块 D ~17 cases]
├── cross_portal_boundary.test.ts                 [新增,模块 E ~9 cases]
├── billing_isolation.test.ts                     [新增,模块 F ~11 cases]
├── soft_delete_recovery.test.ts                  [新增,模块 G ~10 cases]
├── api_keys_webhooks.test.ts                     [新增,模块 H ~15 cases]
├── audit_chain.test.ts                           [新增/扩展,模块 I ~10 cases]
├── perf/                                         [新增目录]
│   ├── api-read.js                               [k6 脚本]
│   └── api-write.js
tests/e2e/                                        [新增目录]
├── provider-journey.spec.ts                      [E2E-101..108]
└── customer-journey.spec.ts
tests/helpers/
├── audit.ts                                      [新增 audit 链验证 helpers]
├── billing.ts                                    [新增用量/账单 seed]
└── perf.ts                                       [新增 perf helper]
```

> **复用建议**:RBAC matrix 抽取到 `tests/helpers/rbac-matrix.ts` 作为单一真理,`rbac_matrix.test.ts` 和本计划的 RB-101/102 共用。

---

## 14. 附录 C · 与设计文档章节对应索引

| 设计文档章节 | 对应测试模块 | 备注 |
|---|---|---|
| §1.3 双门户分离 | 模块 E | 核心目标 |
| §1.4 三层实体模型 | 全部 | 引用完整性 |
| §1.5 RBAC 角色体系 | 模块 B | 7 角色清单 |
| §1.9 全局技术约束 | 模块 A、H、I | 行级隔离、字段加密、软删除、全审计 |
| §1.10 技术架构分层 | 模块 J | 性能边界 |
| §2.1 服务商入驻 | LG-* + SD-* | 注册流程 |
| §2.2 登录与会话管理 | LG-* + SE-* | JWT + 会话 |
| §2.3 密码安全策略 | PW-* | bcrypt cost 12 |
| §2.5 服务商团队管理 | 模块 D | 邀请 + 角色 |
| §2.6 客户组织管理 | SD-* + 模块 G | 软删除 |
| §2.7 客户门户账号体系 | CP-* | 双门户边界 |
| §2.8 多租户隔离机制 | 模块 A | **核心** |
| §2.9 RBAC 权限矩阵 | 模块 B | 7 角色 × N 资源 |
| §2.10 邀请机制 | IN-* | token 7d/24h |
| §2.11 身份相关审计 | AU-* | 越权入审计 |
| §3.11 代码源凭证安全 | CR-* | KMS 加密 |
| §3.12 项目级单仓库授权 | AK-* | API Key 范围 |
| §7.1-7.6 计费与用量 | 模块 F | 用量事件 + 配额 |
| §8.2 白标能力 | (Out of Scope) | 阶段 3 |
| §9.2 审计日志与追溯 | 模块 I | 哈希链 |
| §9.3 权限治理与最小权限原则 | 模块 B + AU-* | 二次审批 / 30min 超时 |
| §13.3 多租户隔离策略(RLS) | 模块 A + 全部 DB 集成 | **核心** |
| §13.10 软删除约定 | 模块 G | 30/90 天 |
| §13.11 审计日志哈希链 | 模块 I | SHA-256 |
| §13.14 性能与扩展性 | 模块 J | 100k 行/天 < 50ms |

---

## 15. 附录 D · 执行计划(落地建议)

### 阶段 A · 加固基础(Week 1-2,P0)

1. **抽离 RBAC matrix** 到 `tests/helpers/rbac-matrix.ts`(单一真理)
2. **扩展 RBAC cells** 从 12+6 行到 31+15 行(§5.2)
3. **扩展多租户隔离** 从 MT-01..10 到 MT-101..110(§6.1)
4. **补全 RLS 策略直查** 到 28 表 100% 覆盖(§6.1.3)

### 阶段 B · 多用户能力(Week 3-4,P0+P1)

5. **认证与会话** §6.3 全部
6. **用户管理(邀请/团队)** §6.4 全部
7. **双门户边界** §6.5 全部

### 阶段 C · 计费与安全(Week 5-6,P1)

8. **用量计费隔离** §6.6 全部
9. **软删除与恢复** §6.7 全部
10. **API Key / Webhook / 凭证** §6.8 全部
11. **审计完整性** §6.9 全部

### 阶段 D · 非功能(Week 7,P2)

12. **性能压测** §6.10
13. **E2E 双门户旅程** §6.11
14. **CI 集成** §8.3

---

> **结束**:本方案已对齐设计文档 §1-§13 全章节的多租户多用户要求,派生 ~589 测试用例,覆盖 7 角色 × 31+15 资源矩阵 + 28 表 RLS + 11 大业务域。下一步:按 §15 分阶段执行,每阶段 review & 调整后进入下一阶段。