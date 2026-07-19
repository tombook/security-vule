// tests/helpers/rbac-matrix.ts
// RBAC 矩阵:服务商/客户门户所有受保护端点 × 7 角色期望(allow / deny)
// 单源真理(Single Source of Truth) — 任何 RBAC 测试都从这里读
//
// 7 角色(对齐 seed.ts):
//   ProviderOwner / ProviderAdmin / ProviderEngineer / ProviderViewer
//   CustomerAdmin / CustomerDeveloper / CustomerViewer
//
// 注意:`tenant_id` 和 `customer_id` 字段在 seed.ts 用 snake_case(对齐 JWT 载荷)

import { TENANT_A, TENANT_B, CUSTOMER_C, type Role } from './seed';

// ──────────────────────────── 类型 ────────────────────────────

export type HttpAction = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

export type Permission = 'allow' | 'deny';

/** 一个端点的 RBAC 期望矩阵 */
export interface RbacEndpoint {
  /** 测试用例描述(会出现在 test 名字里) */
  description: string;
  /** HTTP 方法 */
  action: HttpAction;
  /** 路径(可能含真实 ID 占位符 `{id}`) */
  path: string;
  /** 请求体(可省略);允许函数返回动态 body */
  body?: unknown | (() => unknown | Promise<unknown>);
  /** 期望:7 角色 → 允许/拒绝 */
  expectations: Record<Role, Permission>;
}

/** 路径里需要注入动态 ID 的端点描述符 */
export interface ResolvedEndpoint {
  description: string;
  action: HttpAction;
  path: string;
  body?: unknown;
  expectations: Record<Role, Permission>;
}

// ──────────────────────────── Provider 门户矩阵 ────────────────────────────
// 来源:apps/api/src/routes/ 实际存在的端点 + 设计文档 §5.2
// 总计 31 端点 × 7 角色 = 217 cells(其中 31 = 唯一路径 × 1)
// 注:`scan/projects?customerId=...` 形式已与实际 endpoint 对齐

export const PROVIDER_MATRIX: RbacEndpoint[] = [
  // ── 1. 客户管理(7 行) ──
  {
    description: 'GET /customers(客户列表)',
    action: 'GET', path: '/api/provider/v1/customers',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /customers/:id(客户详情)',
    action: 'GET', path: `/api/provider/v1/customers/{customerId}`,
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /customers(新建客户)',
    action: 'POST', path: '/api/provider/v1/customers',
    body: () => ({ name: 'rbac-matrix-test', contactEmail: 'rbac-matrix@test.dev', slug: `rbac-matrix-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` }),
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'PATCH /customers/:id(编辑客户)',
    action: 'PATCH', path: `/api/provider/v1/customers/{customerId}`,
    body: { name: 'rbac-patched' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /customers/:id/contacts(联系人列表)',
    action: 'GET', path: `/api/provider/v1/customers/{customerId}/contacts`,
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /customers/:id/contacts(新建联系人)',
    action: 'POST', path: `/api/provider/v1/customers/{customerId}/contacts`,
    body: { name: 'rbac-contact', email: 'contact@test.dev', role: 'primary' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /customers/:id/billing(用量与账单)',
    action: 'GET', path: `/api/provider/v1/customers/{customerId}/billing`,
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 2. 项目管理(5 行) ──
  {
    description: 'GET /scan/projects(项目列表)',
    action: 'GET', path: `/api/provider/v1/scan/projects?customerId=${CUSTOMER_C}`,
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /scan/projects/:id(项目详情)',
    action: 'GET', path: '/api/provider/v1/scan/projects/{id}',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /scan/projects(新建项目)',
    action: 'POST', path: '/api/provider/v1/scan/projects',
    body: () => ({ customerId: CUSTOMER_C, name: `rbac-proj-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, defaultBranch: 'main' }),
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'PATCH /scan/projects/:id(编辑项目)',
    action: 'PATCH', path: '/api/provider/v1/scan/projects/{id}',
    body: { name: 'rbac-proj-renamed' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /scan/sources(配置代码源)',
    action: 'POST', path: '/api/provider/v1/scan/sources',
    body: { projectId: '{id}', type: 'upload' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 3. 扫描触发(2 行) ──
  {
    description: 'POST /scan/scans/trigger(触发扫描)',
    action: 'POST', path: '/api/provider/v1/scan/scans/trigger',
    body: { projectId: '{id}', trigger: 'manual' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /scan/scans/:id(扫描详情)',
    action: 'GET', path: '/api/provider/v1/scan/scans/{id}',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 4. Findings(5 行) ──
  {
    description: 'GET /findings(Finding 列表)',
    action: 'GET', path: '/api/provider/v1/findings?size=5',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /findings/:id(Finding 详情)',
    action: 'GET', path: '/api/provider/v1/findings/{id}',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'PATCH /findings/:id(状态流转)',
    action: 'PATCH', path: '/api/provider/v1/findings/{id}',
    body: { status: 'in_progress' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /findings/bulk(批量操作)',
    action: 'POST', path: '/api/provider/v1/findings/bulk',
    // body 在测试运行时动态生成 — 需要真实 finding ID
    body: () => ({ ids: ['{findingId}'], action: 'false_positive' }),
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /findings/severity-breakdown(严重度分布)',
    action: 'GET', path: '/api/provider/v1/findings/severity-breakdown',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 5. PoC 验证(2 行) ──
  {
    description: 'GET /validation/queue(PoC 队列)',
    action: 'GET', path: '/api/provider/v1/validation/queue',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /validation/poc/generate(生成 PoC)',
    action: 'POST', path: '/api/provider/v1/validation/poc/generate',
    body: { findingId: '{findingId}' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 6. 用量与计费(3 行) ──
  {
    description: 'GET /usage/usage(全局用量)',
    action: 'GET', path: '/api/provider/v1/usage/usage?days=30',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /billing/plans(套餐)',
    action: 'GET', path: '/api/provider/v1/billing/plans',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /billing/invoices(账单)',
    action: 'GET', path: '/api/provider/v1/billing/invoices',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 7. 治理与安全(5 行) ──
  {
    description: 'GET /governance/audit(审计日志)',
    action: 'GET', path: '/api/provider/v1/governance/audit',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /governance/team(团队成员)',
    action: 'GET', path: '/api/provider/v1/governance/team',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /governance/security(安全设置)',
    action: 'GET', path: '/api/provider/v1/governance/security',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'PUT /governance/security(修改安全设置)',
    action: 'PUT', path: '/api/provider/v1/governance/security',
    body: { passwordMinLength: 12 },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /governance/permissions(权限矩阵)',
    action: 'GET', path: '/api/provider/v1/governance/permissions',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 8. 设置与集成(3 行) ──
  {
    description: 'GET /settings/api-keys(API Key 列表)',
    action: 'GET', path: '/api/provider/v1/settings/api-keys',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'POST /settings/api-keys(生成 API Key)',
    action: 'POST', path: '/api/provider/v1/settings/api-keys',
    body: { name: 'rbac-key', scope: 'project', projectId: '{id}' },
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /integrations/tickets(工单集成)',
    action: 'GET', path: '/api/provider/v1/integrations/tickets',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 9. 检测中心(1 行) ──
  {
    description: 'GET /detection/engines(引擎列表)',
    action: 'GET', path: '/api/provider/v1/detection/engines',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },

  // ── 10. Webhooks(1 行) ──
  {
    description: 'GET /webhooks(Webhook 列表)',
    action: 'GET', path: '/api/provider/v1/webhooks',
    expectations: {
      ProviderOwner: 'allow', ProviderAdmin: 'allow', ProviderEngineer: 'allow', ProviderViewer: 'allow',
      CustomerAdmin: 'deny', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
];

// ──────────────────────────── Customer 门户矩阵 ────────────────────────────
// 来源:apps/api/src/routes/customer.ts + 设计文档 §5.2
// 总计 15 端点 × 7 角色 = 105 cells

export const CUSTOMER_MATRIX: RbacEndpoint[] = [
  {
    description: 'GET /customer/dashboard(客户门户首页)',
    action: 'GET', path: '/api/customer/v1/dashboard',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/projects(项目列表)',
    action: 'GET', path: '/api/customer/v1/projects',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/projects/:id(项目详情)',
    action: 'GET', path: '/api/customer/v1/projects/{id}',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/findings(Finding 列表)',
    action: 'GET', path: '/api/customer/v1/findings?size=5',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/findings/:id(Finding 详情)',
    action: 'GET', path: '/api/customer/v1/findings/{id}',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/reports(报告列表)',
    action: 'GET', path: '/api/customer/v1/reports',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/reports/:id/download(报告下载)',
    action: 'GET', path: '/api/customer/v1/reports/{id}/download',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/usage(我的用量)',
    action: 'GET', path: '/api/customer/v1/usage',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/settings/members(成员管理)',
    action: 'GET', path: '/api/customer/v1/settings/members',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
  {
    description: 'PUT /customer/settings/notifications(更新通知设置)',
    action: 'PUT', path: '/api/customer/v1/settings/notifications',
    body: { emailEnabled: true, inAppEnabled: true },
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'deny',
    },
  },
  {
    description: 'GET /customer/settings/notifications(读取通知设置)',
    action: 'GET', path: '/api/customer/v1/settings/notifications',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'allow', CustomerViewer: 'allow',
    },
  },
  {
    description: 'GET /customer/settings/integrations(集成设置)',
    action: 'GET', path: '/api/customer/v1/settings/integrations',
    expectations: {
      ProviderOwner: 'deny', ProviderAdmin: 'deny', ProviderEngineer: 'deny', ProviderViewer: 'deny',
      CustomerAdmin: 'allow', CustomerDeveloper: 'deny', CustomerViewer: 'deny',
    },
  },
];

// ──────────────────────────── 跨门户错配矩阵 ────────────────────────────

export const CROSS_PORTAL_MATRIX = [
  {
    description: 'Provider token 访问 customer API(应 403/404)',
    path: '/api/customer/v1/dashboard',
    providerToken: 'ownerA' as const,
    expectedStatus: [403, 404],
  },
  {
    description: 'Customer token 访问 provider API(应 403/404)',
    path: '/api/provider/v1/customers',
    providerToken: 'adminC' as const,
    expectedStatus: [403, 404],
  },
];

// ──────────────────────────── 工具 ────────────────────────────

/** 7 角色列表(顺序固定,用于矩阵迭代) */
export const ALL_ROLES: Role[] = [
  'ProviderOwner', 'ProviderAdmin', 'ProviderEngineer', 'ProviderViewer',
  'CustomerAdmin', 'CustomerDeveloper', 'CustomerViewer',
];

/** 把路径里的 `{id}` 占位符替换成真实 ID */
export function resolvePath(path: string, ids: Record<string, string>): string {
  return path.replace(/\{(\w+)\}/g, (_, k) => ids[k] ?? `{${k}}`);
}

/**
 * 把 body 里的 `{xxx}` 占位符替换;函数式 body 每次执行生成新对象(避免冲突)
 * 占位符支持:id / customerId / findingId / projectId
 */
export async function resolveBody(body: unknown | (() => unknown | Promise<unknown>), ids: Record<string, string>): Promise<unknown> {
  if (typeof body === 'function') body = await body();
  if (body == null) return body;
  const json = JSON.stringify(body).replace(/\{(\w+)\}/g, (_, k) => ids[k] ?? `{${k}}`);
  return JSON.parse(json);
}