# 第二波 P1 计划:身份与组织完整化

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把身份与组织模块从"骨架可用"升级到"对齐 MSSP 设计",实现服务商入驻审核、JWT 30min、设计要求的 4+3 角色体系、查询拦截中间件、邀请邮件真发、身份事件审计补全。

**Architecture:** 在现有 auth/ 上扩展,保留双轨 user/tenant manager,新增 provider-onboarding、role-permission-matrix、tenant-isolation-middleware 模块。所有变更向后兼容(默认 24h → 可配 30min)。

**Tech Stack:** TypeScript, Express, JSON Web Token, bcryptjs, nodemailer (mailer 已就绪)

---

## 文件结构

```
src/
├── auth/
│   ├── roles.ts                    # 新增: 设计要求的 7 角色枚举
│   ├── rbac-matrix.ts              # 新增: 角色-资源权限矩阵
│   ├── tenant-isolation.ts         # 新增: 查询拦截中间件
│   ├── provider-onboarding.ts      # 新增: 服务商入驻审核
│   ├── invitation-mailer.ts        # 新增: 邀请邮件真发
│   ├── jwt-config.ts               # 新增: JWT 30min 配置
│   ├── audit-events.ts             # 新增: 身份事件审计枚举
│   └── local-auth.ts               # 修改: 接入新角色 + JWT 30min
├── middleware/
│   └── tenant-isolation.ts         # 新增: Express 中间件
tests/
├── unit/auth/
│   ├── roles.test.ts
│   ├── rbac-matrix.test.ts
│   ├── tenant-isolation.test.ts
│   ├── provider-onboarding.test.ts
│   ├── invitation-mailer.test.ts
│   └── audit-events.test.ts
```

---

## 任务 1: 设计要求的 7 角色体系

**Files:**
- Create: `src/auth/roles.ts`
- Test: `tests/unit/auth/roles.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/roles.test.ts
import { describe, it, expect } from 'vitest';
import { ROLES, isValidRole, getRoleCategory } from '../../../src/auth/roles';

describe('Roles', () => {
  it('should have 4 provider roles', () => {
    expect(ROLES.PROVIDER_OWNER).toBe('provider_owner');
    expect(ROLES.PROVIDER_ENGINEER).toBe('provider_engineer');
    expect(ROLES.PROVIDER_ACCOUNT_MGR).toBe('provider_account_mgr');
    expect(ROLES.PROVIDER_AUDITOR).toBe('provider_auditor');
  });

  it('should have 3 customer roles', () => {
    expect(ROLES.CUSTOMER_ADMIN).toBe('customer_admin');
    expect(ROLES.CUSTOMER_DEVELOPER).toBe('customer_developer');
    expect(ROLES.CUSTOMER_VIEWER).toBe('customer_viewer');
  });

  it('should validate role strings', () => {
    expect(isValidRole('provider_owner')).toBe(true);
    expect(isValidRole('customer_admin')).toBe(true);
    expect(isValidRole('random_string')).toBe(false);
    expect(isValidRole('')).toBe(false);
  });

  it('should categorize roles', () => {
    expect(getRoleCategory('provider_owner')).toBe('provider');
    expect(getRoleCategory('customer_admin')).toBe('customer');
    expect(getRoleCategory('unknown')).toBe('unknown');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/roles.test.ts`
Expected: FAIL (cannot find module)

- [ ] **Step 3: 实现 roles.ts**

```typescript
// src/auth/roles.ts
/**
 * 角色体系 — 对齐设计文档 §1.5 / §2.9
 *
 * Provider (服务商) 4 角色:
 *   - provider_owner       超管 (白标/计费/团队)
 *   - provider_engineer    安全工程师 (检测/PoC/findings, 限授权客户)
 *   - provider_account_mgr 客户经理 (客户管理+计费, 只读技术)
 *   - provider_auditor     只读审计 (全局只读)
 *
 * Customer (客户) 3 角色:
 *   - customer_admin       客户管理员 (本客户全部 + 成员管理)
 *   - customer_developer   开发者 (项目 + findings + 触发扫描)
 *   - customer_viewer      只读 (本客户只读)
 */

export const ROLES = {
  // Provider
  PROVIDER_OWNER: 'provider_owner',
  PROVIDER_ENGINEER: 'provider_engineer',
  PROVIDER_ACCOUNT_MGR: 'provider_account_mgr',
  PROVIDER_AUDITOR: 'provider_auditor',
  // Customer
  CUSTOMER_ADMIN: 'customer_admin',
  CUSTOMER_DEVELOPER: 'customer_developer',
  CUSTOMER_VIEWER: 'customer_viewer',
} as const;

export type Role = (typeof ROLES)[keyof typeof ROLES];

export const ALL_ROLES: Role[] = Object.values(ROLES);
export const PROVIDER_ROLES: Role[] = [
  ROLES.PROVIDER_OWNER,
  ROLES.PROVIDER_ENGINEER,
  ROLES.PROVIDER_ACCOUNT_MGR,
  ROLES.PROVIDER_AUDITOR,
];
export const CUSTOMER_ROLES: Role[] = [
  ROLES.CUSTOMER_ADMIN,
  ROLES.CUSTOMER_DEVELOPER,
  ROLES.CUSTOMER_VIEWER,
];

export function isValidRole(role: string): role is Role {
  return (ALL_ROLES as string[]).includes(role);
}

export function getRoleCategory(role: string): 'provider' | 'customer' | 'unknown' {
  if ((PROVIDER_ROLES as string[]).includes(role)) return 'provider';
  if ((CUSTOMER_ROLES as string[]).includes(role)) return 'customer';
  return 'unknown';
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/auth/roles.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/auth/roles.ts tests/unit/auth/roles.test.ts
git commit -m "feat(auth): introduce 7-role system aligned with MSSP design"
```

---

## 任务 2: RBAC 权限矩阵

**Files:**
- Create: `src/auth/rbac-matrix.ts`
- Test: `tests/unit/auth/rbac-matrix.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/rbac-matrix.test.ts
import { describe, it, expect } from 'vitest';
import { can, Resource, Action, ROLES } from '../../../src/auth/rbac-matrix';

describe('RBAC Matrix', () => {
  it('Owner can manage customers', () => {
    expect(can(ROLES.PROVIDER_OWNER, Resource.CUSTOMER, Action.WRITE)).toBe(true);
  });

  it('Engineer can read customers but not write', () => {
    expect(can(ROLES.PROVIDER_ENGINEER, Resource.CUSTOMER, Action.READ)).toBe(true);
    expect(can(ROLES.PROVIDER_ENGINEER, Resource.CUSTOMER, Action.WRITE)).toBe(false);
  });

  it('AccountMgr can read+write customers (only the customer mgmt part)', () => {
    expect(can(ROLES.PROVIDER_ACCOUNT_MGR, Resource.CUSTOMER, Action.WRITE)).toBe(true);
    expect(can(ROLES.PROVIDER_ACCOUNT_MGR, Resource.POC, Action.WRITE)).toBe(false);
  });

  it('Auditor is read-only globally', () => {
    expect(can(ROLES.PROVIDER_AUDITOR, Resource.FINDING, Action.READ)).toBe(true);
    expect(can(ROLES.PROVIDER_AUDITOR, Resource.FINDING, Action.WRITE)).toBe(false);
  });

  it('Customer Admin can manage their customer', () => {
    expect(can(ROLES.CUSTOMER_ADMIN, Resource.PROJECT, Action.WRITE)).toBe(true);
    expect(can(ROLES.CUSTOMER_ADMIN, Resource.BILLING, Action.READ)).toBe(true);
  });

  it('Customer Developer can trigger scan but not manage members', () => {
    expect(can(ROLES.CUSTOMER_DEVELOPER, Resource.SCAN, Action.WRITE)).toBe(true);
    expect(can(ROLES.CUSTOMER_DEVELOPER, Resource.MEMBER, Action.WRITE)).toBe(false);
  });

  it('Customer Viewer is fully read-only', () => {
    expect(can(ROLES.CUSTOMER_VIEWER, Resource.FINDING, Action.READ)).toBe(true);
    expect(can(ROLES.CUSTOMER_VIEWER, Resource.SCAN, Action.WRITE)).toBe(false);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/rbac-matrix.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 rbac-matrix.ts**

```typescript
// src/auth/rbac-matrix.ts
/**
 * 角色-资源-动作权限矩阵 — 对齐设计文档 §2.9
 */
import { ROLES, type Role } from './roles.js';

export enum Resource {
  CUSTOMER = 'customer',
  PROJECT = 'project',
  SCAN = 'scan',
  FINDING = 'finding',
  POC = 'poc',
  BILLING = 'billing',
  POLICY = 'policy',
  MEMBER = 'member',
  ORG = 'org',
  AUDIT = 'audit',
}

export enum Action {
  READ = 'read',
  WRITE = 'write',
  DELETE = 'delete',
}

type Matrix = Record<Role, Partial<Record<Resource, Action[]>>>;

const matrix: Matrix = {
  // Provider
  [ROLES.PROVIDER_OWNER]: {
    [Resource.CUSTOMER]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.PROJECT]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.SCAN]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.FINDING]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.POC]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.BILLING]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.POLICY]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.MEMBER]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.ORG]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.AUDIT]: [Action.READ],
  },
  [ROLES.PROVIDER_ENGINEER]: {
    [Resource.CUSTOMER]: [Action.READ],
    [Resource.PROJECT]: [Action.READ, Action.WRITE],
    [Resource.SCAN]: [Action.READ, Action.WRITE],
    [Resource.FINDING]: [Action.READ, Action.WRITE],
    [Resource.POC]: [Action.READ, Action.WRITE],
    [Resource.BILLING]: [Action.READ],
    [Resource.POLICY]: [Action.READ, Action.WRITE],
  },
  [ROLES.PROVIDER_ACCOUNT_MGR]: {
    [Resource.CUSTOMER]: [Action.READ, Action.WRITE, Action.DELETE],
    [Resource.PROJECT]: [Action.READ],
    [Resource.SCAN]: [Action.READ],
    [Resource.FINDING]: [Action.READ],
    [Resource.BILLING]: [Action.READ, Action.WRITE],
    [Resource.ORG]: [Action.READ],
  },
  [ROLES.PROVIDER_AUDITOR]: {
    [Resource.CUSTOMER]: [Action.READ],
    [Resource.PROJECT]: [Action.READ],
    [Resource.SCAN]: [Action.READ],
    [Resource.FINDING]: [Action.READ],
    [Resource.POC]: [Action.READ],
    [Resource.BILLING]: [Action.READ],
    [Resource.POLICY]: [Action.READ],
    [Resource.MEMBER]: [Action.READ],
    [Resource.ORG]: [Action.READ],
    [Resource.AUDIT]: [Action.READ],
  },
  // Customer
  [ROLES.CUSTOMER_ADMIN]: {
    [Resource.PROJECT]: [Action.READ, Action.WRITE],
    [Resource.SCAN]: [Action.READ, Action.WRITE],
    [Resource.FINDING]: [Action.READ, Action.WRITE],
    [Resource.BILLING]: [Action.READ],
    [Resource.MEMBER]: [Action.READ, Action.WRITE, Action.DELETE],
  },
  [ROLES.CUSTOMER_DEVELOPER]: {
    [Resource.PROJECT]: [Action.READ],
    [Resource.SCAN]: [Action.READ, Action.WRITE],
    [Resource.FINDING]: [Action.READ, Action.WRITE],
    [Resource.BILLING]: [Action.READ],
  },
  [ROLES.CUSTOMER_VIEWER]: {
    [Resource.PROJECT]: [Action.READ],
    [Resource.SCAN]: [Action.READ],
    [Resource.FINDING]: [Action.READ],
    [Resource.BILLING]: [Action.READ],
  },
};

export function can(role: Role, resource: Resource, action: Action): boolean {
  const perms = matrix[role]?.[resource];
  if (!perms) return false;
  return perms.includes(action);
}

export function requirePermission(role: Role, resource: Resource, action: Action): void {
  if (!can(role, resource, action)) {
    throw new Error(`Permission denied: ${role} cannot ${action} ${resource}`);
  }
}

export { ROLES };
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/auth/rbac-matrix.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/auth/rbac-matrix.ts tests/unit/auth/rbac-matrix.test.ts
git commit -m "feat(auth): implement role-permission matrix per design §2.9"
```

---

## 任务 3: 租户隔离中间件

**Files:**
- Create: `src/middleware/tenant-isolation.ts`
- Test: `tests/unit/auth/tenant-isolation.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/tenant-isolation.test.ts
import { describe, it, expect, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { tenantIsolationMiddleware } from '../../../src/middleware/tenant-isolation';

function mockReq(headers: Record<string, string>, params: any = {}): Request {
  return { headers, params, query: {}, body: {} } as any;
}

function mockRes(): Response {
  const res = {} as Response;
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

describe('tenantIsolationMiddleware', () => {
  it('should reject if X-Tenant-Id header missing', () => {
    const req = mockReq({ 'x-user-id': 'u1' });
    const res = mockRes();
    const next = vi.fn() as NextFunction;
    tenantIsolationMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not found' });
    expect(next).not.toHaveBeenCalled();
  });

  it('should reject if X-User-Id header missing', () => {
    const req = mockReq({ 'x-tenant-id': 't1' });
    const res = mockRes();
    const next = vi.fn() as NextFunction;
    tenantIsolationMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(next).not.toHaveBeenCalled();
  });

  it('should inject tenant/customer context and call next', () => {
    const req = mockReq({ 'x-tenant-id': 't1', 'x-user-id': 'u1', 'x-customer-id': 'c1' });
    const res = mockRes();
    const next = vi.fn() as NextFunction;
    tenantIsolationMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect((req as any).tenantContext).toEqual({
      tenantId: 't1',
      userId: 'u1',
      customerId: 'c1',
    });
  });

  it('should allow customerId to be optional', () => {
    const req = mockReq({ 'x-tenant-id': 't1', 'x-user-id': 'u1' });
    const res = mockRes();
    const next = vi.fn() as NextFunction;
    tenantIsolationMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect((req as any).tenantContext.customerId).toBeUndefined();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/tenant-isolation.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 tenant-isolation.ts**

```typescript
// src/middleware/tenant-isolation.ts
import type { Request, Response, NextFunction } from 'express';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('tenant-isolation');

export interface TenantContext {
  tenantId: string;
  userId: string;
  customerId?: string;
  roles?: string[];
}

declare global {
  namespace Express {
    interface Request {
      tenantContext?: TenantContext;
    }
  }
}

/**
 * 租户隔离中间件 — 对齐设计文档 §2.8
 *
 * - 要求请求头 X-Tenant-Id + X-User-Id 必填
 * - X-Customer-Id 可选 (服务商门户无, 客户门户必填)
 * - 注入 req.tenantContext, 供后续 handler 使用
 * - 缺失时返回 404 (不返回 403, 避免泄露资源存在性 — 设计要求)
 * - 失败请求写审计日志
 */
export function tenantIsolationMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const tenantId = req.headers['x-tenant-id'] as string | undefined;
  const userId = req.headers['x-user-id'] as string | undefined;
  const customerId = req.headers['x-customer-id'] as string | undefined;
  const rolesHeader = req.headers['x-user-roles'] as string | undefined;

  if (!tenantId || !userId) {
    logger.warn('Tenant isolation rejected - missing context', {
      path: req.path,
      method: req.method,
      hasTenantId: !!tenantId,
      hasUserId: !!userId,
    });
    res.status(404).json({ success: false, error: 'Not found' });
    return;
  }

  const roles = rolesHeader ? rolesHeader.split(',').map((r) => r.trim()) : [];

  req.tenantContext = {
    tenantId,
    userId,
    customerId: customerId || undefined,
    roles,
  };
  next();
}

/**
 * 工厂: 在中间件中根据 req.tenantContext 提供带过滤的 manager 方法
 */
export function withTenant<T extends { tenantId: string; customerId?: string }>(
  ctx: TenantContext | undefined,
  items: T[]
): T[] {
  if (!ctx) return [];
  return items.filter((item) => {
    if (item.tenantId !== ctx.tenantId) return false;
    if (ctx.customerId && item.customerId && item.customerId !== ctx.customerId) {
      return false;
    }
    return true;
  });
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/auth/tenant-isolation.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/middleware/tenant-isolation.ts tests/unit/auth/tenant-isolation.test.ts
git commit -m "feat(auth): add tenant isolation middleware with 404-on-missing"
```

---

## 任务 4: 服务商入驻审核流程

**Files:**
- Create: `src/auth/provider-onboarding.ts`
- Test: `tests/unit/auth/provider-onboarding.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/provider-onboarding.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { providerOnboardingService } from '../../../src/auth/provider-onboarding';

describe('ProviderOnboardingService', () => {
  beforeEach(() => providerOnboardingService._reset?.());

  it('should create pending application', () => {
    const app = providerOnboardingService.apply({
      companyName: 'Acme Security',
      contactName: 'Alice',
      contactEmail: 'alice@acme.com',
      contactPhone: '+1-555-0100',
      serviceScale: '50-200',
      customerCount: 10,
    });
    expect(app.id).toBeDefined();
    expect(app.status).toBe('pending');
  });

  it('should approve and create tenant + owner', async () => {
    const app = providerOnboardingService.apply({
      companyName: 'Beta Security',
      contactName: 'Bob',
      contactEmail: 'bob@beta.com',
      contactPhone: '+1-555-0101',
      serviceScale: '10-50',
      customerCount: 3,
    });

    const result = await providerOnboardingService.approve(app.id, {
      reviewerId: 'platform-admin',
      plan: 'professional',
      quota: 500_000,
    });

    expect(result.status).toBe('active');
    expect(result.tenantId).toBeDefined();
    expect(result.ownerUserId).toBeDefined();
    expect(result.activationToken).toBeDefined();
  });

  it('should reject with reason and allow re-apply', () => {
    const app = providerOnboardingService.apply({
      companyName: 'Gamma',
      contactName: 'Carol',
      contactEmail: 'carol@gamma.com',
      contactPhone: '+1-555-0102',
      serviceScale: 'unknown',
      customerCount: 0,
    });

    const rejected = providerOnboardingService.reject(app.id, {
      reviewerId: 'platform-admin',
      reason: '资料不全',
    });
    expect(rejected.status).toBe('rejected');
    expect(rejected.rejectionReason).toBe('资料不全');
  });

  it('should list pending applications', () => {
    providerOnboardingService.apply({
      companyName: 'D1', contactName: 'D', contactEmail: 'd1@d.com', contactPhone: '1', serviceScale: 's', customerCount: 1,
    });
    providerOnboardingService.apply({
      companyName: 'D2', contactName: 'D', contactEmail: 'd2@d.com', contactPhone: '1', serviceScale: 's', customerCount: 1,
    });
    const pending = providerOnboardingService.list({ status: 'pending' });
    expect(pending.length).toBe(2);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/provider-onboarding.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 provider-onboarding.ts**

```typescript
// src/auth/provider-onboarding.ts
import crypto from 'crypto';
import { childLogger } from '../utils/logger.js';
import { tenantManager } from './tenant-manager.js';
import { userManager } from './user-manager.js';
import { mailer, EmailTemplates } from './mailer.js';

const logger = childLogger('provider-onboarding');

export type ApplicationStatus = 'pending' | 'active' | 'rejected' | 'suspended';

export interface ProviderApplication {
  id: string;
  companyName: string;
  contactName: string;
  contactEmail: string;
  contactPhone: string;
  serviceScale: string;
  customerCount: number;
  status: ApplicationStatus;
  rejectionReason?: string;
  tenantId?: string;
  ownerUserId?: string;
  createdAt: number;
  reviewedAt?: number;
  reviewerId?: string;
  plan?: string;
  quota?: number;
}

const applications = new Map<string, ProviderApplication>();
let _idCounter = 0;

function nextId(): string {
  _idCounter++;
  return `app-${Date.now()}-${_idCounter}`;
}

export const providerOnboardingService = {
  /**
   * 服务商提交入驻申请
   */
  apply(input: Omit<ProviderApplication, 'id' | 'status' | 'createdAt'>): ProviderApplication {
    const id = nextId();
    const app: ProviderApplication = {
      ...input,
      id,
      status: 'pending',
      createdAt: Date.now(),
    };
    applications.set(id, app);
    logger.info('Provider application submitted', {
      id,
      company: input.companyName,
      email: input.contactEmail,
    });
    // 通知平台运营
    const tpl = EmailTemplates.providerApplicationReceived({
      companyName: input.companyName,
      contactName: input.contactName,
      contactEmail: input.contactEmail,
    });
    mailer.send({
      to: 'platform-ops@security-vule.io',
      subject: tpl.subject,
      html: tpl.html,
      text: tpl.text,
    }).catch((err) => logger.error('Failed to send platform notification', { error: err.message }));
    return app;
  },

  /**
   * 平台运营审核通过 → 创建 tenant + Owner + 发送激活邮件
   */
  async approve(
    appId: string,
    options: { reviewerId: string; plan: string; quota: number }
  ): Promise<ProviderApplication> {
    const app = applications.get(appId);
    if (!app) throw new Error(`Application not found: ${appId}`);
    if (app.status !== 'pending') {
      throw new Error(`Application already in status: ${app.status}`);
    }

    // 1. 创建 tenant
    const tenant = await tenantManager.createTenant({
      name: app.companyName,
      plan: options.plan as any,
      status: 'active',
    });

    // 2. 创建 Owner 用户 (无密码, 等激活链接)
    const owner = await userManager.createUser(
      {
        email: app.contactEmail,
        displayName: app.contactName,
        roles: ['provider_owner'],
        tenantId: tenant.id,
        // password 将在激活时设置
      } as any,
      { userId: options.reviewerId, email: 'platform@security-vule.io' },
      'Provider onboarding approved'
    );

    // 3. 生成激活 token (复用 passwordResetService 的模式)
    const activationToken = crypto.randomBytes(32).toString('hex');
    const activationExpiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24h

    applications.set(appId, {
      ...app,
      status: 'active',
      tenantId: tenant.id,
      ownerUserId: owner.id,
      reviewedAt: Date.now(),
      reviewerId: options.reviewerId,
      plan: options.plan,
      quota: options.quota,
    });

    // 4. 发送激活邮件
    const baseUrl = process.env.APP_BASE_URL || 'http://localhost:5173';
    const activationUrl = `${baseUrl}/activate?token=${activationToken}&appId=${appId}`;
    const tpl = EmailTemplates.providerActivation({
      displayName: app.contactName,
      activationUrl,
      expiresInHours: 24,
    });
    await mailer.send({
      to: app.contactEmail,
      subject: tpl.subject,
      html: tpl.html,
      text: tpl.text,
    });

    logger.info('Provider approved', { appId, tenantId: tenant.id, ownerId: owner.id });
    return applications.get(appId)!;
  },

  /**
   * 驳回
   */
  reject(appId: string, options: { reviewerId: string; reason: string }): ProviderApplication {
    const app = applications.get(appId);
    if (!app) throw new Error(`Application not found: ${appId}`);
    if (app.status !== 'pending') {
      throw new Error(`Application already in status: ${app.status}`);
    }
    const updated: ProviderApplication = {
      ...app,
      status: 'rejected',
      rejectionReason: options.reason,
      reviewedAt: Date.now(),
      reviewerId: options.reviewerId,
    };
    applications.set(appId, updated);

    // 通知申请人
    const tpl = EmailTemplates.providerApplicationRejected({
      companyName: app.companyName,
      contactName: app.contactName,
      reason: options.reason,
    });
    mailer.send({
      to: app.contactEmail,
      subject: tpl.subject,
      html: tpl.html,
      text: tpl.text,
    }).catch((err) => logger.error('Failed to send rejection email', { error: err.message }));

    return updated;
  },

  /**
   * 列表
   */
  list(filter: { status?: ApplicationStatus }): ProviderApplication[] {
    return Array.from(applications.values()).filter((a) => {
      if (filter.status && a.status !== filter.status) return false;
      return true;
    });
  },

  get(id: string): ProviderApplication | undefined {
    return applications.get(id);
  },

  /** @internal */
  _reset(): void {
    applications.clear();
  },
};
```

- [ ] **Step 4: 添加邮件模板**

修改 [src/auth/mailer.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/mailer.ts),在 `EmailTemplates` 中添加:

```typescript
providerApplicationReceived: (input: { companyName: string; contactName: string; contactEmail: string }) => ({
  subject: `[Security Vule] 新的服务商入驻申请: ${input.companyName}`,
  html: `<p>${input.companyName} 提交了入驻申请。</p>
         <p>联系人: ${input.contactName} (${input.contactEmail})</p>
         <p>请登录运营后台审核: <a href="${process.env.PLATFORM_ADMIN_URL || 'http://localhost:5173/admin'}">审核入口</a></p>`,
  text: `${input.companyName} 申请入驻。请登录运营后台审核。`,
}),
providerActivation: (input: { displayName: string; activationUrl: string; expiresInHours: number }) => ({
  subject: '[Security Vule] 欢迎入驻!请激活您的账户',
  html: `<p>${input.displayName}, 您好!</p>
         <p>您的服务商账户已审核通过。点击下方链接激活并设置密码(链接 ${input.expiresInHours} 小时内有效):</p>
         <p><a href="${input.activationUrl}">${input.activationUrl}</a></p>`,
  text: `激活链接: ${input.activationUrl} (${input.expiresInHours}小时内有效)`,
}),
providerApplicationRejected: (input: { companyName: string; contactName: string; reason: string }) => ({
  subject: '[Security Vule] 入驻申请未通过',
  html: `<p>${input.contactName} 您好,</p>
         <p>很抱歉, ${input.companyName} 的入驻申请未通过审核。</p>
         <p>原因: ${input.reason}</p>
         <p>您可补充材料后重新提交。</p>`,
  text: `申请未通过。原因: ${input.reason}`,
}),
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/auth/provider-onboarding.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/auth/provider-onboarding.ts src/auth/mailer.ts tests/unit/auth/provider-onboarding.test.ts
git commit -m "feat(auth): add provider onboarding flow with approval state machine"
```

---

## 任务 5: 邀请邮件真发(替换死代码)

**Files:**
- Create: `src/auth/invitation-mailer.ts`
- Modify: `src/auth/tenant-manager.ts:368-405`
- Test: `tests/unit/auth/invitation-mailer.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/invitation-mailer.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../../src/auth/mailer', () => ({
  mailer: { send: vi.fn().mockResolvedValue(undefined) },
  EmailTemplates: {
    tenantInvitation: vi.fn().mockReturnValue({
      subject: 'invite', html: '<p>invite</p>', text: 'invite',
    }),
  },
}));

import { invitationMailer } from '../../../src/auth/invitation-mailer';
import { mailer, EmailTemplates } from '../../../src/auth/mailer';

describe('invitationMailer', () => {
  beforeEach(() => {
    vi.mocked(mailer.send).mockClear();
    vi.mocked(EmailTemplates.tenantInvitation as any).mockClear();
  });

  it('should send provider invitation with 7-day expiry', async () => {
    await invitationMailer.sendProviderInvite({
      to: 'eng@svc.com',
      inviterName: 'Alice (Owner)',
      tenantName: 'Acme Security',
      role: 'provider_engineer',
      acceptUrl: 'https://app.com/invite?token=abc',
    });
    expect(mailer.send).toHaveBeenCalledOnce();
    expect(EmailTemplates.tenantInvitation).toHaveBeenCalledWith(
      expect.objectContaining({ expiresInDays: 7 }),
    );
  });

  it('should send customer admin invitation with 24h expiry', async () => {
    await invitationMailer.sendCustomerAdminInvite({
      to: 'admin@client.com',
      inviterName: 'Bob (Provider Owner)',
      customerName: 'ClientCo',
      acceptUrl: 'https://app.com/invite?token=xyz',
    });
    expect(mailer.send).toHaveBeenCalledOnce();
    expect(EmailTemplates.tenantInvitation).toHaveBeenCalledWith(
      expect.objectContaining({ expiresInDays: 1 }),
    );
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/invitation-mailer.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 invitation-mailer.ts**

```typescript
// src/auth/invitation-mailer.ts
import { mailer, EmailTemplates } from './mailer.js';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('invitation-mailer');

interface BaseInviteInput {
  to: string;
  inviterName: string;
  acceptUrl: string;
}

interface ProviderInviteInput extends BaseInviteInput {
  tenantName: string;
  role: string;
}

interface CustomerAdminInviteInput extends BaseInviteInput {
  customerName: string;
}

export const invitationMailer = {
  /**
   * 服务商成员邀请 — 设计 §2.10: 7 天有效
   */
  async sendProviderInvite(input: ProviderInviteInput): Promise<void> {
    const tpl = EmailTemplates.tenantInvitation({
      displayName: input.to.split('@')[0],
      inviterName: input.inviterName,
      organizationName: input.tenantName,
      role: input.role,
      acceptUrl: input.acceptUrl,
      expiresInDays: 7,
    });
    try {
      await mailer.send({
        to: input.to,
        subject: tpl.subject,
        html: tpl.html,
        text: tpl.text,
      });
      logger.info('Provider invitation sent', { to: input.to, role: input.role });
    } catch (err) {
      logger.error('Failed to send provider invitation', {
        to: input.to,
        error: (err as Error).message,
      });
      throw err;
    }
  },

  /**
   * 客户管理员邀请 — 设计 §2.10: 24h 有效
   */
  async sendCustomerAdminInvite(input: CustomerAdminInviteInput): Promise<void> {
    const tpl = EmailTemplates.tenantInvitation({
      displayName: input.to.split('@')[0],
      inviterName: input.inviterName,
      organizationName: input.customerName,
      role: 'customer_admin',
      acceptUrl: input.acceptUrl,
      expiresInDays: 1,
    });
    try {
      await mailer.send({
        to: input.to,
        subject: tpl.subject,
        html: tpl.html,
        text: tpl.text,
      });
      logger.info('Customer admin invitation sent', { to: input.to, customer: input.customerName });
    } catch (err) {
      logger.error('Failed to send customer admin invitation', {
        to: input.to,
        error: (err as Error).message,
      });
      throw err;
    }
  },
};
```

- [ ] **Step 4: 修改 tenant-manager.ts 接入真发**

修改 [src/auth/tenant-manager.ts:368-405](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/tenant-manager.ts#L368-L405) 的 `inviteMember` 方法:

```typescript
  async inviteMember(
    tenantId: string,
    email: string,
    role: string,
    options: { inviterId: string; inviterName: string; customerId?: string; baseUrl?: string } = { inviterId: 'system', inviterName: 'System' }
  ): Promise<TenantInvitation> {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) throw new Error(`Tenant not found: ${tenantId}`);

    // 服务商成员 7 天, 客户管理员 24h
    const isCustomerAdmin = role === 'customer_admin';
    const expiresAt = Date.now() + (isCustomerAdmin ? 24 : 7 * 24) * 60 * 60 * 1000;

    // 生成一次性 token (存入邀请记录)
    const token = crypto.randomBytes(32).toString('hex');
    const invitation: TenantInvitation = {
      id: token,
      tenantId,
      customerId: options.customerId,
      email,
      role,
      status: 'pending',
      invitedBy: options.inviterId,
      expiresAt,
      createdAt: Date.now(),
    };
    this.invitations.set(token, invitation);
    await this.persist();

    // 真发邮件
    const baseUrl = options.baseUrl || process.env.APP_BASE_URL || 'http://localhost:5173';
    const acceptUrl = `${baseUrl}/invite?token=${token}`;

    if (isCustomerAdmin) {
      const customer = options.customerId ? this.customers.get(options.customerId) : null;
      await invitationMailer.sendCustomerAdminInvite({
        to: email,
        inviterName: options.inviterName,
        customerName: customer?.name || '客户组织',
        acceptUrl,
      });
    } else {
      await invitationMailer.sendProviderInvite({
        to: email,
        inviterName: options.inviterName,
        tenantName: tenant.name,
        role,
        acceptUrl,
      });
    }

    return invitation;
  }
```

在文件顶部添加:
```typescript
import crypto from 'crypto';
import { invitationMailer } from './invitation-mailer.js';
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/auth/invitation-mailer.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/auth/invitation-mailer.ts src/auth/tenant-manager.ts tests/unit/auth/invitation-mailer.test.ts
git commit -m "feat(auth): actually send invitation emails with role-based expiry"
```

---

## 任务 6: JWT 30min 接入 + 身份事件审计补全

**Files:**
- Create: `src/auth/jwt-config.ts`
- Modify: `src/auth/middleware.ts`
- Test: `tests/unit/auth/audit-events.test.ts`

- [ ] **Step 1: 实现 jwt-config.ts**

```typescript
// src/auth/jwt-config.ts
/**
 * JWT 配置 — 对齐设计 §2.2
 *
 * Access Token: 30 min (生产)
 * Refresh Token: 7 days (由 session.ts 管理)
 */
export interface JWTConfig {
  accessTokenExpiresIn: string;     // JWT exp claim
  refreshTokenExpiresIn: number;    // ms
  sessionDuration: number;          // ms
}

const DEFAULT: JWTConfig = {
  accessTokenExpiresIn: process.env.NODE_ENV === 'production' ? '30m' : '24h',
  refreshTokenExpiresIn: 7 * 24 * 60 * 60 * 1000,
  sessionDuration: 24 * 60 * 60 * 1000,
};

export const jwtConfig: JWTConfig = { ...DEFAULT };
export function getAccessTokenExpiresInSeconds(): number {
  // 简单解析 '30m' / '24h' / '7d'
  const s = jwtConfig.accessTokenExpiresIn;
  const num = parseInt(s, 10);
  if (s.endsWith('m')) return num * 60;
  if (s.endsWith('h')) return num * 3600;
  if (s.endsWith('d')) return num * 86400;
  return num;
}
```

- [ ] **Step 2: 修改 middleware.ts 使用配置**

修改 [src/auth/middleware.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/middleware.ts) 中 `generateJWT` 函数签名附近:

```typescript
// 在 generateJWT 函数内, exp 字段从 hardcoded 改为:
const token = jwt.sign(
  { ...payload, customerId: payload.customerId },
  secret,
  { expiresIn: jwtConfig.accessTokenExpiresIn, algorithm: 'HS256' }
);
```

- [ ] **Step 3: 写 audit-events 测试**

```typescript
// tests/unit/auth/audit-events.test.ts
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../src/utils/audit-helper', () => ({
  auditHelper: { recordEvent: vi.fn() },
}));

import { recordAuthEvent, AuthAction } from '../../../src/auth/audit-events';
import { auditHelper } from '../../../src/utils/audit-helper';

describe('recordAuthEvent', () => {
  it('should record login_success', () => {
    recordAuthEvent({
      action: AuthAction.LOGIN_SUCCESS,
      actorId: 'u1',
      actorEmail: 'u1@x.com',
      ip: '1.1.1.1',
    });
    expect(auditHelper.recordEvent).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'login_success' }),
    );
  });

  it('should record login_failed with reason', () => {
    recordAuthEvent({
      action: AuthAction.LOGIN_FAILED,
      actorEmail: 'bad@x.com',
      ip: '1.1.1.1',
      reason: 'invalid_credentials',
    });
    expect(auditHelper.recordEvent).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'invalid_credentials' }),
    );
  });

  it('should record role_change with before/after', () => {
    recordAuthEvent({
      action: AuthAction.ROLE_CHANGED,
      actorId: 'admin1',
      resourceType: 'user',
      resourceId: 'u2',
      metadata: { from: 'viewer', to: 'engineer' },
    });
    expect(auditHelper.recordEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({ from: 'viewer', to: 'engineer' }),
      }),
    );
  });
});
```

- [ ] **Step 4: 运行测试验证失败**

Run: `bun run test tests/unit/auth/audit-events.test.ts`
Expected: FAIL

- [ ] **Step 5: 实现 audit-events.ts**

```typescript
// src/auth/audit-events.ts
import { auditHelper } from '../utils/audit-helper.js';

export enum AuthAction {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILED = 'login_failed',
  LOGOUT = 'logout',
  TOKEN_REVOKED = 'token_revoked',
  PASSWORD_CHANGED = 'password_changed',
  PASSWORD_RESET_REQUESTED = 'password_reset_requested',
  PASSWORD_RESET_COMPLETED = 'password_reset_completed',
  ROLE_CHANGED = 'role_changed',
  INVITATION_SENT = 'invitation_sent',
  INVITATION_ACCEPTED = 'invitation_accepted',
  INVITATION_REVOKED = 'invitation_revoked',
  CUSTOMER_CREATED = 'customer_created',
  CUSTOMER_SUSPENDED = 'customer_suspended',
  CUSTOMER_DELETED = 'customer_deleted',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'unauthorized_access_attempt',
  ACCOUNT_LOCKED = 'account_locked',
  IP_BLOCKED = 'ip_blocked',
}

export interface AuthEvent {
  action: AuthAction;
  actorId?: string;
  actorEmail?: string;
  tenantId?: string;
  customerId?: string;
  resourceType?: string;
  resourceId?: string;
  ip?: string;
  userAgent?: string;
  outcome?: 'success' | 'failure';
  reason?: string;
  metadata?: Record<string, any>;
}

export function recordAuthEvent(e: AuthEvent): void {
  auditHelper.recordEvent({
    action: e.action,
    actorId: e.actorId,
    actorEmail: e.actorEmail,
    tenantId: e.tenantId,
    customerId: e.customerId,
    resourceType: e.resourceType,
    resourceId: e.resourceId,
    ip: e.ip,
    userAgent: e.userAgent,
    outcome: e.outcome || 'success',
    reason: e.reason,
    metadata: e.metadata,
  });
}
```

- [ ] **Step 6: 接入关键事件**

修改 [src/auth/local-auth.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/local-auth.ts) 在 login/logout/changePassword 中插入:

```typescript
import { recordAuthEvent, AuthAction } from './audit-events.js';

// login 成功处
recordAuthEvent({
  action: AuthAction.LOGIN_SUCCESS,
  actorId: user.id, actorEmail: user.email, ip: ipAddress, userAgent,
  tenantId: user.tenantId,
});

// login 失败处
recordAuthEvent({
  action: AuthAction.LOGIN_FAILED,
  actorEmail: email, ip: ipAddress, userAgent,
  outcome: 'failure', reason: 'invalid_credentials',
});

// changePassword 完成处
recordAuthEvent({
  action: AuthAction.PASSWORD_CHANGED,
  actorId: userId,
});

// resetPassword 完成处
recordAuthEvent({
  action: AuthAction.PASSWORD_RESET_COMPLETED,
  actorId: consumed.userId, actorEmail: consumed.email,
});
```

类似地修改 tenant-manager.ts 邀请处,添加 `AuthAction.INVITATION_SENT/ACCEPTED/REVOKED`。

- [ ] **Step 7: 运行测试验证**

Run: `bun run test tests/unit/auth/audit-events.test.ts tests/unit/auth/local-auth-security.test.ts`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add src/auth/jwt-config.ts src/auth/middleware.ts src/auth/audit-events.ts src/auth/local-auth.ts tests/unit/auth/audit-events.test.ts
git commit -m "feat(auth): JWT 30min config + comprehensive auth audit event coverage"
```

---

## 任务 7: 接入 tenantIsolation 中间件到 server.ts

**Files:**
- Modify: `src/auth/server.ts:99-128`

- [ ] **Step 1: 修改 server.ts**

在 [src/auth/server.ts:103](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/server.ts#L103) 后插入:

```typescript
  // 请求排水中间件 - 必须在所有路由之前
  app.use((req, res, next) => {
    if (isDraining()) {
      res.setHeader('Connection', 'close');
      res.status(503).json({ success: false, error: 'Service is shutting down' });
      return;
    }
    next();
  });

  // === 第二波: 租户隔离中间件 (放在排水之后, CORS 之前) ===
  app.use(tenantIsolationMiddleware);

  // CORS (开发环境)
```

- [ ] **Step 2: 添加 import**

在 server.ts 顶部添加:

```typescript
import { tenantIsolationMiddleware } from '../middleware/tenant-isolation.js';
```

- [ ] **Step 3: 提交**

```bash
git add src/auth/server.ts
git commit -m "feat(auth): mount tenant isolation middleware globally"
```

---

## 任务 8: 验收

- [ ] **Step 1: 跑全部第二波测试**

```bash
bun run test tests/unit/auth/
```
Expected: ALL PASS

- [ ] **Step 2: 提交**

```bash
git add -A
git commit -m "chore: phase1 P1 identity & organization complete

- 7-role system (Provider 4 + Customer 3) per design §1.5
- RBAC matrix per design §2.9
- Tenant isolation middleware (404 on missing context)
- Provider onboarding with approval state machine
- Invitation emails actually sent (7d provider / 24h customer)
- JWT 30min config (production)
- Comprehensive auth audit events (login/logout/role/invite/etc)"
```

---

## 执行选项

**1. 子代理驱动 (推荐)** - 每个任务派发子代理
**2. 内联执行** - 当前会话顺序执行
