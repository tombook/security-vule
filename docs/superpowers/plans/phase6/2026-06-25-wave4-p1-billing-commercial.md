# 第四波 P1 计划:商业运营计费接入

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把商业运营模块从"模型层可用"升级到"可计费",实现统一套餐体系(消除双轨)、成本分摊算法、Stripe 支付集成、用量监控 Dashboard、PDF 发票。

**Architecture:** 重构 usage-types.ts 合并双轨套餐;新增 allocation-engine 实现 3 种分摊策略;新增 payment-providers/stripe;新增 billing-dashboard API;新增 invoice-pdf 渲染器。

**Tech Stack:** TypeScript, Express, Stripe SDK, pdfkit (PDF), zod (验证)

---

## 文件结构

```
src/
├── billing/
│   ├── plan-catalog.ts             # 新增: 统一套餐目录
│   ├── allocation-engine.ts        # 新增: 3 种分摊算法
│   ├── payment-provider.ts         # 新增: 支付抽象接口
│   ├── payment-stripe.ts           # 新增: Stripe 实现
│   ├── payment-mock.ts             # 新增: 沙箱/开发用 Mock
│   ├── billing-dashboard.ts        # 新增: 仪表盘聚合
│   ├── invoice-pdf.ts              # 新增: PDF 发票渲染
│   ├── plan-types.ts               # 重构: 合并双轨
│   └── usage-types.ts              # 修改: 对齐
tests/
├── unit/billing/
│   ├── plan-catalog.test.ts
│   ├── allocation-engine.test.ts
│   ├── payment-mock.test.ts
│   ├── billing-dashboard.test.ts
│   └── invoice-pdf.test.ts
```

---

## 任务 1: 统一套餐目录(消除双轨)

**Files:**
- Create: `src/billing/plan-catalog.ts`
- Test: `tests/unit/billing/plan-catalog.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/plan-catalog.test.ts
import { describe, it, expect } from 'vitest';
import { PLAN_CATALOG, getPlan, listPlans } from '../../../src/billing/plan-catalog';

describe('PlanCatalog', () => {
  it('should have 4 plans: starter, professional, enterprise, on_premise', () => {
    const plans = listPlans();
    expect(plans.map((p) => p.id)).toEqual(['starter', 'professional', 'enterprise', 'on_premise']);
  });

  it('should match design §7.1 pricing', () => {
    expect(PLAN_CATALOG.starter.aiTokenQuota).toBe(100_000);
    expect(PLAN_CATALOG.starter.priceUsdMonthly).toBe(499);
    expect(PLAN_CATALOG.starter.maxCustomers).toBe(5);
    expect(PLAN_CATALOG.starter.maxProjects).toBe(50);

    expect(PLAN_CATALOG.professional.aiTokenQuota).toBe(500_000);
    expect(PLAN_CATALOG.professional.priceUsdMonthly).toBe(1999);
    expect(PLAN_CATALOG.professional.maxCustomers).toBe(20);
    expect(PLAN_CATALOG.professional.maxProjects).toBe(200);
    expect(PLAN_CATALOG.professional.pocLibrary).toBe(true);

    expect(PLAN_CATALOG.enterprise.aiTokenQuota).toBeNull();  // 无限
    expect(PLAN_CATALOG.enterprise.maxCustomers).toBe(100);
  });

  it('getPlan should return full plan object', () => {
    const p = getPlan('professional');
    expect(p?.id).toBe('professional');
    expect(p?.name).toBe('专业版');
  });

  it('should throw on unknown plan id', () => {
    expect(() => getPlan('unknown_plan')).toThrow();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/plan-catalog.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 plan-catalog.ts**

```typescript
// src/billing/plan-catalog.ts
/**
 * 统一套餐目录 — 对齐设计 §7.1
 * 消除 BillingPlan (starter/professional/enterprise) 与 TenantPlan (free/starter/pro/enterprise) 的双轨
 */

export interface PlanDefinition {
  id: 'starter' | 'professional' | 'enterprise' | 'on_premise';
  name: string;
  nameEn: string;
  aiTokenQuota: number | null;      // null = 无限
  maxCustomers: number | null;       // null = 无限
  maxProjects: number | null;        // null = 无限
  pocLibrary: boolean;
  whiteLabel: boolean;
  sso: boolean;
  sla: '99.9' | '99.95' | '99.99';
  priceUsdMonthly: number;            // on_premise: 年付
  overagePricePer1kTokens: number;    // 超出后单价
  features: string[];
}

export const PLAN_CATALOG: Record<PlanDefinition['id'], PlanDefinition> = {
  starter: {
    id: 'starter',
    name: '入门版',
    nameEn: 'Starter',
    aiTokenQuota: 100_000,
    maxCustomers: 5,
    maxProjects: 50,
    pocLibrary: false,
    whiteLabel: false,
    sso: false,
    sla: '99.9',
    priceUsdMonthly: 499,
    overagePricePer1kTokens: 5,       // 5 USD / 1K tokens
    features: [
      '无限次扫描',
      'SCA 依赖检查',
      'DFG 静态分析',
      'CI/CD 插件',
      '邮件支持',
    ],
  },
  professional: {
    id: 'professional',
    name: '专业版',
    nameEn: 'Professional',
    aiTokenQuota: 500_000,
    maxCustomers: 20,
    maxProjects: 200,
    pocLibrary: true,
    whiteLabel: false,
    sso: false,
    sla: '99.95',
    priceUsdMonthly: 1999,
    overagePricePer1kTokens: 4,
    features: [
      '包含入门版所有功能',
      'AI PoC 验证 (含沙箱)',
      'PoC 库沉淀与复用',
      'Triage AI 辅助',
      '工单集成 (GitHub/GitLab)',
      '工单支持 4h 响应',
    ],
  },
  enterprise: {
    id: 'enterprise',
    name: '企业版',
    nameEn: 'Enterprise',
    aiTokenQuota: null,              // 无限
    maxCustomers: 100,
    maxProjects: 2000,
    pocLibrary: true,
    whiteLabel: true,
    sso: true,
    sla: '99.99',
    priceUsdMonthly: 4999,           // 起步价, 实际按用量计费
    overagePricePer1kTokens: 3,
    features: [
      '包含专业版所有功能',
      '白标 (Logo/色/域名/水印)',
      'SSO (SAML/OIDC)',
      '2FA 强制',
      '完整合规框架',
      '专属客户经理',
      '7×24 支持',
    ],
  },
  on_premise: {
    id: 'on_premise',
    name: '私有部署',
    nameEn: 'On-Premise',
    aiTokenQuota: null,
    maxCustomers: null,
    maxProjects: null,
    pocLibrary: true,
    whiteLabel: true,
    sso: true,
    sla: '99.99',
    priceUsdMonthly: 0,               // 联系销售
    overagePricePer1kTokens: 0,
    features: [
      '完全私有化',
      '源码交付',
      '定制开发',
      '现场实施',
    ],
  },
};

export function getPlan(id: string): PlanDefinition | null {
  if (!(id in PLAN_CATALOG)) {
    throw new Error(`Unknown plan: ${id}`);
  }
  return PLAN_CATALOG[id as PlanDefinition['id']];
}

export function listPlans(): PlanDefinition[] {
  return Object.values(PLAN_CATALOG);
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/billing/plan-catalog.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/billing/plan-catalog.ts tests/unit/billing/plan-catalog.test.ts
git commit -m "feat(billing): unified 4-plan catalog (starter/professional/enterprise/on_premise)"
```

---

## 任务 2: 成本分摊引擎(3 种策略)

**Files:**
- Create: `src/billing/allocation-engine.ts`
- Test: `tests/unit/billing/allocation-engine.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/allocation-engine.test.ts
import { describe, it, expect } from 'vitest';
import { allocationEngine, AllocationInput } from '../../../src/billing/allocation-engine';

const baseInput: AllocationInput = {
  totalProviderCostUsd: 1000,
  totalTokens: 1_000_000,
  customers: [
    { customerId: 'c1', tokens: 500_000, strategy: 'usage_proportional' },
    { customerId: 'c2', tokens: 300_000, strategy: 'usage_proportional' },
    { customerId: 'c3', tokens: 200_000, strategy: 'usage_proportional' },
  ],
};

describe('AllocationEngine', () => {
  it('usage_proportional: should allocate by token ratio', () => {
    const result = allocationEngine.compute(baseInput);
    expect(result.allocations).toHaveLength(3);
    expect(result.allocations[0].amountUsd).toBe(500);
    expect(result.allocations[1].amountUsd).toBe(300);
    expect(result.allocations[2].amountUsd).toBe(200);
    expect(result.totalAllocatedUsd).toBe(1000);
  });

  it('flat_rate: should give each customer same fee', () => {
    const input: AllocationInput = {
      totalProviderCostUsd: 3000,
      totalTokens: 0,
      customers: [
        { customerId: 'c1', tokens: 0, strategy: 'flat_rate', monthlyFlatFee: 500 },
        { customerId: 'c2', tokens: 0, strategy: 'flat_rate', monthlyFlatFee: 500 },
        { customerId: 'c3', tokens: 0, strategy: 'flat_rate', monthlyFlatFee: 1000 },
      ],
    };
    const result = allocationEngine.compute(input);
    expect(result.allocations[0].amountUsd).toBe(500);
    expect(result.allocations[2].amountUsd).toBe(1000);
    expect(result.totalAllocatedUsd).toBe(2000);
  });

  it('custom: should use customMultiplier', () => {
    const input: AllocationInput = {
      totalProviderCostUsd: 1000,
      totalTokens: 1_000_000,
      customers: [
        { customerId: 'c1', tokens: 1_000_000, strategy: 'custom', customMultiplier: 0.5 },
      ],
    };
    const result = allocationEngine.compute(input);
    // proportional 默认值 1000, * 0.5 = 500
    expect(result.allocations[0].amountUsd).toBe(500);
  });

  it('should handle empty customer list', () => {
    const input: AllocationInput = {
      totalProviderCostUsd: 1000,
      totalTokens: 0,
      customers: [],
    };
    const result = allocationEngine.compute(input);
    expect(result.allocations).toHaveLength(0);
    expect(result.totalAllocatedUsd).toBe(0);
    expect(result.unallocatedUsd).toBe(1000);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/allocation-engine.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 allocation-engine.ts**

```typescript
// src/billing/allocation-engine.ts
/**
 * 成本分摊引擎 — 对齐设计 §7.3
 *
 * 三种策略:
 * - usage_proportional: 按 AI token 使用比例分摊 (公平)
 * - flat_rate: 给客户设月固定费 (简单, 适合小客户)
 * - custom: 手动调整分摊金额
 */

export type AllocationStrategy = 'usage_proportional' | 'flat_rate' | 'custom';

export interface CustomerAllocationInput {
  customerId: string;
  tokens: number;
  strategy: AllocationStrategy;
  monthlyFlatFee?: number;
  customMultiplier?: number;       // 0~1 或 1.5 等
}

export interface AllocationInput {
  totalProviderCostUsd: number;
  totalTokens: number;
  customers: CustomerAllocationInput[];
}

export interface AllocationResult {
  customerId: string;
  tokens: number;
  amountUsd: number;
  strategy: AllocationStrategy;
}

export interface AllocationOutput {
  allocations: AllocationResult[];
  totalAllocatedUsd: number;
  unallocatedUsd: number;
}

export const allocationEngine = {
  /**
   * 计算每个客户应分摊的成本
   */
  compute(input: AllocationInput): AllocationOutput {
    const results: AllocationResult[] = [];
    let totalAllocated = 0;

    for (const customer of input.customers) {
      let amount = 0;
      switch (customer.strategy) {
        case 'usage_proportional': {
          // 按 token 占比
          if (input.totalTokens > 0) {
            const ratio = customer.tokens / input.totalTokens;
            amount = Math.round(input.totalProviderCostUsd * ratio * 100) / 100;
          }
          break;
        }
        case 'flat_rate': {
          amount = customer.monthlyFlatFee ?? 0;
          break;
        }
        case 'custom': {
          // 先按 proportional 计算, 再乘 multiplier
          const baseRatio = input.totalTokens > 0
            ? customer.tokens / input.totalTokens
            : 0;
          const proportional = input.totalProviderCostUsd * baseRatio;
          const multiplier = customer.customMultiplier ?? 1;
          amount = Math.round(proportional * multiplier * 100) / 100;
          break;
        }
      }
      results.push({
        customerId: customer.customerId,
        tokens: customer.tokens,
        amountUsd: amount,
        strategy: customer.strategy,
      });
      totalAllocated += amount;
    }

    return {
      allocations: results,
      totalAllocatedUsd: Math.round(totalAllocated * 100) / 100,
      unallocatedUsd: Math.round((input.totalProviderCostUsd - totalAllocated) * 100) / 100,
    };
  },
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/billing/allocation-engine.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/billing/allocation-engine.ts tests/unit/billing/allocation-engine.test.ts
git commit -m "feat(billing): cost allocation engine with 3 strategies (proportional/flat/custom)"
```

---

## 任务 3: 支付抽象接口 + Mock 实现

**Files:**
- Create: `src/billing/payment-provider.ts`
- Create: `src/billing/payment-mock.ts`
- Test: `tests/unit/billing/payment-mock.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/payment-mock.test.ts
import { describe, it, expect } from 'vitest';
import { mockPaymentProvider } from '../../../src/billing/payment-mock';

describe('MockPaymentProvider', () => {
  it('should create a checkout session', async () => {
    const session = await mockPaymentProvider.createCheckout({
      amountUsd: 1999,
      customerId: 'c1',
      planId: 'professional',
      successUrl: 'https://app.com/success',
      cancelUrl: 'https://app.com/cancel',
    });
    expect(session.id).toBeDefined();
    expect(session.url).toContain('mock-checkout');
  });

  it('should handle payment webhook', async () => {
    const result = await mockPaymentProvider.handleWebhook({
      eventType: 'invoice.paid',
      data: { invoiceId: 'inv-1', customerId: 'c1' },
    });
    expect(result.processed).toBe(true);
  });

  it('should refund a charge', async () => {
    const result = await mockPaymentProvider.refund({
      chargeId: 'ch-1',
      amountUsd: 100,
    });
    expect(result.refundId).toBeDefined();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/payment-mock.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 payment-provider.ts (接口)**

```typescript
// src/billing/payment-provider.ts
/**
 * 支付抽象接口 — 便于切换 Stripe / Alipay / WeChat
 */

export interface CheckoutInput {
  amountUsd: number;
  customerId: string;
  planId: string;
  successUrl: string;
  cancelUrl: string;
}

export interface CheckoutSession {
  id: string;
  url: string;
  expiresAt: number;
}

export interface WebhookInput {
  eventType: string;
  data: Record<string, any>;
}

export interface WebhookResult {
  processed: boolean;
  message?: string;
}

export interface RefundInput {
  chargeId: string;
  amountUsd: number;
  reason?: string;
}

export interface RefundResult {
  refundId: string;
  status: 'pending' | 'succeeded' | 'failed';
  amountUsd: number;
}

export interface PaymentProvider {
  readonly name: string;
  createCheckout(input: CheckoutInput): Promise<CheckoutSession>;
  handleWebhook(input: WebhookInput): Promise<WebhookResult>;
  refund(input: RefundInput): Promise<RefundResult>;
}
```

- [ ] **Step 4: 实现 payment-mock.ts**

```typescript
// src/billing/payment-mock.ts
import crypto from 'crypto';
import type { PaymentProvider, CheckoutInput, CheckoutSession, WebhookInput, WebhookResult, RefundInput, RefundResult } from './payment-provider.js';

let _id = 0;
const id = () => `mock-${Date.now()}-${++_id}`;

export const mockPaymentProvider: PaymentProvider = {
  name: 'mock',

  async createCheckout(input: CheckoutInput): Promise<CheckoutSession> {
    return {
      id: id(),
      url: `https://mock-checkout.security-vule.io/pay?amount=${input.amountUsd}&plan=${input.planId}&customer=${input.customerId}`,
      expiresAt: Date.now() + 30 * 60 * 1000,    // 30 分钟
    };
  },

  async handleWebhook(input: WebhookInput): Promise<WebhookResult> {
    // Mock 直接成功处理
    return { processed: true, message: `Mock processed: ${input.eventType}` };
  },

  async refund(input: RefundInput): Promise<RefundResult> {
    return {
      refundId: id(),
      status: 'succeeded',
      amountUsd: input.amountUsd,
    };
  },
};
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/billing/payment-mock.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/billing/payment-provider.ts src/billing/payment-mock.ts tests/unit/billing/payment-mock.test.ts
git commit -m "feat(billing): payment provider interface + mock implementation"
```

---

## 任务 4: Stripe 支付实现(可选启用)

**Files:**
- Create: `src/billing/payment-stripe.ts`
- Modify: `src/billing/server.ts` (添加 Stripe 切换)

- [ ] **Step 1: 实现 payment-stripe.ts**

```typescript
// src/billing/payment-stripe.ts
import Stripe from 'stripe';
import type { PaymentProvider, CheckoutInput, CheckoutSession, WebhookInput, WebhookResult, RefundInput, RefundResult } from './payment-provider.js';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('payment-stripe');

let stripeClient: Stripe | null = null;

function getClient(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY not configured');
    stripeClient = new Stripe(key, { apiVersion: '2024-06-20' });
  }
  return stripeClient;
}

export const stripePaymentProvider: PaymentProvider = {
  name: 'stripe',

  async createCheckout(input: CheckoutInput): Promise<CheckoutSession> {
    const session = await getClient().checkout.sessions.create({
      mode: 'subscription',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: `Security Vule - ${input.planId}` },
            unit_amount: input.amountUsd * 100,   // cents
            recurring: { interval: 'month' },
          },
          quantity: 1,
        },
      ],
      success_url: input.successUrl,
      cancel_url: input.cancelUrl,
      client_reference_id: input.customerId,
      metadata: { planId: input.planId, customerId: input.customerId },
    });
    return {
      id: session.id,
      url: session.url || '',
      expiresAt: (session.expires_at || 0) * 1000,
    };
  },

  async handleWebhook(input: WebhookInput): Promise<WebhookResult> {
    // Stripe webhook 需 raw body 校验签名, 这里假设已经过 express.raw 解析
    // 业务侧: 根据 eventType 触发对应动作
    logger.info('Stripe webhook processed', { event: input.eventType });
    return { processed: true };
  },

  async refund(input: RefundInput): Promise<RefundResult> {
    const refund = await getClient().refunds.create({
      charge: input.chargeId,
      amount: input.amountUsd * 100,
      reason: input.reason as any,
    });
    return {
      refundId: refund.id,
      status: refund.status === 'succeeded' ? 'succeeded' : 'pending',
      amountUsd: (refund.amount || 0) / 100,
    };
  },
};

/**
 * 工厂: 根据环境变量选择 provider
 */
export function getPaymentProvider(): PaymentProvider {
  if (process.env.STRIPE_SECRET_KEY) {
    return stripePaymentProvider;
  }
  // 开发/沙箱默认用 mock
  const { mockPaymentProvider } = require('./payment-mock.js');
  return mockPaymentProvider;
}
```

- [ ] **Step 2: 在 server.ts 挂载支付 Webhook**

在 [src/auth/server.ts:209](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/server.ts#L209) 之后:

```typescript
// === 支付 webhook (需 raw body) ===
app.post('/api/v1/billing/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  try {
    const Stripe = require('stripe');
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
    // 触发对应业务
    res.json({ received: true });
  } catch (err: any) {
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});
```

- [ ] **Step 3: 提交**

```bash
git add src/billing/payment-stripe.ts src/auth/server.ts
git commit -m "feat(billing): Stripe payment provider with checkout/webhook/refund"
```

---

## 任务 5: 用量 Dashboard 聚合 API

**Files:**
- Create: `src/billing/billing-dashboard.ts`
- Test: `tests/unit/billing/billing-dashboard.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/billing-dashboard.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { billingDashboardService } from '../../../src/billing/billing-dashboard';
import { usageTracker } from '../../../src/billing/usage-tracker';

describe('BillingDashboard', () => {
  beforeEach(() => {
    usageTracker._reset();
  });

  it('should return dashboard summary for a tenant', () => {
    usageTracker.record({
      tenantId: 't1', customerId: 'c1',
      capability: 'ai_poc_generation', model: 'gpt-4',
      promptTokens: 1000, completionTokens: 500,
    });
    usageTracker.record({
      tenantId: 't1', customerId: 'c1',
      capability: 'ai_triage', model: 'gpt-4',
      promptTokens: 800, completionTokens: 200,
    });
    usageTracker.record({
      tenantId: 't1', customerId: 'c2',
      capability: 'ai_triage', model: 'gpt-4',
      promptTokens: 500, completionTokens: 100,
    });

    const dash = billingDashboardService.getDashboard({ tenantId: 't1' });

    expect(dash.totalTokens).toBe(3100);
    expect(dash.totalCostUsd).toBeGreaterThan(0);
    expect(dash.topCustomers.length).toBeGreaterThan(0);
    expect(dash.topCustomers[0].customerId).toBe('c1');
    expect(dash.topCustomers[0].tokens).toBe(2500);
  });

  it('should provide optimization insights', () => {
    // 大量重复 poc_gen 表明可能没复用 PoC 库
    for (let i = 0; i < 10; i++) {
      usageTracker.record({
        tenantId: 't1', customerId: 'c1',
        capability: 'ai_poc_generation', model: 'gpt-4',
        promptTokens: 2000, completionTokens: 1000,
      });
    }
    const dash = billingDashboardService.getDashboard({ tenantId: 't1' });
    expect(dash.insights.some((i) => i.includes('PoC 库'))).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/billing-dashboard.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 billing-dashboard.ts**

```typescript
// src/billing/billing-dashboard.ts
/**
 * 计费 Dashboard 聚合 — 对齐设计 §7.5
 */
import { usageTracker } from './usage-tracker.js';

export interface CustomerUsageSummary {
  customerId: string;
  tokens: number;
  costUsd: number;
  byCapability: Record<string, number>;
}

export interface DashboardData {
  totalTokens: number;
  totalCostUsd: number;
  totalEvents: number;
  topCustomers: CustomerUsageSummary[];
  byCapability: Record<string, { tokens: number; costUsd: number; events: number }>;
  insights: string[];
}

export const billingDashboardService = {
  getDashboard(filter: { tenantId: string; customerId?: string }): DashboardData {
    const events = usageTracker.query({ tenantId: filter.tenantId, customerId: filter.customerId });
    const customerMap = new Map<string, CustomerUsageSummary>();
    const capabilityMap: Record<string, { tokens: number; costUsd: number; events: number }> = {};

    for (const e of events) {
      // Customer
      const c = customerMap.get(e.customerId) || {
        customerId: e.customerId,
        tokens: 0,
        costUsd: 0,
        byCapability: {},
      };
      c.tokens += e.totalTokens;
      c.costUsd += e.costUsd;
      c.byCapability[e.capability] = (c.byCapability[e.capability] || 0) + e.totalTokens;
      customerMap.set(e.customerId, c);

      // Capability
      if (!capabilityMap[e.capability]) {
        capabilityMap[e.capability] = { tokens: 0, costUsd: 0, events: 0 };
      }
      capabilityMap[e.capability].tokens += e.totalTokens;
      capabilityMap[e.capability].costUsd += e.costUsd;
      capabilityMap[e.capability].events++;
    }

    const topCustomers = Array.from(customerMap.values())
      .sort((a, b) => b.tokens - a.tokens)
      .slice(0, 5);

    const totalTokens = events.reduce((s, e) => s + e.totalTokens, 0);
    const totalCost = events.reduce((s, e) => s + e.costUsd, 0);

    // AI 优化建议
    const insights = this.generateInsights(events, capabilityMap, topCustomers);

    return {
      totalTokens,
      totalCostUsd: Math.round(totalCost * 100) / 100,
      totalEvents: events.length,
      topCustomers,
      byCapability: capabilityMap,
      insights,
    };
  },

  generateInsights(
    events: any[],
    capability: Record<string, { tokens: number; costUsd: number; events: number }>,
    topCustomers: CustomerUsageSummary[]
  ): string[] {
    const insights: string[] = [];

    // 检测 PoC 生成过多 → 建议复用 PoC 库
    const pocEvents = capability['ai_poc_generation']?.events || 0;
    if (pocEvents > 20) {
      insights.push(`本月生成 ${pocEvents} 次 PoC, 建议使用 PoC 库复用相似漏洞的 PoC 模板, 可节省约 30% AI 用量。`);
    }

    // 检测单客户用量过高
    if (topCustomers.length > 0 && topCustomers[0].tokens > 100_000) {
      insights.push(`客户 ${topCustomers[0].customerId} 本月用 ${topCustomers[0].tokens} tokens (Top 1), 建议确认是否需要升级到 enterprise 套餐。`);
    }

    // 检测 Triage 比例异常
    const triageEvents = capability['ai_triage']?.events || 0;
    if (triageEvents > pocEvents * 5) {
      insights.push('AI Triage 调用次数远超 PoC 生成次数, 建议减少低置信度 finding 的 triage, 改为规则预筛。');
    }

    return insights;
  },
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/billing/billing-dashboard.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/billing/billing-dashboard.ts tests/unit/billing/billing-dashboard.test.ts
git commit -m "feat(billing): dashboard with Top customers + AI optimization insights"
```

---

## 任务 6: PDF 发票渲染

**Files:**
- Create: `src/billing/invoice-pdf.ts`
- Test: `tests/unit/billing/invoice-pdf.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/invoice-pdf.test.ts
import { describe, it, expect } from 'vitest';
import { invoicePdfRenderer } from '../../../src/billing/invoice-pdf';

describe('InvoicePdfRenderer', () => {
  it('should render invoice to PDF buffer', async () => {
    const pdf = await invoicePdfRenderer.render({
      invoiceId: 'inv-2026-001',
      customerName: 'Acme Co',
      providerName: 'Beta Security',
      periodStart: '2026-01-01',
      periodEnd: '2026-01-31',
      planName: '专业版',
      lineItems: [
        { description: '月度套餐费', quantity: 1, unitPriceUsd: 1999, amountUsd: 1999 },
        { description: '超额 AI Token (200K)', quantity: 200, unitPriceUsd: 4, amountUsd: 800 },
      ],
      totalUsd: 2799,
      currency: 'USD',
    });

    expect(pdf).toBeInstanceOf(Buffer);
    // PDF 文件以 %PDF 开头
    expect(pdf.slice(0, 4).toString()).toBe('%PDF');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/invoice-pdf.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 invoice-pdf.ts**

```typescript
// src/billing/invoice-pdf.ts
/**
 * PDF 发票渲染 — 对齐设计 §7.4
 * 使用 PDFKit (零依赖, 纯 JS)
 */
import PDFDocument from 'pdfkit';

export interface InvoiceLineItem {
  description: string;
  quantity: number;
  unitPriceUsd: number;
  amountUsd: number;
}

export interface InvoiceInput {
  invoiceId: string;
  customerName: string;
  providerName: string;
  periodStart: string;
  periodEnd: string;
  planName: string;
  lineItems: InvoiceLineItem[];
  totalUsd: number;
  currency: string;
  logoBase64?: string;
  watermark?: string;
}

export const invoicePdfRenderer = {
  async render(invoice: InvoiceInput): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50, size: 'A4' });
        const chunks: Buffer[] = [];
        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        // 标题
        doc.fontSize(20).text('Invoice', { align: 'right' });
        doc.fontSize(10).text(invoice.invoiceId, { align: 'right' });
        doc.moveDown(2);

        // 双栏: 客户 / 服务商
        doc.fontSize(12).text('From:', { continued: false });
        doc.fontSize(10).text(invoice.providerName);
        doc.moveDown(0.5);
        doc.fontSize(12).text('To:', { continued: false });
        doc.fontSize(10).text(invoice.customerName);
        doc.moveDown(0.5);
        doc.fontSize(10).text(`Period: ${invoice.periodStart} ~ ${invoice.periodEnd}`);
        doc.text(`Plan: ${invoice.planName}`);
        doc.moveDown();

        // 表格头
        doc.fontSize(11).fillColor('#666');
        doc.text('Description', 50, doc.y, { width: 250, continued: true });
        doc.text('Qty', 300, undefined, { width: 50, align: 'right', continued: true });
        doc.text('Unit Price', 350, undefined, { width: 80, align: 'right', continued: true });
        doc.text('Amount', 430, undefined, { width: 100, align: 'right' });
        doc.fillColor('#000');
        doc.moveTo(50, doc.y).lineTo(530, doc.y).stroke();
        doc.moveDown(0.5);

        // 行项目
        for (const item of invoice.lineItems) {
          doc.fontSize(10);
          doc.text(item.description, 50, doc.y, { width: 250, continued: true });
          doc.text(String(item.quantity), 300, undefined, { width: 50, align: 'right', continued: true });
          doc.text(`$${item.unitPriceUsd.toFixed(2)}`, 350, undefined, { width: 80, align: 'right', continued: true });
          doc.text(`$${item.amountUsd.toFixed(2)}`, 430, undefined, { width: 100, align: 'right' });
          doc.moveDown(0.5);
        }

        // 总计
        doc.moveTo(50, doc.y).lineTo(530, doc.y).stroke();
        doc.moveDown(0.5);
        doc.fontSize(12).font('Helvetica-Bold');
        doc.text(`Total: $${invoice.totalUsd.toFixed(2)} ${invoice.currency}`, 350, doc.y, { width: 180, align: 'right' });
        doc.font('Helvetica');

        // 水印
        if (invoice.watermark) {
          doc.opacity(0.1);
          doc.fontSize(60).fillColor('#999').text(
            invoice.watermark,
            0, 300,
            { align: 'center', width: 600 }
          );
          doc.opacity(1);
        }

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  },
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/billing/invoice-pdf.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/billing/invoice-pdf.ts tests/unit/billing/invoice-pdf.test.ts
git commit -m "feat(billing): PDF invoice renderer with PDFKit (zero native deps)"
```

---

## 任务 7: 接入用量埋点到剩余 AI 调用点

**Files:**
- Modify: `src/llm/router.js`(若存在)

- [ ] **Step 1: 检查现有 LLM 调用点**

```bash
grep -rn "generateCompletion\|llmRouter\." src/llm/ src/poc/ src/detection/ 2>/dev/null | head -30
```

- [ ] **Step 2: 在每个 LLM 调用点添加埋点**

模式(在所有 LLM 调用后):

```typescript
import { usageTracker } from '../billing/usage-tracker.js';
import { getTenantContext } from '../auth/context.js';

const tenantContext = getTenantContext();
if (tenantContext && result.usage) {
  usageTracker.record({
    tenantId: tenantContext.tenantId,
    customerId: tenantContext.customerId || 'unknown',
    projectId: tenantContext.projectId,
    findingId: tenantContext.findingId,
    capability: 'ai_explain',  // 根据调用点选择
    model: result.model || model,
    promptTokens: result.usage.promptTokens,
    completionTokens: result.usage.completionTokens,
  });
}
```

主要埋点位置:
- `src/llm/router.js` 的 generateCompletion 后
- `src/poc/ai-poc-generator.ts` 的 LLM 调用后
- `src/detection/ai-triage.ts` 的 LLM 调用后
- `src/redteam/strategies/` 的 LLM 调用后
- `src/poc/dom-xss-verifier.ts` 的 LLM 调用后

- [ ] **Step 3: 提交**

```bash
git add src/
git commit -m "feat(billing): instrument LLM call sites with usage tracking"
```

---

## 任务 8: 验收

```bash
bun run test tests/unit/billing/
```

```bash
git add -A
git commit -m "chore: phase1 P1 commercial operations complete

- Unified 4-plan catalog (eliminated dual-track)
- 3-strategy cost allocation engine
- Payment provider interface + Stripe + Mock
- Billing dashboard with AI optimization insights
- PDF invoice renderer
- LLM call sites instrumented for usage tracking"
```

## 执行选项

**1. 子代理驱动 (推荐)**
**2. 内联执行**
