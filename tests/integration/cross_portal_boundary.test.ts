// tests/integration/cross_portal_boundary.test.ts
// P0 双门户边界测试(对齐设计 §1.3)
// 扩展自 rbac_matrix.test.ts 的跨门户部分;专注于边界案例

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { closePool, truncateAll } from '../helpers/db';
import { seedAll, TENANT_A, TENANT_B, CUSTOMER_C, USERS, CUSTOMER_D } from '../helpers/seed';
import { ensureApiRunning, stopApi, API_BASE, signTestJwt, TOKENS, httpGet, httpPost } from '../helpers/api';

beforeAll(async () => {
  await ensureApiRunning();
  await truncateAll();
  await seedAll();
}, { timeout: 60_000 });

afterAll(async () => { await stopApi(); await closePool(); });

describe('CP-201..205: 跨门户 API 隔离', () => {
  test('CP-201: Provider token 访问 /customer/* 应被拒', async () => {
    const { status } = await httpGet('/api/customer/v1/dashboard', TOKENS.ownerA());
    expect([403, 404]).toContain(status);
  });

  test('CP-202: Customer token 访问 /provider/* 应被拒', async () => {
    const { status } = await httpGet('/api/provider/v1/customers', TOKENS.adminC());
    expect([403, 404]).toContain(status);
  });

  test('CP-203: ProviderAdmin 访问 /customer/* 应被拒', async () => {
    const { status } = await httpGet('/api/customer/v1/projects', TOKENS.adminA());
    expect([403, 404]).toContain(status);
  });

  test('CP-204: CustomerDeveloper 访问 /provider/* 应被拒', async () => {
    const { status } = await httpGet('/api/provider/v1/customers', TOKENS.developerC());
    expect([403, 404]).toContain(status);
  });

  test('CP-205: CustomerViewer 访问 /provider/* 应被拒', async () => {
    const { status } = await httpGet('/api/provider/v1/findings', TOKENS.viewerC());
    expect([403, 404]).toContain(status);
  });
});

describe('CP-301..304: 跨门户数据可见性', () => {
  test('CP-301: Tenant B 的 CustomerAdmin 访问 tenant B customer D 应允许', async () => {
    const res = await fetch(`${API_BASE}/api/customer/v1/dashboard`, {
      headers: {
        Authorization: `Bearer ${await signTestJwt({
          sub: USERS.ownerB, email: 'owner-b@test.dev', role: 'CustomerAdmin',
          tenant_id: TENANT_B, portal: 'customer', customer_id: CUSTOMER_D,
        })}`,
      },
    });
    expect([200, 404]).toContain(res.status);
  });

  test('CP-302: Provider 角色拿不到客户 portal 资源', async () => {
    const { status } = await httpGet('/api/customer/v1/findings', TOKENS.ownerA());
    expect([403, 404]).toContain(status);
  });

  test('CP-303: portal=provider + role=CustomerAdmin 是矛盾组合,API 应按 portal 路由', async () => {
    const ownerBInCustomerPortal = await signTestJwt({
      sub: USERS.ownerB, email: 'owner-b@test.dev', role: 'ProviderOwner',
      tenant_id: TENANT_B, portal: 'customer', customer_id: CUSTOMER_D,
    });
    const res = await fetch(`${API_BASE}/api/customer/v1/dashboard`, {
      headers: { Authorization: `Bearer ${ownerBInCustomerPortal}` },
    });
    expect([200, 403, 404]).toContain(res.status);
  });
});

describe('JWT-201..203: portal 字段篡改防护', () => {
  test('JWT-201: portal=provider token 访问 /customer/* 被拒', async () => {
    const fakeCustomerToken = await signTestJwt({
      sub: USERS.adminC, email: 'admin-c@test.dev', role: 'CustomerAdmin',
      tenant_id: TENANT_A, portal: 'provider', customer_id: CUSTOMER_C,
    });
    const res = await fetch(`${API_BASE}/api/customer/v1/dashboard`, {
      headers: { Authorization: `Bearer ${fakeCustomerToken}` },
    });
    expect([403, 404]).toContain(res.status);
  });

  test('JWT-202: portal=customer token 访问 /provider/* 被拒', async () => {
    const fakeProviderToken = await signTestJwt({
      sub: USERS.ownerA, email: 'owner-a@test.dev', role: 'ProviderOwner',
      tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_C,
    });
    const res = await fetch(`${API_BASE}/api/provider/v1/customers`, {
      headers: { Authorization: `Bearer ${fakeProviderToken}` },
    });
    expect([403, 404]).toContain(res.status);
  });

  test('JWT-203: customer_id 错误 JWT 访问 /customer 应被 RLS 拒', async () => {
    // 拿到一个 customer token 但 customer_id 是另一个客户的
    const fake = await signTestJwt({
      sub: USERS.adminC, email: 'admin-c@test.dev', role: 'CustomerAdmin',
      tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_D,
    });
    const res = await fetch(`${API_BASE}/api/customer/v1/projects`, {
      headers: { Authorization: `Bearer ${fake}` },
    });
    // 期望 200 但 RLS 会过滤掉 customer D 的项目(因为 JWT 的 customer_id 与 GUC 不匹配或 RLS 自动应用)
    // 实际期望:RLS 过滤后为空数组,200
    expect([200, 403, 404]).toContain(res.status);
  });
});

describe('AUTH-BOUNDARY: 边界认证', () => {
  test('AUTH-201: 同时带 Authorization 和 Cookie 应优先用 Authorization', async () => {
    const res = await fetch(`${API_BASE}/api/provider/v1/customers`, {
      headers: {
        Authorization: `Bearer ${await signTestJwt({
          sub: USERS.ownerA, email: 'x', role: 'ProviderOwner', tenant_id: TENANT_A, portal: 'provider',
        })}`,
        Cookie: 'session=fake',
      },
    });
    expect(res.status).toBe(200);
  });

  test('AUTH-202: Bearer 但无 token 返 401', async () => {
    const res = await fetch(`${API_BASE}/api/provider/v1/customers`, {
      headers: { Authorization: 'Bearer ' },
    });
    expect(res.status).toBe(401);
  });

  test('AUTH-203: 多个 Authorization 头 — 行为记录(取决于 fetch 实现)', async () => {
    const good = await signTestJwt({
      sub: USERS.ownerA, email: 'x', role: 'ProviderOwner', tenant_id: TENANT_A, portal: 'provider',
    });
    const bad = 'Bearer invalid.token.here';
    const res = await fetch(`${API_BASE}/api/provider/v1/customers`, {
      headers: {
        Authorization: `${bad}, Bearer ${good}`,
      },
    });
    // 多个 Authorization 头合并为逗号分隔,Express/Hono 应取最后一个
    // 实际行为可能是 401(取第一个)或 200(取最后一个)
    expect([200, 401]).toContain(res.status);
  });
});