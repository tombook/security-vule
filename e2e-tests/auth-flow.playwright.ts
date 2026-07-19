// tests/e2e/auth-flow.spec.ts
// Playwright E2E(对齐设计 §12.2.12 业务闭环 + 端到端旅程)
// 占位:框架就绪,完整 UI 流程待与 apps/web 集成后扩展

import { test, expect } from '@playwright/test';

test.describe('Provider Portal E2E', () => {
  test.skip('E2E-101: 服务商登录后进入工作台', async ({ page }) => {
    // 完整流程待 apps/web 提供登录页后启用
    await page.goto('http://localhost:5173/login');
    await page.fill('input[type=email]', 'owner-a@test.dev');
    await page.fill('input[type=password]', 'TestPass123');
    await page.click('button[type=submit]');
    await expect(page).toHaveURL(/workbench/);
  });

  test.skip('E2E-102: 客户跨门户登录被拒', async ({ page }) => {
    await page.goto('http://localhost:5173/login');
    await page.fill('input[type=email]', 'admin-c@test.dev');
    await page.fill('input[type=password]', 'TestPass123');
    await page.click('button[type=submit]');
    await expect(page.locator('text=该账号不在此门户')).toBeVisible();
  });
});

test.describe('API smoke via HTTP', () => {
  test('API-SMOKE-1: GET /api/health 返 200', async ({ request }) => {
    const res = await request.get('http://localhost:3000/api/health');
    expect(res.status()).toBe(200);
  });

  test('API-SMOKE-2: 跨租户 401/403', async ({ request }) => {
    const res = await request.get('http://localhost:3000/api/provider/v1/customers', {
      headers: { Authorization: 'Bearer invalid.token' },
    });
    expect([401, 403]).toContain(res.status());
  });
});