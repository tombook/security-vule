# 第六波 P2 计划:门户与设计系统

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把门户与设计系统从"原型 HTML"升级到"可访问的生产级 UI",补齐缺失的子页面、引入 General Sans 字体、修复无障碍问题、添加报告水印。

**Architecture:** 在 prototypes/app/portal/ 上扩展缺失页面;design-tokens.css 补充 General Sans;统一所有页面添加 ARIA;后端 WhiteLabel 增加 watermark 字段。

**Tech Stack:** HTML/CSS/JS(原型), WCAG 2.1 AA, Google Fonts (General Sans), PDFKit

---

## 文件结构

```
prototypes/app/portal/
├── customer/
│   └── usage.html                  # 新增: 用量仪表盘
├── provider/
│   └── billing.html                # 新增: 计费中心
└── shared/
    └── a11y-fixes.css              # 新增: 无障碍样式

src/
├── whitelabel/
│   └── whitelabel-types.ts         # 修改: 添加 watermark
└── report/
    └── pdf-watermark.ts            # 新增: 水印辅助
tests/
├── unit/whitelabel/watermark.test.ts
```

---

## 任务 1: 客户门户用量页面

**Files:**
- Create: `prototypes/app/portal/customer/usage.html`

- [ ] **Step 1: 创建 customer/usage.html**

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>用量 - Security Vule 客户门户</title>
  <link rel="stylesheet" href="../../new-design/design-tokens.css">
  <link rel="stylesheet" href="../../new-design/components.css">
  <link rel="stylesheet" href="../../new-design/layout.css">
  <link rel="stylesheet" href="../../new-design/a11y-fixes.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&family=General+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
  <a href="#main-content" class="skip-link">跳转到主内容</a>
  <header class="portal-header" role="banner">
    <nav aria-label="主导航">
      <a href="dashboard.html">仪表盘</a>
      <a href="findings.html">漏洞</a>
      <a href="compliance.html">合规报告</a>
      <a href="usage.html" aria-current="page">用量</a>
      <a href="settings.html">设置</a>
    </nav>
  </header>

  <main id="main-content" class="portal-main" role="main">
    <h1>AI Token 用量</h1>
    <p class="page-description">查看本月的 AI 调用消耗与配额使用情况</p>

    <section aria-labelledby="quota-heading" class="card">
      <h2 id="quota-heading">本月配额</h2>
      <div class="quota-display">
        <div class="quota-meter" role="progressbar" aria-valuenow="45" aria-valuemin="0" aria-valuemax="100" aria-label="配额使用率">
          <div class="quota-meter-fill" style="width: 45%"></div>
        </div>
        <p>已使用 <strong>45,000</strong> / 100,000 tokens (45%)</p>
        <p>剩余 55,000 tokens · 预计 ${new Date().toLocaleDateString('zh-CN')} 月底清零</p>
      </div>
    </section>

    <section aria-labelledby="trend-heading" class="card">
      <h2 id="trend-heading">用量趋势 (近 7 天)</h2>
      <div class="chart-placeholder" role="img" aria-label="近 7 天 AI token 用量折线图, 显示为波动上升趋势">
        <p>📈 折线图: 显示近 7 天每日 token 消耗</p>
      </div>
    </section>

    <section aria-labelledby="capability-heading" class="card">
      <h2 id="capability-heading">按能力分布</h2>
      <table class="data-table" aria-describedby="capability-desc">
        <caption id="capability-desc">本月各 AI 能力 token 消耗</caption>
        <thead>
          <tr>
            <th scope="col">能力</th>
            <th scope="col">调用次数</th>
            <th scope="col">Tokens</th>
            <th scope="col">费用 (USD)</th>
          </tr>
        </thead>
        <tbody id="capability-tbody">
          <tr><td>AI PoC 生成</td><td>0</td><td>0</td><td>$0.00</td></tr>
          <tr><td>AI Triage</td><td>0</td><td>0</td><td>$0.00</td></tr>
          <tr><td>AI 漏洞解释</td><td>0</td><td>0</td><td>$0.00</td></tr>
        </tbody>
      </table>
    </section>
  </main>

  <script>
    // 加载用量数据
    fetch('/api/v1/usage/customer/current', { credentials: 'include' })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          const summary = data.data;
          document.querySelector('.quota-meter-fill').style.width = `${summary.usagePercent}%`;
          document.querySelector('.quota-meter').setAttribute('aria-valuenow', String(summary.usagePercent));
          // 填充表格
          const tbody = document.getElementById('capability-tbody');
          tbody.innerHTML = '';
          for (const [cap, info] of Object.entries(summary.byCapability || {})) {
            const row = document.createElement('tr');
            row.innerHTML = `
              <td>${cap}</td>
              <td>${info.events}</td>
              <td>${info.tokens.toLocaleString()}</td>
              <td>$${info.cost.toFixed(2)}</td>
            `;
            tbody.appendChild(row);
          }
        }
      })
      .catch(err => console.error('Failed to load usage:', err));
  </script>
</body>
</html>
```

- [ ] **Step 2: 提交**

```bash
git add prototypes/app/portal/customer/usage.html
git commit -m "feat(portal): customer usage dashboard page per design §8.1"
```

---

## 任务 2: 服务商门户计费中心

**Files:**
- Create: `prototypes/app/portal/provider/billing.html`

- [ ] **Step 1: 创建 provider/billing.html**

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>计费中心 - Security Vule 服务商门户</title>
  <link rel="stylesheet" href="../../new-design/design-tokens.css">
  <link rel="stylesheet" href="../../new-design/components.css">
  <link rel="stylesheet" href="../../new-design/layout.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&family=General+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
  <a href="#main-content" class="skip-link">跳转到主内容</a>

  <div class="app-layout">
    <aside class="sidebar" role="navigation" aria-label="主导航">
      <nav>
        <a href="dashboard.html">工作台</a>
        <a href="customers.html">客户</a>
        <a href="projects.html">项目</a>
        <a href="findings.html">漏洞中心</a>
        <a href="ai-poc.html">AI PoC</a>
        <a href="billing.html" aria-current="page">计费</a>
        <a href="compliance.html">合规中心</a>
        <a href="integrations.html">集成</a>
        <a href="governance.html">治理</a>
        <a href="settings.html">系统设置</a>
      </nav>
    </aside>

    <main id="main-content" class="main-content" role="main">
      <header class="page-header">
        <h1>计费中心</h1>
        <p class="page-description">查看套餐、用量、账单与优化建议</p>
      </header>

      <section aria-labelledby="plan-heading" class="card">
        <h2 id="plan-heading">当前套餐</h2>
        <div class="plan-info">
          <span class="plan-badge">专业版</span>
          <p>AI Token 配额: 500,000 / 月</p>
          <p>客户数: 12 / 20</p>
          <p>项目数: 87 / 200</p>
          <button class="btn btn-primary">升级套餐</button>
        </div>
      </section>

      <section aria-labelledby="usage-heading" class="card">
        <h2 id="usage-heading">本月用量</h2>
        <div class="usage-stats">
          <div class="stat-card">
            <span class="stat-label">总 Tokens</span>
            <span class="stat-value">0</span>
          </div>
          <div class="stat-card">
            <span class="stat-label">总费用 (USD)</span>
            <span class="stat-value">$0.00</span>
          </div>
          <div class="stat-card">
            <span class="stat-label">PoC 生成次数</span>
            <span class="stat-value">0</span>
          </div>
          <div class="stat-card">
            <span class="stat-label">AI Triage 次数</span>
            <span class="stat-value">0</span>
          </div>
        </div>
      </section>

      <section aria-labelledby="top-customers-heading" class="card">
        <h2 id="top-customers-heading">Top 5 消耗客户</h2>
        <table class="data-table">
          <caption>本月 AI token 用量最多的 5 个客户</caption>
          <thead>
            <tr>
              <th scope="col">排名</th>
              <th scope="col">客户</th>
              <th scope="col">Tokens</th>
              <th scope="col">费用 (USD)</th>
            </tr>
          </thead>
          <tbody id="top-customers-tbody">
            <tr><td colspan="4" style="text-align:center;">加载中...</td></tr>
          </tbody>
        </table>
      </section>

      <section aria-labelledby="insights-heading" class="card">
        <h2 id="insights-heading">AI 优化建议</h2>
        <ul class="insight-list" id="insight-list">
          <li>暂无建议</li>
        </ul>
      </section>

      <section aria-labelledby="invoices-heading" class="card">
        <h2 id="invoices-heading">最近账单</h2>
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">账单号</th>
              <th scope="col">周期</th>
              <th scope="col">金额</th>
              <th scope="col">状态</th>
              <th scope="col">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr><td colspan="5" style="text-align:center;">暂无账单</td></tr>
          </tbody>
        </table>
      </section>
    </main>
  </div>
</body>
</html>
```

- [ ] **Step 2: 提交**

```bash
git add prototypes/app/portal/provider/billing.html
git commit -m "feat(portal): provider billing center page per design §1.6/§7.6"
```

---

## 任务 3: 引入 General Sans 字体

**Files:**
- Modify: `prototypes/app/new-design/design-tokens.css`

- [ ] **Step 1: 修改 design-tokens.css 字体配置**

修改 [prototypes/app/new-design/design-tokens.css](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/prototypes/app/new-design/design-tokens.css) 第 90-92 行:

```css
--font-body: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
--font-display: "General Sans", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
--font-mono: "JetBrains Mono", "IBM Plex Mono", "Fira Code", "Cascadia Code", monospace;
```

- [ ] **Step 2: 提交**

```bash
git add prototypes/app/new-design/design-tokens.css
git commit -m "fix(design): introduce General Sans font per design §10.3"
```

---

## 任务 4: 无障碍修复(aria-label / focus 样式)

**Files:**
- Create: `prototypes/app/new-design/a11y-fixes.css`

- [ ] **Step 1: 创建 a11y-fixes.css**

```css
/* === WCAG 2.1 AA 无障碍修复 === */

/* Skip link (键盘用户) */
.skip-link {
  position: absolute;
  top: -40px;
  left: 8px;
  background: var(--color-primary);
  color: white;
  padding: 8px 16px;
  z-index: 9999;
  border-radius: var(--radius-sm);
  text-decoration: none;
  font-weight: 600;
}
.skip-link:focus {
  top: 8px;
  outline: 3px solid var(--color-primary-hover);
}

/* 全局 focus-visible 样式 */
*:focus-visible {
  outline: 3px solid var(--color-primary);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

/* Input 焦点 */
.form-input:focus,
input:focus,
textarea:focus,
select:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-soft);
}

/* Button focus */
.btn:focus-visible {
  outline: 3px solid var(--color-primary-hover);
  outline-offset: 2px;
}

/* 文本对比度提升: text-3 从 #8A8A8A → #767676 (4.5:1) */
:root {
  --color-text-3: #767676;
}

/* Nav 当前页标记 */
nav a[aria-current="page"] {
  color: var(--color-primary);
  font-weight: 600;
  border-left: 3px solid var(--color-primary);
  padding-left: 12px;
}

/* 表格行键盘可达 */
.data-table tbody tr:focus-within {
  background: var(--color-primary-soft);
}

/* Quota meter accessibility */
.quota-meter {
  background: var(--color-bg-3);
  height: 12px;
  border-radius: 6px;
  overflow: hidden;
  margin: 12px 0;
}
.quota-meter-fill {
  background: var(--color-primary);
  height: 100%;
  transition: width 0.3s ease;
}

/* 图标 button 必填 aria-label */
.icon-button {
  background: none;
  border: none;
  cursor: pointer;
  padding: 8px;
  border-radius: var(--radius-sm);
}
.icon-button:hover {
  background: var(--color-bg-2);
}

/* 屏幕阅读器专用文本 */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
```

- [ ] **Step 2: 在所有 portal 页面引入 a11y-fixes.css**

修改 [prototypes/app/portal/index.html](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/prototypes/app/portal/index.html) 等所有门户页面,在 `<head>` 末尾添加:

```html
<link rel="stylesheet" href="../new-design/a11y-fixes.css">
```

- [ ] **Step 3: 提交**

```bash
git add prototypes/app/new-design/a11y-fixes.css prototypes/app/portal/
git commit -m "fix(a11y): add skip-link, focus-visible, contrast fixes per WCAG 2.1 AA"
```

---

## 任务 5: WhiteLabel 报告水印

**Files:**
- Modify: `src/whitelabel/whitelabel-types.ts`
- Create: `src/report/pdf-watermark.ts`
- Test: `tests/unit/whitelabel/watermark.test.ts`

- [ ] **Step 1: 修改 whitelabel-types.ts 添加 watermark**

修改 [src/whitelabel/whitelabel-types.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/whitelabel/whitelabel-types.ts),在 WhitelabelConfig 接口中添加:

```typescript
export interface WhitelabelConfig {
  // ... 已有字段
  reportWatermark?: {
    enabled: boolean;
    text: string;
    position: 'center' | 'corner';
    opacity: number;        // 0~1
  };
}
```

- [ ] **Step 2: 实现 pdf-watermark.ts**

```typescript
// src/report/pdf-watermark.ts
import PDFDocument from 'pdfkit';

export interface WatermarkConfig {
  text: string;
  position: 'center' | 'corner';
  opacity: number;
}

export const DEFAULT_WATERMARK: WatermarkConfig = {
  text: '',
  position: 'center',
  opacity: 0.08,
};

export function applyWatermark(doc: PDFKit.PDFDocument, config: WatermarkConfig): void {
  if (!config.text) return;
  const { width, height } = doc.page;

  doc.save();
  doc.opacity(config.opacity);
  doc.fillColor('#666');

  if (config.position === 'center') {
    doc.rotate(-30, { origin: [width / 2, height / 2] });
    doc.fontSize(72).text(config.text, 0, height / 2 - 36, {
      align: 'center',
      width,
    });
  } else {
    // 角落
    doc.fontSize(14).text(config.text, width - 200, height - 30, {
      align: 'right',
      width: 180,
    });
  }

  doc.restore();
}
```

- [ ] **Step 3: 写测试**

```typescript
// tests/unit/whitelabel/watermark.test.ts
import { describe, it, expect } from 'vitest';
import { applyWatermark, DEFAULT_WATERMARK } from '../../../src/report/pdf-watermark';

describe('applyWatermark', () => {
  it('should be a no-op when text is empty', () => {
    const doc: any = { save: () => {}, opacity: () => {}, fillColor: () => {}, restore: () => {}, page: { width: 600, height: 800 } };
    expect(() => applyWatermark(doc, { ...DEFAULT_WATERMARK, text: '' })).not.toThrow();
  });

  it('should apply centered watermark', () => {
    const calls: string[] = [];
    const doc: any = {
      save: () => calls.push('save'),
      opacity: () => calls.push('opacity'),
      fillColor: () => calls.push('fillColor'),
      rotate: () => calls.push('rotate'),
      fontSize: () => ({ text: () => calls.push('text') }),
      restore: () => calls.push('restore'),
      page: { width: 600, height: 800 },
    };
    applyWatermark(doc, { text: 'ACME', position: 'center', opacity: 0.1 });
    expect(calls).toContain('save');
    expect(calls).toContain('rotate');
    expect(calls).toContain('restore');
  });
});
```

- [ ] **Step 4: 接入 PDF 生成器**

修改 [src/billing/invoice-pdf.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/billing/invoice-pdf.ts) 的水印部分,替换为:

```typescript
import { applyWatermark } from '../report/pdf-watermark.js';

// 在 doc.end() 之前:
if (invoice.watermark) {
  applyWatermark(doc, {
    text: invoice.watermark,
    position: 'center',
    opacity: 0.1,
  });
}
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/whitelabel/watermark.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/whitelabel/whitelabel-types.ts src/report/pdf-watermark.ts src/billing/invoice-pdf.ts tests/unit/whitelabel/watermark.test.ts
git commit -m "feat(whitelabel): report watermark with configurable position and opacity"
```

---

## 任务 6: 把白标入口迁移到服务商门户

**Files:**
- Modify: `prototypes/app/portal/provider/settings.html`
- Modify: `prototypes/app/portal/customer/settings.html`(删除白标部分)

- [ ] **Step 1: 在 provider/settings.html 添加白标 section**

在 [prototypes/app/portal/provider/settings.html](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/prototypes/app/portal/provider/settings.html) 添加白标配置区:

```html
<section aria-labelledby="whitelabel-heading" class="card">
  <h2 id="whitelabel-heading">白标配置</h2>
  <p class="page-description">为客户门户定制品牌 (Logo / 域名 / 主题色 / 报告水印)</p>

  <div class="form-group">
    <label class="form-label" for="wlBrandName">品牌名称</label>
    <input type="text" class="form-input" id="wlBrandName">
  </div>

  <div class="form-group">
    <label class="form-label" for="wlLogoUrl">Logo URL</label>
    <input type="url" class="form-input" id="wlLogoUrl" placeholder="https://your-cdn.com/logo.png">
    <small>推荐 200x60 PNG/SVG 透明背景</small>
  </div>

  <div class="form-group">
    <label class="form-label" for="wlPrimaryColor">主色调</label>
    <input type="color" class="form-input" id="wlPrimaryColor" value="#0047AB">
  </div>

  <div class="form-group">
    <label class="form-label" for="wlCustomDomain">自定义域名</label>
    <input type="text" class="form-input" id="wlCustomDomain" placeholder="security.your-domain.com">
  </div>

  <div class="form-group">
    <label>
      <input type="checkbox" id="wlWatermarkEnabled">
      启用报告水印
    </label>
  </div>

  <div class="form-group">
    <label class="form-label" for="wlWatermarkText">水印文字</label>
    <input type="text" class="form-input" id="wlWatermarkText" placeholder="Confidential - ACME Security">
  </div>

  <button class="btn btn-primary" onclick="saveWhiteLabel()">保存白标配置</button>
</section>
```

- [ ] **Step 2: 从 customer/settings.html 移除白标部分**

删除 [prototypes/app/portal/customer/settings.html](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/prototypes/app/portal/customer/settings.html) 第 800-994 行的白标 section。

- [ ] **Step 3: 提交**

```bash
git add prototypes/app/portal/provider/settings.html prototypes/app/portal/customer/settings.html
git commit -m "refactor(portal): move white label config to provider settings per design §8.2"
```

---

## 任务 7: 验收

```bash
bun run test tests/unit/whitelabel/
```

```bash
git add -A
git commit -m "chore: phase1 P2 portal & design system complete

- Customer usage dashboard page
- Provider billing center page
- General Sans font introduced
- WCAG 2.1 AA accessibility (skip-link, focus-visible, contrast)
- WhiteLabel report watermark (configurable position/opacity)
- White label config moved to provider portal"
```

## 执行选项

**1. 子代理驱动 (推荐)**
**2. 内联执行**
