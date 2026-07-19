import { describe, expect, test, beforeEach } from 'bun:test';
import { QuotaManager } from '../../../src/usage/quota.js';
import type { QuotaConfig, QuotaWarning } from '../../../src/usage/quota.js';
import type { UsageEvent } from '../../../src/usage/types.js';
import { UsageStore } from '../../../src/usage/store.js';
import { USAGE_FILENAME } from '../../../src/usage/types.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

function createEvent(overrides: Partial<UsageEvent> = {}): UsageEvent {
  return {
    ts: new Date().toISOString(),
    capability: 'scan_llm',
    provider: 'openai',
    model: 'gpt-4',
    prompt_tokens: 100,
    completion_tokens: 50,
    cost_usd: 0.003,
    ...overrides,
  };
}

describe('QuotaManager', () => {
  test('无配置时返回空数组', () => {
    const qm = new QuotaManager();
    const events = [createEvent(), createEvent()];
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('80% 阈值触发 warning - tokens', () => {
    const qm = new QuotaManager({ maxTokens: 1000, windowMs: 60000 });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 6; i++) {
      events.push(createEvent({ prompt_tokens: 100, completion_tokens: 50 }));
    }
    const warnings = qm.check(events);
    expect(warnings.length).toBe(1);
    expect(warnings[0].type).toBe('tokens');
    expect(warnings[0].current).toBe(900);
    expect(warnings[0].limit).toBe(1000);
    expect(warnings[0].percentage).toBe(90);
    expect(warnings[0].windowMs).toBe(60000);
  });

  test('100% 超限 isExceeded = true', () => {
    const qm = new QuotaManager({ maxTokens: 1000, windowMs: 60000 });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 10; i++) {
      events.push(createEvent({ prompt_tokens: 100, completion_tokens: 50 }));
    }
    const warnings = qm.check(events);
    expect(warnings.length).toBe(1);
    expect(warnings[0].percentage).toBe(150);
    expect(qm.isExceeded(warnings)).toBe(true);
  });

  test('未达 80% 时不触发 warning', () => {
    const qm = new QuotaManager({ maxTokens: 10000, windowMs: 60000 });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 5; i++) {
      events.push(createEvent({ prompt_tokens: 100, completion_tokens: 50 }));
    }
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('多类型（tokens + cost + calls）同时检查', () => {
    const qm = new QuotaManager({
      maxTokens: 1000,
      maxCostUsd: 0.02,
      maxCalls: 8,
      windowMs: 60000,
    });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 10; i++) {
      events.push(createEvent({
        prompt_tokens: 100,
        completion_tokens: 50,
        cost_usd: 0.003,
      }));
    }
    const warnings = qm.check(events);
    expect(warnings.length).toBe(3);
    const types = warnings.map(w => w.type).sort();
    expect(types).toEqual(['calls', 'cost', 'tokens']);
    expect(qm.isExceeded(warnings)).toBe(true);
  });

  test('窗口外事件不计入', () => {
    const qm = new QuotaManager({ maxTokens: 1000, windowMs: 60000 });
    const now = Date.now();
    const events: UsageEvent[] = [];
    // 窗口外的事件（2分钟前）
    for (let i = 0; i < 10; i++) {
      events.push(createEvent({
        ts: new Date(now - 120000).toISOString(),
        prompt_tokens: 100,
        completion_tokens: 50,
      }));
    }
    // 窗口内的事件
    for (let i = 0; i < 3; i++) {
      events.push(createEvent({
        ts: new Date(now).toISOString(),
        prompt_tokens: 100,
        completion_tokens: 50,
      }));
    }
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('缺少 token 字段的事件按 0 计算', () => {
    const qm = new QuotaManager({ maxTokens: 1000, windowMs: 60000 });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 10; i++) {
      events.push(createEvent({ prompt_tokens: undefined, completion_tokens: undefined }));
    }
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('缺少 cost 字段的事件按 0 计算', () => {
    const qm = new QuotaManager({ maxCostUsd: 0.01, windowMs: 60000 });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 100; i++) {
      events.push(createEvent({ cost_usd: undefined }));
    }
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('onWarn 回调被调用', () => {
    const warningsReceived: QuotaWarning[] = [];
    const qm = new QuotaManager({
      maxTokens: 1000,
      windowMs: 60000,
      onWarn: (w) => warningsReceived.push(w),
    });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 8; i++) {
      events.push(createEvent({ prompt_tokens: 100, completion_tokens: 50 }));
    }
    qm.check(events);
    expect(warningsReceived.length).toBe(1);
    expect(warningsReceived[0].type).toBe('tokens');
  });

  test('onWarn 回调异常不影响主流程', () => {
    const qm = new QuotaManager({
      maxTokens: 1000,
      windowMs: 60000,
      onWarn: () => { throw new Error('callback error'); },
    });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 8; i++) {
      events.push(createEvent({ prompt_tokens: 100, completion_tokens: 50 }));
    }
    const warnings = qm.check(events);
    expect(warnings.length).toBe(1);
  });

  test('isExceeded - 无警告时返回 false', () => {
    const qm = new QuotaManager();
    expect(qm.isExceeded([])).toBe(false);
  });

  test('isExceeded - 只有警告但未超限时返回 false', () => {
    const qm = new QuotaManager();
    const warnings: QuotaWarning[] = [
      { type: 'tokens', current: 850, limit: 1000, percentage: 85, windowMs: 60000 },
    ];
    expect(qm.isExceeded(warnings)).toBe(false);
  });

  test('checkFromStore 集成测试（用临时文件）', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'quota-test-'));
    const filePath = join(tmpDir, USAGE_FILENAME);

    try {
      const store = new UsageStore(filePath);
      const now = Date.now();

      for (let i = 0; i < 10; i++) {
        await store.append(createEvent({
          ts: new Date(now).toISOString(),
          prompt_tokens: 100,
          completion_tokens: 50,
          cost_usd: 0.003,
        }));
      }

      const qm = new QuotaManager({
        maxTokens: 1000,
        maxCostUsd: 0.02,
        maxCalls: 8,
        windowMs: 60000,
      });

      const warnings = await qm.checkFromStore(store);
      expect(warnings.length).toBe(3);
      expect(qm.isExceeded(warnings)).toBe(true);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('默认 windowMs 为 24 小时', () => {
    const qm = new QuotaManager({ maxTokens: 1000 });
    const events = [createEvent()];
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });

  test('配置为 0 或负数的配额不生效', () => {
    const qm = new QuotaManager({
      maxTokens: 0,
      maxCostUsd: -1,
      maxCalls: 0,
      windowMs: 60000,
    });
    const events: UsageEvent[] = [];
    for (let i = 0; i < 100; i++) {
      events.push(createEvent());
    }
    const warnings = qm.check(events);
    expect(warnings).toEqual([]);
  });
});
