import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { generateReport, formatMarkdown, parseTimeArg } from '../../../src/usage/reporter.js';
import { UsageStore } from '../../../src/usage/store.js';
import type { UsageEvent } from '../../../src/usage/types.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-usage-'));
}

function createMockEvents(): UsageEvent[] {
  return [
    {
      capability: 'poc_gen',
      provider: 'openai',
      model: 'gpt-4',
      prompt_tokens: 1000,
      completion_tokens: 500,
      cost_usd: 0.015,
      ts: '2026-06-25T10:00:00.000Z',
      scan_id: 'abc1234567890',
    },
    {
      capability: 'poc_gen',
      provider: 'openai',
      model: 'gpt-4',
      prompt_tokens: 2000,
      completion_tokens: 800,
      cost_usd: 0.028,
      ts: '2026-06-25T11:00:00.000Z',
      scan_id: 'abc1234567890',
    },
    {
      capability: 'ai_triage',
      provider: 'anthropic',
      model: 'claude-3',
      prompt_tokens: 500,
      completion_tokens: 200,
      cost_usd: 0.005,
      ts: '2026-06-24T15:00:00.000Z',
      scan_id: 'def6789012345',
    },
    {
      capability: 'ai_triage',
      provider: 'anthropic',
      model: 'claude-3',
      prompt_tokens: 800,
      completion_tokens: 300,
      cost_usd: 0.008,
      ts: '2026-06-23T09:00:00.000Z',
      scan_id: 'def6789012345',
    },
    {
      capability: 'code_explain',
      provider: 'openai',
      model: 'gpt-3.5-turbo',
      prompt_tokens: 300,
      completion_tokens: 100,
      cost_usd: 0.001,
      ts: '2026-06-22T14:00:00.000Z',
      scan_id: 'ghi1122334455',
    },
  ];
}

describe('usage/reporter: 按 capability 聚合', () => {
  test('应该正确按 capability 分组并聚合', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'capability' });

    expect(report.total_events).toBe(5);
    expect(report.total_prompt_tokens).toBe(1000 + 2000 + 500 + 800 + 300);
    expect(report.total_completion_tokens).toBe(500 + 800 + 200 + 300 + 100);
    expect(report.total_cost_usd).toBeCloseTo(0.015 + 0.028 + 0.005 + 0.008 + 0.001, 5);

    const pocGenGroup = report.groups.find(g => g.key === 'poc_gen');
    expect(pocGenGroup).toBeDefined();
    expect(pocGenGroup!.events).toBe(2);
    expect(pocGenGroup!.prompt_tokens).toBe(3000);
    expect(pocGenGroup!.completion_tokens).toBe(1300);
    expect(pocGenGroup!.total_tokens).toBe(4300);
    expect(pocGenGroup!.cost_usd).toBeCloseTo(0.043, 5);

    const triageGroup = report.groups.find(g => g.key === 'ai_triage');
    expect(triageGroup).toBeDefined();
    expect(triageGroup!.events).toBe(2);

    const explainGroup = report.groups.find(g => g.key === 'code_explain');
    expect(explainGroup).toBeDefined();
    expect(explainGroup!.events).toBe(1);
  });
});

describe('usage/reporter: 按 day 聚合', () => {
  test('应该正确按日期分组', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'day' });

    expect(report.groups.length).toBe(4);

    const day25 = report.groups.find(g => g.key === '2026-06-25');
    expect(day25).toBeDefined();
    expect(day25!.events).toBe(2);

    const day24 = report.groups.find(g => g.key === '2026-06-24');
    expect(day24).toBeDefined();
    expect(day24!.events).toBe(1);
  });
});

describe('usage/reporter: 空事件列表', () => {
  test('空事件应该返回空报告', async () => {
    const report = await generateReport([], { groupBy: 'capability' });

    expect(report.total_events).toBe(0);
    expect(report.total_prompt_tokens).toBe(0);
    expect(report.total_completion_tokens).toBe(0);
    expect(report.total_cost_usd).toBe(0);
    expect(report.groups).toEqual([]);
  });
});

describe('usage/reporter: Markdown 格式', () => {
  test('Markdown 应该包含正确的表头和数字格式', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'capability' });
    const md = formatMarkdown(report, 'capability');

    expect(md).toContain('# AI 用量报告');
    expect(md).toContain('**周期**:');
    expect(md).toContain('**总调用**:');
    expect(md).toContain('**总 token**:');
    expect(md).toContain('**总成本**:');
    expect(md).toContain('## 按 功能 分组');
    expect(md).toContain('| 分组 | 调用次数 | Prompt tokens | Completion tokens | 总成本 |');
    expect(md).toContain('|---|---:|---:|---:|---:|');
    expect(md).toContain('poc_gen');
    expect(md).toContain('$0.0430');
  });

  test('不同 groupBy 应该显示对应标题', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'provider' });
    const md = formatMarkdown(report, 'provider');
    expect(md).toContain('## 按 提供商 分组');

    const report2 = await generateReport(events, { groupBy: 'model' });
    const md2 = formatMarkdown(report2, 'model');
    expect(md2).toContain('## 按 模型 分组');

    const report3 = await generateReport(events, { groupBy: 'day' });
    const md3 = formatMarkdown(report3, 'day');
    expect(md3).toContain('## 按 日期 分组');

    const report4 = await generateReport(events, { groupBy: 'project' });
    const md4 = formatMarkdown(report4, 'project');
    expect(md4).toContain('## 按 项目 分组');
  });
});

describe('usage/reporter: since/until 过滤', () => {
  test('应该正确过滤时间范围内的事件', async () => {
    const events = createMockEvents();
    const since = new Date('2026-06-24T00:00:00.000Z');
    const until = new Date('2026-06-25T23:59:59.999Z');

    const report = await generateReport(events, { groupBy: 'capability', since, until });

    expect(report.total_events).toBe(3);
    expect(report.period.since).toBe('2026-06-24');
    expect(report.period.until).toBe('2026-06-25');
  });

  test('与 mock store 联动测试', async () => {
    const dir = freshDir();
    const usageFile = join(dir, '.vule-usage.jsonl');

    const store = new UsageStore(usageFile);
    const events = createMockEvents();
    for (const e of events) {
      await store.append(e);
    }

    const loaded = await store.readAll();
    expect(loaded.length).toBe(5);

    const since = new Date('2026-06-25T00:00:00.000Z');
    const report = await generateReport(loaded, { groupBy: 'capability', since });

    expect(report.total_events).toBe(2);
    expect(report.groups.length).toBe(1);
    expect(report.groups[0].key).toBe('poc_gen');

    rmSync(dir, { recursive: true, force: true });
  });
});

describe('usage/reporter: 排序', () => {
  test('应该按 cost_usd 降序排列', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'capability' });

    const costs = report.groups.map(g => g.cost_usd);
    const sorted = [...costs].sort((a, b) => b - a);
    expect(costs).toEqual(sorted);
  });
});

describe('usage/reporter: 按 provider/model/project 聚合', () => {
  test('按 provider 聚合，缺失时用 unknown', async () => {
    const events: UsageEvent[] = [
      { capability: 'x', prompt_tokens: 100, completion_tokens: 50, cost_usd: 0.01, ts: '2026-06-25T00:00:00Z', provider: 'openai' },
      { capability: 'y', prompt_tokens: 200, completion_tokens: 100, cost_usd: 0.02, ts: '2026-06-25T00:00:00Z' },
    ];
    const report = await generateReport(events, { groupBy: 'provider' });
    expect(report.groups.map(g => g.key)).toContain('openai');
    expect(report.groups.map(g => g.key)).toContain('unknown');
  });

  test('按 project 聚合，使用 scan_id 前 8 字符', async () => {
    const events = createMockEvents();
    const report = await generateReport(events, { groupBy: 'project' });

    const keys = report.groups.map(g => g.key);
    expect(keys).toContain('abc12345');
    expect(keys).toContain('def67890');
    expect(keys).toContain('ghi11223');
  });
});

describe('usage/reporter: parseTimeArg', () => {
  test('解析相对时间 30d', () => {
    const d = parseTimeArg('30d');
    expect(d).toBeDefined();
    const expected = Date.now() - 30 * 24 * 60 * 60 * 1000;
    expect(Math.abs(d!.getTime() - expected)).toBeLessThan(1000);
  });

  test('解析相对时间 7d', () => {
    const d = parseTimeArg('7d');
    expect(d).toBeDefined();
    const expected = Date.now() - 7 * 24 * 60 * 60 * 1000;
    expect(Math.abs(d!.getTime() - expected)).toBeLessThan(1000);
  });

  test('解析相对时间 24h', () => {
    const d = parseTimeArg('24h');
    expect(d).toBeDefined();
    const expected = Date.now() - 24 * 60 * 60 * 1000;
    expect(Math.abs(d!.getTime() - expected)).toBeLessThan(1000);
  });

  test('解析日期 2026-06-01', () => {
    const d = parseTimeArg('2026-06-01', 'start');
    expect(d).toBeDefined();
    expect(d!.getFullYear()).toBe(2026);
    expect(d!.getMonth()).toBe(5);
    expect(d!.getDate()).toBe(1);
    expect(d!.getHours()).toBe(0);
  });

  test('解析日期作为结束时间', () => {
    const d = parseTimeArg('2026-06-01', 'end');
    expect(d).toBeDefined();
    expect(d!.getHours()).toBe(23);
    expect(d!.getMinutes()).toBe(59);
  });

  test('解析 now', () => {
    const d = parseTimeArg('now');
    expect(d).toBeDefined();
    expect(Math.abs(d!.getTime() - Date.now())).toBeLessThan(1000);
  });

  test('undefined 返回 undefined', () => {
    expect(parseTimeArg(undefined)).toBeUndefined();
  });
});
