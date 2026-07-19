import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { AuditLogger, AuditLockError } from '../../../src/audit/logger.js';
import { AUDIT_FILENAME, type AuditEvent } from '../../../src/audit/types.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-audit-'));
}

function makeEvent(overrides?: Partial<AuditEvent>): AuditEvent {
  return {
    ts: new Date().toISOString(),
    actor: 'test-user',
    action: 'scan.started',
    target: '/path/to/file',
    result: 'ok',
    meta: { key: 'value' },
    ...overrides,
  };
}

// 简单哈希函数用于测试验证
function simpleHash(data: string): string {
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

describe('audit/logger: 基本 log + readAll', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('readAll() 空文件返回空数组', async () => {
    const logger = new AuditLogger({ filePath: join(dir, AUDIT_FILENAME) });
    const events = await logger.readAll();
    expect(events).toEqual([]);
  });

  test('log + readAll 基本读写', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });
    await logger.log({ action: 'scan.started', target: '/test/path' });
    const events = await logger.readAll();
    expect(events.length).toBe(1);
    expect(events[0].action).toBe('scan.started');
    expect(events[0].target).toBe('/test/path');
  });
});

describe('audit/logger: 自动补 ts、actor 字段', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('自动补 ts 字段', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const before = new Date().toISOString();
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });
    await logger.log({ action: 'scan.completed' });
    const events = await logger.readAll();
    expect(events.length).toBe(1);
    expect(events[0].ts).toBeDefined();
    expect(events[0].ts >= before).toBe(true);
  });

  test('自动补 actor 字段（使用默认值）', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, enableHashChain: false });
    await logger.log({ action: 'scan.started' });
    const events = await logger.readAll();
    expect(events.length).toBe(1);
    expect(events[0].actor).toBeDefined();
    expect(typeof events[0].actor).toBe('string');
  });

  test('使用自定义 actor', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'custom-actor', enableHashChain: false });
    await logger.log({ action: 'scan.started' });
    const events = await logger.readAll();
    expect(events[0].actor).toBe('custom-actor');
  });

  test('log 时传入的 actor 优先', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'default-actor', enableHashChain: false });
    await logger.log({ action: 'scan.started', actor: 'override-actor' });
    const events = await logger.readAll();
    expect(events[0].actor).toBe('override-actor');
  });
});

describe('audit/logger: 哈希链', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('第一条事件 prev_hash = "0"', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    const events = await logger.readAll();
    expect(events.length).toBe(1);
    expect(events[0].prev_hash).toBe('0');
    expect(events[0].hash).toBeDefined();
  });

  test('每条事件 prev_hash = 上一条 hash', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });
    await logger.log({ action: 'poc.generated' });
    const events = await logger.readAll();
    expect(events.length).toBe(3);
    expect(events[0].prev_hash).toBe('0');
    expect(events[1].prev_hash).toBe(events[0].hash);
    expect(events[2].prev_hash).toBe(events[1].hash);
  });

  test('哈希计算正确', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started', target: '/test', result: 'ok', meta: { a: 1 } });
    const events = await logger.readAll();
    expect(events.length).toBe(1);
    // 手动计算预期哈希
    const expectedPayload = ['0', events[0].ts, 'test-user', 'scan.started', '/test', 'ok', JSON.stringify({ a: 1 })].join('|');
    const expectedHash = simpleHash(expectedPayload);
    expect(events[0].hash).toBe(expectedHash);
  });
});

describe('audit/logger: verifyChain', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('正常链返回 valid=true, breakIndex=-1', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });
    await logger.log({ action: 'poc.verified' });
    const result = await logger.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.breakIndex).toBe(-1);
    expect(result.total).toBe(3);
  });

  test('空链返回 valid=true, breakIndex=-1', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, hashFn: simpleHash });
    const result = await logger.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.breakIndex).toBe(-1);
    expect(result.total).toBe(0);
  });

  test('篡改中间一条后能检测到断点', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });
    await logger.log({ action: 'poc.verified' });

    // 篡改第二条事件的 action
    const content = readFileSync(path, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    const secondEvent = JSON.parse(lines[1]);
    secondEvent.action = 'tampered.action';
    lines[1] = JSON.stringify(secondEvent);
    writeFileSync(path, lines.join('\n') + '\n');

    const result = await logger.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.breakIndex).toBe(1);
    expect(result.total).toBe(3);
  });

  test('篡改第一条事件的 prev_hash 能检测到', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });

    // 篡改第一条事件的 prev_hash
    const content = readFileSync(path, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    const firstEvent = JSON.parse(lines[0]);
    firstEvent.prev_hash = 'tampered';
    lines[0] = JSON.stringify(firstEvent);
    writeFileSync(path, lines.join('\n') + '\n');

    const result = await logger.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.breakIndex).toBe(0);
  });
});

describe('audit/logger: since/until/action 过滤', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('since 过滤：只返回指定时间之后的事件', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });

    // Pin since to 1s before all logging happens. The naive 'new Date()
    // after the awaits' was timing-fragile: now-action's internal ts
    // could land microseconds before the post-await new Date(), failing
    // the strict ts < since filter.
    const since = new Date(Date.now() - 1000);
    const oldDate = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const newDate = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await logger.log({ action: 'old-action', ts: oldDate.toISOString() });
    await logger.log({ action: 'now-action' });
    await logger.log({ action: 'future-action', ts: newDate.toISOString() });

    const events = await logger.readAll({ since });
    expect(events.length).toBe(2);
    expect(events.map(e => e.action).sort()).toEqual(['future-action', 'now-action']);
  });

  test('until 过滤：只返回指定时间之前的事件', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });

    const oldDate = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const newDate = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await logger.log({ action: 'old-action', ts: oldDate.toISOString() });
    await logger.log({ action: 'now-action' });
    await logger.log({ action: 'future-action', ts: newDate.toISOString() });

    const until = new Date();
    const events = await logger.readAll({ until });
    expect(events.length).toBe(2);
    expect(events.map(e => e.action).sort()).toEqual(['now-action', 'old-action']);
  });

  test('action 过滤：只返回指定 action 的事件', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });

    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'poc.generated' });

    const events = await logger.readAll({ action: 'scan.started' });
    expect(events.length).toBe(2);
    expect(events.every(e => e.action === 'scan.started')).toBe(true);
  });

  test('since + until + action 同时使用', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });

    const d1 = new Date(Date.now() - 1000 * 60 * 60 * 48);
    const d2 = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const d3 = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await logger.log({ action: 'scan.started', ts: d1.toISOString() });
    await logger.log({ action: 'scan.started', ts: d2.toISOString() });
    await logger.log({ action: 'poc.generated', ts: d2.toISOString() });
    await logger.log({ action: 'scan.started', ts: d3.toISOString() });

    const since = new Date(Date.now() - 1000 * 60 * 60 * 36);
    const until = new Date(Date.now() + 1000 * 60 * 60 * 12);
    const events = await logger.readAll({ since, until, action: 'scan.started' });
    expect(events.length).toBe(1);
    expect(events[0].action).toBe('scan.started');
  });
});

describe('audit/logger: 并发 log 不丢数据', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('50 个并发 Promise.all 不丢数据', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });

    const count = 50;
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(logger.log({ action: `evt-${i}` }));
    }
    await Promise.all(promises);

    const events = await logger.readAll();
    expect(events.length).toBe(count);

    const actions = new Set(events.map(e => e.action));
    expect(actions.size).toBe(count);
  });

  test('多个实例并发写入不丢数据', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const a = new AuditLogger({ filePath: path, actor: 'user-a', enableHashChain: false });
    const b = new AuditLogger({ filePath: path, actor: 'user-b', enableHashChain: false });

    const count = 25;
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(a.log({ action: `a-${i}` }));
      promises.push(b.log({ action: `b-${i}` }));
    }
    await Promise.all(promises);

    const events = await new AuditLogger({ filePath: path, enableHashChain: false }).readAll();
    expect(events.length).toBe(count * 2);
  });

  test('并发写入时哈希链仍然正确', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });

    const count = 20;
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(logger.log({ action: `evt-${i}` }));
    }
    await Promise.all(promises);

    const events = await logger.readAll();
    expect(events.length).toBe(count);

    // 验证哈希链完整性
    const result = await logger.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.breakIndex).toBe(-1);
  });
});

describe('audit/logger: exportTo 导出正确', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('exportTo 导出所有事件', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', hashFn: simpleHash });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });

    const exportPath = join(dir, 'exported-audit.jsonl');
    await logger.exportTo(exportPath);

    expect(existsSync(exportPath)).toBe(true);

    const exportedContent = readFileSync(exportPath, 'utf-8');
    const exportedLines = exportedContent.split('\n').filter(l => l.trim());
    expect(exportedLines.length).toBe(2);

    // 验证导出的内容可以正常解析
    const exportedEvents = exportedLines.map(l => JSON.parse(l));
    expect(exportedEvents[0].action).toBe('scan.started');
    expect(exportedEvents[1].action).toBe('scan.completed');
    expect(exportedEvents[0].hash).toBeDefined();
    expect(exportedEvents[1].prev_hash).toBe(exportedEvents[0].hash);
  });

  test('exportTo 空文件导出空文件', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, hashFn: simpleHash });
    const exportPath = join(dir, 'exported-empty.jsonl');
    await logger.exportTo(exportPath);
    expect(existsSync(exportPath)).toBe(true);
    const content = readFileSync(exportPath, 'utf-8');
    expect(content.trim()).toBe('');
  });
});

describe('audit/logger: enableHashChain=false', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('enableHashChain=false 时不计算 hash', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });
    await logger.log({ action: 'scan.started' });
    await logger.log({ action: 'scan.completed' });
    const events = await logger.readAll();
    expect(events.length).toBe(2);
    expect(events[0].hash).toBeUndefined();
    expect(events[0].prev_hash).toBeUndefined();
    expect(events[1].hash).toBeUndefined();
    expect(events[1].prev_hash).toBeUndefined();
  });

  test('enableHashChain=false 时 verifyChain 返回无效', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, actor: 'test-user', enableHashChain: false });
    await logger.log({ action: 'scan.started' });
    const result = await logger.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.breakIndex).toBe(0);
  });
});

describe('audit/logger: 损坏行跳过', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('损坏 JSON 行被跳过，不崩溃', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const badLines = [
      JSON.stringify(makeEvent({ action: 'good-1', actor: 'test' })),
      '{not valid json',
      JSON.stringify(makeEvent({ action: 'good-2', actor: 'test' })),
      'also bad',
      JSON.stringify(makeEvent({ action: 'good-3', actor: 'test' })),
    ].join('\n') + '\n';
    writeFileSync(path, badLines);

    const logger = new AuditLogger({ filePath: path, enableHashChain: false });
    const events = await logger.readAll();
    expect(events.length).toBe(3);
    expect(events[0].action).toBe('good-1');
    expect(events[1].action).toBe('good-2');
    expect(events[2].action).toBe('good-3');
  });

  test('空行被跳过', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const content = [
      JSON.stringify(makeEvent({ action: 'a', actor: 'test' })),
      '',
      '   ',
      JSON.stringify(makeEvent({ action: 'b', actor: 'test' })),
      '',
    ].join('\n');
    writeFileSync(path, content);

    const logger = new AuditLogger({ filePath: path, enableHashChain: false });
    const events = await logger.readAll();
    expect(events.length).toBe(2);
  });
});

describe('audit/logger: 其他特性', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('filePath getter 返回正确路径', () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path });
    expect(logger.filePath).toBe(path);
  });

  test('默认路径为 cwd/.vule-audit.jsonl', () => {
    const logger = new AuditLogger();
    expect(logger.filePath).toBe(join(process.cwd(), AUDIT_FILENAME));
  });

  test('手动 acquireLock 后再次获取抛 AuditLockError', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path, lockRetries: 1, lockBackoffMs: 5 } as any);
    await logger.acquireLock();
    let err: unknown = null;
    try {
      await logger.acquireLock();
    } catch (e) {
      err = e;
    }
    await logger.releaseLock();
    expect(err instanceof AuditLockError).toBe(true);
  });

  test('releaseLock 后可以再次获取锁', async () => {
    const path = join(dir, AUDIT_FILENAME);
    const logger = new AuditLogger({ filePath: path });
    await logger.acquireLock();
    await logger.releaseLock();
    await logger.acquireLock();
    await logger.releaseLock();
  });
});
