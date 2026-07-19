import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { UsageStore, UsageLockError } from '../../../src/usage/store.js';
import { USAGE_FILENAME, type UsageEvent } from '../../../src/usage/types.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-usage-'));
}

function makeEvent(overrides?: Partial<UsageEvent>): UsageEvent {
  return {
    ts: new Date().toISOString(),
    capability: 'scan_llm',
    provider: 'openai',
    model: 'gpt-4',
    prompt_tokens: 100,
    completion_tokens: 50,
    cost_usd: 0.001,
    file_hash: 'abc123',
    scan_id: 'scan-001',
    meta: { key: 'value' },
    ...overrides,
  };
}

describe('usage/store: 基本读写', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('readAll() 空文件返回空数组', async () => {
    const store = new UsageStore(join(dir, USAGE_FILENAME));
    const events = await store.readAll();
    expect(events).toEqual([]);
  });

  test('append + readAll 基本读写', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    const event = makeEvent({ capability: 'poc_gen' });
    await store.append(event);
    const events = await store.readAll();
    expect(events.length).toBe(1);
    expect(events[0].capability).toBe('poc_gen');
    expect(events[0].provider).toBe('openai');
  });

  test('append 自动补 ts 字段', async () => {
    const path = join(dir, USAGE_FILENAME);
    const before = new Date().toISOString();
    const store = new UsageStore(path);
    const event: UsageEvent = { capability: 'explain' };
    await store.append(event);
    const events = await store.readAll();
    expect(events.length).toBe(1);
    expect(events[0].ts).toBeDefined();
    expect(events[0].ts >= before).toBe(true);
  });

  test('追加多条事件，顺序正确', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    for (let i = 0; i < 5; i++) {
      await store.append(makeEvent({ capability: `cap-${i}` }));
    }
    const events = await store.readAll();
    expect(events.length).toBe(5);
    expect(events.map(e => e.capability)).toEqual(['cap-0', 'cap-1', 'cap-2', 'cap-3', 'cap-4']);
  });
});

describe('usage/store: 损坏行跳过', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('损坏 JSON 行被跳过，不崩溃', async () => {
    const path = join(dir, USAGE_FILENAME);
    const badLines = [
      JSON.stringify(makeEvent({ capability: 'good-1' })),
      '{not valid json',
      JSON.stringify(makeEvent({ capability: 'good-2' })),
      'also bad',
      JSON.stringify(makeEvent({ capability: 'good-3' })),
    ].join('\n') + '\n';
    writeFileSync(path, badLines);

    const store = new UsageStore(path);
    const events = await store.readAll();
    expect(events.length).toBe(3);
    expect(events[0].capability).toBe('good-1');
    expect(events[1].capability).toBe('good-2');
    expect(events[2].capability).toBe('good-3');
  });

  test('空行被跳过', async () => {
    const path = join(dir, USAGE_FILENAME);
    const content = [
      JSON.stringify(makeEvent({ capability: 'a' })),
      '',
      '   ',
      JSON.stringify(makeEvent({ capability: 'b' })),
      '',
    ].join('\n');
    writeFileSync(path, content);

    const store = new UsageStore(path);
    const events = await store.readAll();
    expect(events.length).toBe(2);
  });
});

describe('usage/store: 时间过滤 since/until', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('since 过滤：只返回指定时间之后的事件', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    // Pin since to 1s before all appends happen. The naive
    // 'new Date() after awaits' is timing-fragile — the 'now' event's
    // ts can land microseconds before the post-await Date.now(), failing
    // the strict ts < since filter (same fix as tests/unit/audit/logger).
    const since = new Date(Date.now() - 1000);
    const oldDate = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const newDate = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await store.append(makeEvent({ ts: oldDate.toISOString(), capability: 'old' }));
    await store.append(makeEvent({ capability: 'now' }));
    await store.append(makeEvent({ ts: newDate.toISOString(), capability: 'future' }));

    const events = await store.readAll({ since });
    expect(events.length).toBe(2);
    expect(events.map(e => e.capability).sort()).toEqual(['future', 'now']);
  });

  test('until 过滤：只返回指定时间之前的事件', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    const oldDate = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const newDate = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await store.append(makeEvent({ ts: oldDate.toISOString(), capability: 'old' }));
    await store.append(makeEvent({ capability: 'now' }));
    await store.append(makeEvent({ ts: newDate.toISOString(), capability: 'future' }));

    const until = new Date();
    const events = await store.readAll({ until });
    expect(events.length).toBe(2);
    expect(events.map(e => e.capability).sort()).toEqual(['now', 'old']);
  });

  test('since + until 同时使用', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    const d1 = new Date(Date.now() - 1000 * 60 * 60 * 48);
    const d2 = new Date(Date.now() - 1000 * 60 * 60 * 24);
    const d3 = new Date(Date.now() + 1000 * 60 * 60 * 24);

    await store.append(makeEvent({ ts: d1.toISOString(), capability: 'too-old' }));
    await store.append(makeEvent({ ts: d2.toISOString(), capability: 'in-range' }));
    await store.append(makeEvent({ ts: d3.toISOString(), capability: 'too-new' }));

    const since = new Date(Date.now() - 1000 * 60 * 60 * 36);
    const until = new Date(Date.now() + 1000 * 60 * 60 * 12);
    const events = await store.readAll({ since, until });
    expect(events.length).toBe(1);
    expect(events[0].capability).toBe('in-range');
  });
});

describe('usage/store: rotate 归档逻辑', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('文件未超过阈值不归档', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    await store.append(makeEvent());
    const archived = await store.rotate(1024 * 1024);
    expect(archived).toBe(0);
    expect(existsSync(path)).toBe(true);
  });

  test('文件超过阈值归档为 .1', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    for (let i = 0; i < 10; i++) {
      await store.append(makeEvent({ capability: `evt-${i}` }));
    }

    const size = statSync(path).size;
    const archived = await store.rotate(size - 1);
    expect(archived).toBe(10);
    expect(existsSync(path)).toBe(false);

    const archivePath = join(dir, '.vule-usage.1.jsonl');
    expect(existsSync(archivePath)).toBe(true);
    const lines = readFileSync(archivePath, 'utf-8').split('\n').filter(l => l.trim());
    expect(lines.length).toBe(10);
  });

  test('多次轮转，最多保留 3 个归档', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    for (let round = 1; round <= 5; round++) {
      for (let i = 0; i < 5; i++) {
        await store.append(makeEvent({ capability: `r${round}-${i}` }));
      }
      const size = statSync(path).size;
      await store.rotate(size - 1);
    }

    expect(existsSync(join(dir, '.vule-usage.1.jsonl'))).toBe(true);
    expect(existsSync(join(dir, '.vule-usage.2.jsonl'))).toBe(true);
    expect(existsSync(join(dir, '.vule-usage.3.jsonl'))).toBe(true);
    expect(existsSync(join(dir, '.vule-usage.4.jsonl'))).toBe(false);
    expect(existsSync(join(dir, '.vule-usage.5.jsonl'))).toBe(false);
  });

  test('空文件 rotate 返回 0', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    const archived = await store.rotate(100);
    expect(archived).toBe(0);
  });
});

describe('usage/store: 并发 append 不丢数据', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('100 个并发 append 不丢数据', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path, { lockRetries: 50, lockBackoffMs: 10 });

    const count = 100;
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(store.append(makeEvent({ capability: `evt-${i}` })));
    }
    await Promise.all(promises);

    const events = await store.readAll();
    expect(events.length).toBe(count);

    const capabilities = new Set(events.map(e => e.capability));
    expect(capabilities.size).toBe(count);
  });

  test('多个实例并发写入不丢数据', async () => {
    const path = join(dir, USAGE_FILENAME);
    const a = new UsageStore(path, { lockRetries: 50, lockBackoffMs: 10 });
    const b = new UsageStore(path, { lockRetries: 50, lockBackoffMs: 10 });

    const count = 50;
    const promises = [];
    for (let i = 0; i < count; i++) {
      promises.push(a.append(makeEvent({ capability: `a-${i}` })));
      promises.push(b.append(makeEvent({ capability: `b-${i}` })));
    }
    await Promise.all(promises);

    const events = await new UsageStore(path).readAll();
    expect(events.length).toBe(count * 2);
  });
});

describe('usage/store: stream 迭代器', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('stream 正常迭代所有事件', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    for (let i = 0; i < 5; i++) {
      await store.append(makeEvent({ capability: `evt-${i}` }));
    }

    const events: UsageEvent[] = [];
    for await (const e of store.stream()) {
      events.push(e);
    }
    expect(events.length).toBe(5);
    expect(events.map(e => e.capability)).toEqual(['evt-0', 'evt-1', 'evt-2', 'evt-3', 'evt-4']);
  });

  test('stream 带 filter 过滤', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    await store.append(makeEvent({ capability: 'scan_llm' }));
    await store.append(makeEvent({ capability: 'poc_gen' }));
    await store.append(makeEvent({ capability: 'scan_llm' }));
    await store.append(makeEvent({ capability: 'report' }));

    const events: UsageEvent[] = [];
    for await (const e of store.stream(ev => ev.capability === 'scan_llm')) {
      events.push(e);
    }
    expect(events.length).toBe(2);
    expect(events.every(e => e.capability === 'scan_llm')).toBe(true);
  });

  test('stream 空文件返回空', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);

    const events: UsageEvent[] = [];
    for await (const e of store.stream()) {
      events.push(e);
    }
    expect(events).toEqual([]);
  });

  test('stream 遇到损坏行跳过', async () => {
    const path = join(dir, USAGE_FILENAME);
    const content = [
      JSON.stringify(makeEvent({ capability: 'good-1' })),
      'bad json line',
      JSON.stringify(makeEvent({ capability: 'good-2' })),
    ].join('\n') + '\n';
    writeFileSync(path, content);

    const store = new UsageStore(path);
    const events: UsageEvent[] = [];
    for await (const e of store.stream()) {
      events.push(e);
    }
    expect(events.length).toBe(2);
  });
});

describe('usage/store: 锁机制', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('手动 acquireLock 后再次获取抛 UsageLockError', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path, { lockRetries: 1, lockBackoffMs: 5 });
    await store.acquireLock();
    let err: unknown = null;
    try {
      await store.acquireLock();
    } catch (e) {
      err = e;
    }
    await store.releaseLock();
    expect(err instanceof UsageLockError).toBe(true);
  });

  test('releaseLock 后可以再次获取锁', async () => {
    const path = join(dir, USAGE_FILENAME);
    const store = new UsageStore(path);
    await store.acquireLock();
    await store.releaseLock();
    await store.acquireLock();
    await store.releaseLock();
  });

  test('默认路径为 cwd/.vule-usage.jsonl', () => {
    const store = new UsageStore();
    expect(store.filePath).toBe(join(process.cwd(), USAGE_FILENAME));
  });
});
