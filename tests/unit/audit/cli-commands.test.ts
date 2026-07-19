import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { auditCommand, auditHelp } from '../../../src/cli.js';
import { AuditLogger, resetGlobalAuditLogger } from '../../../src/audit/logger.js';
import type { AuditEvent } from '../../../src/audit/types.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-audit-cli-'));
}

async function createTestAuditFile(dir: string, count: number = 5): Promise<string> {
  const auditFile = join(dir, 'test-audit.jsonl');
  const logger = new AuditLogger({ filePath: auditFile });
  const actions = ['scan.started', 'scan.completed', 'finding.state_changed', 'poc.verified', 'llm.called'];
  const baseTime = Date.now();
  for (let i = 0; i < count; i++) {
    await logger.log({
      action: actions[i % actions.length],
      target: `file-${i}.py`,
      result: 'ok',
      meta: { index: i },
      ts: new Date(baseTime - (count - i) * 1000 * 60 * 60).toISOString(),
    });
  }
  return auditFile;
}

describe('audit/cli: auditHelp', () => {
  test('returns help text with list/export/verify', () => {
    const help = auditHelp();
    expect(help).toContain('audit');
    expect(help).toContain('list');
    expect(help).toContain('export');
    expect(help).toContain('verify');
  });
});

describe('audit/cli: audit list --help', () => {
  test('audit list --help 正常输出', async () => {
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['list', '--help']);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.length).toBeGreaterThan(0);
    const all = captures.join('\n');
    expect(all).toContain('list');
    expect(all).toContain('--action');
    expect(all).toContain('--since');
    expect(all).toContain('--until');
    expect(all).toContain('--limit');
  });

  test('audit --help 正常输出', async () => {
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['--help']);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.length).toBeGreaterThan(0);
  });
});

describe('audit/cli: audit list', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
    resetGlobalAuditLogger();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    resetGlobalAuditLogger();
  });

  test('audit list 输出 JSON 数组', async () => {
    const auditFile = await createTestAuditFile(dir, 3);
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['list', '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.length).toBeGreaterThan(0);
    const output = JSON.parse(captures.join('\n'));
    expect(Array.isArray(output)).toBe(true);
    expect(output.length).toBe(3);
  });

  test('audit list --action 过滤正确', async () => {
    const auditFile = await createTestAuditFile(dir, 10);
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['list', '--action', 'scan.started', '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    const output = JSON.parse(captures.join('\n')) as AuditEvent[];
    expect(Array.isArray(output)).toBe(true);
    expect(output.length).toBeGreaterThan(0);
    for (const ev of output) {
      expect(ev.action).toBe('scan.started');
    }
  });

  test('audit list --since 时间过滤', async () => {
    const auditFile = await createTestAuditFile(dir, 5);
    const logger = new AuditLogger({ filePath: auditFile });
    const allEvents = await logger.readAll();
    const midTime = allEvents[2].ts;

    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['list', '--since', midTime, '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    const output = JSON.parse(captures.join('\n')) as AuditEvent[];
    expect(output.length).toBeLessThanOrEqual(3);
    for (const ev of output) {
      expect(new Date(ev.ts).getTime()).toBeGreaterThanOrEqual(new Date(midTime).getTime());
    }
  });

  test('audit list --limit 限制条数', async () => {
    const auditFile = await createTestAuditFile(dir, 10);
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['list', '--limit', '3', '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    const output = JSON.parse(captures.join('\n')) as AuditEvent[];
    expect(output.length).toBe(3);
  });
});

describe('audit/cli: audit export', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
    resetGlobalAuditLogger();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    resetGlobalAuditLogger();
  });

  test('audit export --output 导出文件格式正确', async () => {
    const auditFile = await createTestAuditFile(dir, 5);
    const outputFile = join(dir, 'exported-audit.json');

    const exit = await auditCommand(['export', '--output', outputFile, '--audit-file', auditFile]);
    expect(exit).toBe(0);
    expect(existsSync(outputFile)).toBe(true);

    const data = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(data).toHaveProperty('exported_at');
    expect(data).toHaveProperty('total');
    expect(data).toHaveProperty('events');
    expect(typeof data.exported_at).toBe('string');
    expect(typeof data.total).toBe('number');
    expect(Array.isArray(data.events)).toBe(true);
    expect(data.total).toBe(5);
    expect(data.events.length).toBe(5);
  });

  test('audit export 缺少 --output 返回错误', async () => {
    const auditFile = await createTestAuditFile(dir, 5);
    const exit = await auditCommand(['export', '--audit-file', auditFile]);
    expect(exit).toBe(2);
  });
});

describe('audit/cli: audit verify', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
    resetGlobalAuditLogger();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    resetGlobalAuditLogger();
  });

  test('audit verify 正常链返回 valid=true', async () => {
    const auditFile = await createTestAuditFile(dir, 5);
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['verify', '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    const output = JSON.parse(captures.join('\n'));
    expect(output.valid).toBe(true);
    expect(output.total).toBe(5);
    expect(output.breakIndex).toBe(-1);
  });

  test('audit verify 篡改链返回 valid=false 且 exit code=1', async () => {
    const auditFile = await createTestAuditFile(dir, 5);

    // 篡改审计日志：修改第3条记录的 action
    const lines = readFileSync(auditFile, 'utf-8').split('\n').filter(l => l.trim());
    const tampered = lines.map((line, i) => {
      if (i === 2) {
        const ev = JSON.parse(line);
        ev.action = 'tampered.action';
        return JSON.stringify(ev);
      }
      return line;
    });
    writeFileSync(auditFile, tampered.join('\n') + '\n');

    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await auditCommand(['verify', '--audit-file', auditFile]);
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(1);
    const output = JSON.parse(captures.join('\n'));
    expect(output.valid).toBe(false);
    expect(output.breakIndex).toBe(2);
    expect(output.total).toBe(5);
  });
});

describe('audit/cli: error paths', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
    resetGlobalAuditLogger();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    resetGlobalAuditLogger();
  });

  test('缺少子命令返回 exit code 2', async () => {
    const exit = await auditCommand([]);
    expect(exit).toBe(2);
  });

  test('未知子命令返回 exit code 2', async () => {
    const exit = await auditCommand(['unknown']);
    expect(exit).toBe(2);
  });
});
