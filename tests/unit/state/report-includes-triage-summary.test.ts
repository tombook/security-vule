import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative } from 'path';
import { scanCommand } from '../../../src/cli.js';
import { StateManager } from '../../../src/state/manager.js';

const VULN_PY = `def run():\n    data = input()\n    eval(data)\n`;

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-report-'));
}

async function captureStderr(fn: () => Promise<unknown>): Promise<string> {
  const orig = console.error;
  let captured = '';
  (console as any).error = (...args: any[]) => { captured += args.join(' ') + '\n'; };
  try { await fn(); } finally { (console as any).error = orig; }
  return captured;
}

async function captureStdout(fn: () => Promise<unknown>): Promise<string> {
  const orig = console.log;
  let captured = '';
  (console as any).log = (...args: any[]) => { captured += args.join(' '); };
  try { await fn(); } finally { (console as any).log = orig; }
  return captured;
}

describe('cli: report header includes triage summary', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('prints "Open: N · Confirmed: N · Fixed: N · WontFix: N · FP: N" header on stderr', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const stderr = await captureStderr(async () => {
      await scanCommand([dir]);
    });
    expect(stderr).toMatch(/Open:\s+\d+\s+·\s+Confirmed:\s+\d+\s+·\s+Fixed:\s+\d+\s+·\s+WontFix:\s+\d+\s+·\s+FP:\s+\d+/);
  });

  test('header reflects state changes (1 fixed, 1 open default)', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'fixed');
    const stderr = await captureStderr(async () => {
      await scanCommand([dir]);
    });
    expect(stderr).toMatch(/Open:\s+0\s+·\s+Confirmed:\s+0\s+·\s+Fixed:\s+1\s+·\s+WontFix:\s+0\s+·\s+FP:\s+0/);
  });

  test('JSON report contains triage block with all 5 statuses', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const out = await captureStdout(async () => {
      await scanCommand([dir]);
    });
    const parsed = JSON.parse(out);
    expect(parsed.triage).toBeDefined();
    expect(parsed.triage.open).toBeGreaterThanOrEqual(0);
    expect(parsed.triage.confirmed).toBeGreaterThanOrEqual(0);
    expect(parsed.triage.fixed).toBeGreaterThanOrEqual(0);
    expect(parsed.triage.wontfix).toBeGreaterThanOrEqual(0);
    expect(parsed.triage.false_positive).toBeGreaterThanOrEqual(0);
  });
});

describe('cli: SARIF output includes triageState', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('SARIF result properties include triageState for state-marked findings', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'confirmed', 'verified', 'alice');

    const outFile = join(dir, 'out.sarif');
    const stdout = await captureStdout(async () => {
      await scanCommand([dir, '--sarif', '-o', outFile]);
    });
    expect(stdout).toBe('');
    const sarif = JSON.parse(readFileSync(outFile, 'utf-8'));
    const target = initial.findings[0];
    const partial = `${relative(process.cwd(), target.file)}:${target.line}:${target.type}`;
    const result = sarif.runs[0].results.find((r: any) =>
      r.partialFingerprints?.includes(partial)
    );
    expect(result).toBeDefined();
    expect(result.properties.triageState).toBe('confirmed');
  });

  test('SARIF result with no state has no triageState property', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const outFile = join(dir, 'out.sarif');
    await captureStdout(async () => {
      await scanCommand([dir, '--sarif', '-o', outFile]);
    });
    const sarif = JSON.parse(readFileSync(outFile, 'utf-8'));
    const result = sarif.runs[0].results[0];
    expect(result.properties.triageState).toBeUndefined();
  });

  test('SARIF result with status=fixed carries triageState="fixed"', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'fixed');

    const outFile = join(dir, 'out.sarif');
    await captureStdout(async () => {
      await scanCommand([dir, '--sarif', '--status=fixed', '-o', outFile]);
    });
    const sarif = JSON.parse(readFileSync(outFile, 'utf-8'));
    expect(sarif.runs[0].results.length).toBe(1);
    expect(sarif.runs[0].results[0].properties.triageState).toBe('fixed');
  });
});

describe('cli: report smoke (no regression)', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('JSON output still contains target/files_scanned/total_findings/findings', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const out = await captureStdout(async () => {
      await scanCommand([dir]);
    });
    const parsed = JSON.parse(out);
    expect(parsed.target).toBe(dir);
    expect(typeof parsed.files_scanned).toBe('number');
    expect(typeof parsed.total_findings).toBe('number');
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  test('output --output FILE still works alongside --status', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const outFile = join(dir, 'out.json');
    const exit = await scanCommand([dir, '-o', outFile, '--status=open']);
    expect(exit).toBeGreaterThanOrEqual(0);
    const data = JSON.parse(readFileSync(outFile, 'utf-8'));
    expect(data.triage).toBeDefined();
  });
});