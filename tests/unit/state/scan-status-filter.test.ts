import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative } from 'path';
import { scanCommand, parseScanArgs, DEFAULT_STATUS_FILTER } from '../../../src/cli.js';
import { StateManager } from '../../../src/state/manager.js';

const VULN_PY = `def run():\n    data = input()\n    eval(data)\n`;

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-scanfilter-'));
}

async function captureStdout(fn: () => Promise<unknown>): Promise<string> {
  const orig = console.log;
  let captured = '';
  (console as any).log = (...args: any[]) => { captured += args.join(' '); };
  try {
    await fn();
  } finally {
    (console as any).log = orig;
  }
  return captured;
}

describe('cli: scan --status filter (default = open + confirmed)', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('default behavior keeps open findings and excludes fixed', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const out = await captureStdout(async () => {
      await scanCommand([dir]);
    });
    const parsed = JSON.parse(out);
    expect(parsed.findings.length).toBeGreaterThanOrEqual(1);
    expect(parsed.triage.open).toBeGreaterThanOrEqual(1);
  });

  test('a finding marked as fixed is hidden by default', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const out = await captureStdout(async () => {
      await scanCommand([dir]);
    });
    const initial = JSON.parse(out);
    expect(initial.findings.length).toBeGreaterThan(0);
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'fixed');
    const out2 = await captureStdout(async () => {
      await scanCommand([dir]);
    });
    const after = JSON.parse(out2);
    expect(after.findings.length).toBe(initial.findings.length - 1);
    expect(after.triage.fixed).toBe(1);
  });

  test('a finding marked as wontfix is hidden by default', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'wontfix');
    const after = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    expect(after.findings.length).toBe(initial.findings.length - 1);
  });

  test('--status=fixed shows only fixed entries', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(fp, 'fixed');
    const after = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir, '--status=fixed']);
    }));
    expect(after.findings.length).toBe(1);
    expect(after.triage.fixed).toBe(1);
  });

  test('--status=open,confirmed,wontfix shows those three classes', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const findings = initial.findings;
    expect(findings.length).toBeGreaterThan(0);
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus(`${relative(dir, findings[0].file)}:${findings[0].line}:${findings[0].type}`, 'wontfix');
    const after = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir, '--status=open,confirmed,wontfix']);
    }));
    expect(after.findings.length).toBe(findings.length);
  });

  test('--status=open shows findings with no state yet (they default to open)', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const out = await captureStdout(async () => {
      await scanCommand([dir, '--status=open']);
    });
    const parsed = JSON.parse(out);
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  test('--state-file overrides default state location', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const custom = join(dir, 'my-state.json');
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    const mgr = new StateManager(custom);
    await mgr.setStatus(fp, 'fixed');
    const after = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir, '--state-file', custom]);
    }));
    expect(after.findings.length).toBe(initial.findings.length - 1);
  });

  test('invalid --status value exits 2', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const exit = await scanCommand([dir, '--status=verified']);
    expect(exit).toBe(2);
  });

  test('--status=fixed,false_positive works with both statuses', async () => {
    const f = join(dir, 'a.py');
    writeFileSync(f, VULN_PY);
    const initial = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir]);
    }));
    expect(initial.findings.length).toBeGreaterThan(0);
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    const fp = `${relative(dir, initial.findings[0].file)}:${initial.findings[0].line}:${initial.findings[0].type}`;
    await mgr.setStatus(fp, 'false_positive');
    const after = JSON.parse(await captureStdout(async () => {
      await scanCommand([dir, '--status=fixed,false_positive']);
    }));
    expect(after.findings.length).toBe(1);
    expect(after.findings[0].type).toBe(initial.findings[0].type);
    expect(after.triage.false_positive).toBe(1);
  });
});

describe('cli: parseScanArgs --status', () => {
  test('default filter is open,confirmed', () => {
    const r = parseScanArgs(['/tmp/x']);
    expect((r as any).statusFilter).toEqual(DEFAULT_STATUS_FILTER);
  });
  test('--status=open,confirmed parses comma list', () => {
    const r = parseScanArgs(['/tmp/x', '--status=open,confirmed']);
    expect((r as any).statusFilter).toEqual(['open', 'confirmed']);
  });
  test('--status=open --status=confirmed appends to filter', () => {
    const r = parseScanArgs(['/tmp/x', '--status=open', '--status=confirmed']);
    expect((r as any).statusFilter).toEqual(['open', 'confirmed']);
  });
  test('invalid status returns error', () => {
    const r = parseScanArgs(['/tmp/x', '--status=verified']);
    expect('error' in r).toBe(true);
  });
});