import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { scanCommand, parseScanArgs } from '../../../src/cli.js';
import { StateManager } from '../../../src/state/manager.js';
import { DEFAULT_STATE_FILENAME } from '../../../src/state/types.js';
import type { SpawnRunner, PortProbe } from '../../../src/poc/runner.js';
import type { VulnerabilityFinding } from '../../../src/engine/analyzer.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-pocstate-'));
}

function writeVulnerablePy(dir: string, name = 'vuln.py'): string {
  const file = join(dir, name);
  writeFileSync(file, `import os
user_input = os.environ.get("INPUT", "")
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
os.system("echo " + user_input)
os.system("ping " + user_input)
`);
  return file;
}

function makeVerifyOutput(verified: Record<string, boolean>): string {
  return JSON.stringify({
    tool: 'security-vule + PoC verification',
    mode: 'mock',
    target: 'http://localhost:8080',
    total_findings: Object.keys(verified).length,
    verified: Object.values(verified).filter(v => v).length,
    unverified: Object.values(verified).filter(v => !v).length,
    unconfirmed: 0,
    findings: Object.entries(verified).map(([fp, v]) => {
      const [file, line, type] = fp.split(':');
      return {
        finding: { id: fp, type, severity: 'HIGH', title: 't', description: 'd', file, line: Number(line), confidence: 0.9 },
        verification: { verified: v, pocs_attempted: 1, pocs_verified: v ? 1 : 0, details: [] },
      };
    }),
  });
}

describe('cli: parseScanArgs — PoC flags', () => {
  test('defaults: withPoc=false, pocTarget=none, pocAutoConfirm=false', () => {
    const r = parseScanArgs(['/tmp/x']);
    expect((r as any).withPoc).toBe(false);
    expect((r as any).pocTarget).toBe('none');
    expect((r as any).pocAutoConfirm).toBe(false);
  });
  test('--with-poc sets withPoc=true', () => {
    const r = parseScanArgs(['/tmp/x', '--with-poc']);
    expect((r as any).withPoc).toBe(true);
  });
  test('--poc-target=mock sets pocTarget=mock', () => {
    const r = parseScanArgs(['/tmp/x', '--poc-target=mock']);
    expect((r as any).pocTarget).toBe('mock');
  });
  test('--poc-target=auto sets pocTarget=auto', () => {
    const r = parseScanArgs(['/tmp/x', '--poc-target=auto']);
    expect((r as any).pocTarget).toBe('auto');
  });
  test('--poc-target=none sets pocTarget=none', () => {
    const r = parseScanArgs(['/tmp/x', '--poc-target=none']);
    expect((r as any).pocTarget).toBe('none');
  });
  test('returns error on invalid --poc-target value', () => {
    const r = parseScanArgs(['/tmp/x', '--poc-target=foo']);
    expect('error' in r).toBe(true);
  });
  test('--poc-auto-confirm sets pocAutoConfirm=true', () => {
    const r = parseScanArgs(['/tmp/x', '--poc-auto-confirm']);
    expect((r as any).pocAutoConfirm).toBe(true);
  });
});

describe('cli: scanCommand — PoC auto-confirm wiring', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('--poc-auto-confirm without --with-poc exits 2 with error', async () => {
    let err = '';
    const origErr = console.error;
    (console as any).error = (...a: any[]) => { err += a.join(' ') + '\n'; };
    try {
      const code = await scanCommand([dir, '--poc-auto-confirm']);
      expect(code).toBe(2);
    } finally {
      (console as any).error = origErr;
    }
    expect(err).toContain('--poc-auto-confirm requires --with-poc');
  });

  test('default scan does not create state file', async () => {
    writeVulnerablePy(dir);
    await scanCommand([dir, '--min-confidence', '0']);
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    expect(existsSync(stateFile)).toBe(false);
  });

  test('--with-poc without --poc-auto-confirm does NOT create state file', async () => {
    writeVulnerablePy(dir);
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({}));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock'], deps);
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    expect(existsSync(stateFile)).toBe(false);
  });

  test('--with-poc --poc-auto-confirm writes confirmed status to state file', async () => {
    const file = writeVulnerablePy(dir);
    const absoluteFp = `${file}:4:shell`;
    const relativeFp = `vuln.py:4:shell`;
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({ [absoluteFp]: true }));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    let capturedOut = '';
    const origLog = console.log;
    (console as any).log = (s: string) => { capturedOut += s; };
    try {
      await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock', '--poc-auto-confirm'], deps);
    } finally {
      (console as any).log = origLog;
    }
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    expect(existsSync(stateFile)).toBe(true);
    const state = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(state.fingerprints[relativeFp]).toBeDefined();
    expect(state.fingerprints[relativeFp].status).toBe('confirmed');
    expect(state.fingerprints[relativeFp].note).toBe('PoC verified');
    const summary = JSON.parse(capturedOut);
    expect(summary.poc.verified).toBeGreaterThanOrEqual(1);
  });

  test('auto-confirm only marks proven findings, leaves unproven untouched', async () => {
    const file = writeVulnerablePy(dir);
    const absoluteProvenFp = `${file}:4:shell`;
    const absoluteOtherFp = `${file}:99:other`;
    const relativeProvenFp = `vuln.py:4:shell`;
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({ [absoluteProvenFp]: true, [absoluteOtherFp]: false }));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock', '--poc-auto-confirm'], deps);
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    const state = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(state.fingerprints[relativeProvenFp]?.status).toBe('confirmed');
    expect(Object.keys(state.fingerprints).length).toBe(1);
  });

  test('without --poc-target the state file is never written', async () => {
    writeVulnerablePy(dir);
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({}));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=none', '--poc-auto-confirm'], deps);
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    expect(existsSync(stateFile)).toBe(false);
  });

  test('does not write state file when PoC subprocess fails (graceful degradation)', async () => {
    writeVulnerablePy(dir);
    const runner: SpawnRunner = async () => { throw new Error('python3 missing'); };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    const origErr = console.error;
    let err = '';
    (console as any).error = (...a: any[]) => { err += a.join(' ') + '\n'; };
    try {
      const code = await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock', '--poc-auto-confirm'], deps);
      expect(code).toBeGreaterThanOrEqual(0);
    } finally {
      (console as any).error = origErr;
    }
    expect(err).toContain('python3 missing');
    const stateFile = join(dir, DEFAULT_STATE_FILENAME);
    expect(existsSync(stateFile)).toBe(false);
  });

  test('auto-confirm uses --state-file override when provided', async () => {
    const file = writeVulnerablePy(dir);
    const customState = join(dir, 'custom-state.json');
    const absoluteFp = `${file}:4:shell`;
    const relativeFp = `vuln.py:4:shell`;
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({ [absoluteFp]: true }));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock', '--poc-auto-confirm', '--state-file', customState], deps);
    expect(existsSync(customState)).toBe(true);
    const state = JSON.parse(readFileSync(customState, 'utf-8'));
    expect(state.fingerprints[relativeFp]?.status).toBe('confirmed');
  });
});

describe('cli: scanCommand — PoC output is not a regression', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('default scan output JSON has no poc field', async () => {
    writeVulnerablePy(dir);
    let captured = '';
    const origLog = console.log;
    (console as any).log = (s: string) => { captured += s; };
    try {
      await scanCommand([dir, '--min-confidence', '0']);
    } finally {
      (console as any).log = origLog;
    }
    const parsed = JSON.parse(captured);
    expect(parsed.poc).toBeUndefined();
    expect(parsed.findings).toBeDefined();
  });

  test('with --with-poc, JSON output has poc summary', async () => {
    writeVulnerablePy(dir);
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({}));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    let captured = '';
    const origLog = console.log;
    (console as any).log = (s: string) => { captured += s; };
    try {
      await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock'], deps);
    } finally {
      (console as any).log = origLog;
    }
    const parsed = JSON.parse(captured);
    expect(parsed.poc).toBeDefined();
    expect(parsed.poc.verified).toBeDefined();
    expect(parsed.poc.unverified).toBeDefined();
  });

  test('each finding has exploit_proven + poc_mark when --with-poc set', async () => {
    const file = writeVulnerablePy(dir);
    const fp = `${file}:4:shell`;
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], makeVerifyOutput({ [fp]: true }));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const deps = { runner, probe } as any;
    let captured = '';
    const origLog = console.log;
    (console as any).log = (s: string) => { captured += s; };
    try {
      await scanCommand([dir, '--min-confidence', '0', '--with-poc', '--poc-target=mock'], deps);
    } finally {
      (console as any).log = origLog;
    }
    const parsed = JSON.parse(captured);
    expect(parsed.findings.length).toBeGreaterThan(0);
    for (const f of parsed.findings) {
      expect('exploit_proven' in f).toBe(true);
      expect('poc_mark' in f).toBe(true);
    }
  });
});
