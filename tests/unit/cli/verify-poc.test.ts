import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  parseVerifyPocOutput,
  mergeFindings,
  detectTargetHealth,
  runPoCVerification,
  isPoCTarget,
  fingerprintOf,
  type SpawnRunner,
  type PortProbe,
  type PoCVerificationOutput,
} from '../../../src/poc/runner.js';
import { verifyPocCommand } from '../../../src/cli.js';
import type { VulnerabilityFinding } from '../../../src/engine/analyzer.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-poc-'));
}

const sampleFindings: VulnerabilityFinding[] = [
  { id: 'f1', type: 'sqli', severity: 'CRITICAL', title: 'SQLi', description: 'a', file: 'a.php', line: 10, confidence: 0.9 },
  { id: 'f2', type: 'xss', severity: 'HIGH', title: 'XSS', description: 'b', file: 'a.php', line: 22, confidence: 0.8 },
  { id: 'f3', type: 'fileinclude', severity: 'MEDIUM', title: 'LFI', description: 'c', file: 'b.php', line: 5, confidence: 0.7 },
];

function makeVerifyOutput(over: Partial<PoCVerificationOutput> = {}): PoCVerificationOutput {
  return {
    tool: 'security-vule + PoC verification',
    mode: 'mock',
    target: 'http://localhost:8080',
    total_findings: 2,
    verified: 1,
    unverified: 1,
    unconfirmed: 0,
    findings: [
      {
        finding: { id: 'f1', type: 'sqli', severity: 'CRITICAL', title: 'SQLi', description: 'a', file: 'a.php', line: 10, confidence: 0.9 } as any,
        verification: { verified: true, pocs_attempted: 2, pocs_verified: 1, details: [] },
      },
      {
        finding: { id: 'f2', type: 'xss', severity: 'HIGH', title: 'XSS', description: 'b', file: 'a.php', line: 22, confidence: 0.8 } as any,
        verification: { verified: false, pocs_attempted: 2, pocs_verified: 0, details: [] },
      },
    ],
    ...over,
  };
}

describe('poc/runner: isPoCTarget', () => {
  test('accepts valid targets', () => {
    for (const v of ['mock', 'dvwa', 'bwapp', 'sqlilabs', 'pikachu', 'auto', 'none']) {
      expect(isPoCTarget(v)).toBe(true);
    }
  });
  test('rejects invalid targets', () => {
    expect(isPoCTarget('foo')).toBe(false);
    expect(isPoCTarget('')).toBe(false);
  });
});

describe('poc/runner: parseVerifyPocOutput', () => {
  test('parses a valid output', () => {
    const out = makeVerifyOutput();
    const parsed = parseVerifyPocOutput(JSON.stringify(out));
    expect(parsed).not.toBeNull();
    expect(parsed!.verified).toBe(1);
    expect(parsed!.unverified).toBe(1);
    expect(parsed!.findings.length).toBe(2);
  });
  test('returns null on empty input', () => {
    expect(parseVerifyPocOutput('')).toBeNull();
    expect(parseVerifyPocOutput('   ')).toBeNull();
  });
  test('returns null on invalid JSON', () => {
    expect(parseVerifyPocOutput('not-json{')).toBeNull();
  });
  test('returns null when findings array missing', () => {
    expect(parseVerifyPocOutput(JSON.stringify({ ok: true }))).toBeNull();
  });
  test('tolerates non-object input', () => {
    expect(parseVerifyPocOutput('null')).toBeNull();
    expect(parseVerifyPocOutput('123')).toBeNull();
  });
});

describe('poc/runner: mergeFindings', () => {
  test('marks verified findings as ✅', () => {
    const merged = mergeFindings(sampleFindings, makeVerifyOutput());
    const sqli = merged.find(m => m.id === 'f1');
    expect(sqli!.exploit_proven).toBe(true);
    expect(sqli!.poc_mark).toBe('✅ verified');
  });
  test('marks failed findings as ❌', () => {
    const merged = mergeFindings(sampleFindings, makeVerifyOutput());
    const xss = merged.find(m => m.id === 'f2');
    expect(xss!.exploit_proven).toBe(false);
    expect(xss!.poc_mark).toBe('❌ not exploited');
  });
  test('marks unmatched findings as ⚠️', () => {
    const merged = mergeFindings(sampleFindings, makeVerifyOutput());
    const lfi = merged.find(m => m.id === 'f3');
    expect(lfi!.exploit_proven).toBeNull();
    expect(lfi!.poc_mark).toBe('⚠️ not verified');
  });
  test('handles empty verification findings as ⚠️ for all', () => {
    const merged = mergeFindings(sampleFindings, makeVerifyOutput({ findings: [], verified: 0, unverified: 0, unconfirmed: sampleFindings.length }));
    for (const m of merged) {
      expect(m.exploit_proven).toBeNull();
      expect(m.poc_mark).toBe('⚠️ not verified');
    }
  });
  test('preserves original finding fields', () => {
    const merged = mergeFindings(sampleFindings, makeVerifyOutput());
    const sqli = merged.find(m => m.id === 'f1')!;
    expect(sqli.type).toBe('sqli');
    expect(sqli.severity).toBe('CRITICAL');
    expect(sqli.line).toBe(10);
    expect(sqli.file).toBe('a.php');
  });
  test('fingerprint is file:line:type', () => {
    expect(fingerprintOf({ file: 'a.php', line: 10, type: 'sqli' })).toBe('a.php:10:sqli');
  });
});

describe('poc/runner: detectTargetHealth', () => {
  const alwaysOpen: PortProbe = async () => true;
  const alwaysClosed: PortProbe = async () => false;

  test('none → unreachable', async () => {
    const h = await detectTargetHealth('none', alwaysOpen);
    expect(h.reachable).toBe(false);
  });
  test('mock reachable when localhost:8080 is open', async () => {
    const h = await detectTargetHealth('mock', alwaysOpen);
    expect(h.reachable).toBe(true);
    expect(h.port).toBe(8080);
    expect(h.host).toBe('localhost');
  });
  test('mock unreachable when localhost:8080 is closed', async () => {
    const h = await detectTargetHealth('mock', alwaysClosed);
    expect(h.reachable).toBe(false);
  });
  test('auto picks mock first when :8080 is open', async () => {
    const h = await detectTargetHealth('auto', alwaysOpen);
    expect(h.reachable).toBe(true);
    expect(h.port).toBe(8080);
  });
  test('auto scans other targets when :8080 closed', async () => {
    const openSome: PortProbe = async (h, p) => p === 8081;
    const h = await detectTargetHealth('auto', openSome);
    expect(h.reachable).toBe(true);
    expect(h.port).toBe(8081);
  });
  test('auto returns unreachable when no port open', async () => {
    const h = await detectTargetHealth('auto', alwaysClosed);
    expect(h.reachable).toBe(false);
  });
  test('unknown target string is unreachable', async () => {
    const h = await detectTargetHealth('nope' as any, alwaysOpen);
    expect(h.reachable).toBe(false);
  });
});

describe('poc/runner: runPoCVerification', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('skips when target=none', async () => {
    const r = await runPoCVerification(sampleFindings, { target: 'none' });
    expect(r.ok).toBe(false);
    expect(r.skipped).toBe('no-target');
  });
  test('skips when target unreachable', async () => {
    const r = await runPoCVerification(sampleFindings, { target: 'mock', probe: async () => false });
    expect(r.ok).toBe(false);
    expect(r.skipped).toBe('no-target');
  });
  test('returns ok with merged findings when spawn succeeds', async () => {
    const outFile = join(dir, 'out.json');
    const findingsFile = join(dir, 'in.json');
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const i = args.indexOf('--findings');
      const o = args.indexOf('--output');
      const fp = args[i + 1];
      const op = args[o + 1];
      const inputRaw = readFileSync(fp, 'utf-8');
      const input = JSON.parse(inputRaw);
      const out = makeVerifyOutput();
      writeFileSync(op, JSON.stringify(out, null, 2));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const r = await runPoCVerification(sampleFindings, {
      target: 'mock',
      runner,
      probe,
      pythonBin: 'python3',
      scriptPath: 'poc-validator/verify_poc.py',
    });
    expect(r.ok).toBe(true);
    expect(r.merged!.length).toBe(3);
    expect(r.merged!.find(m => m.id === 'f1')!.poc_mark).toBe('✅ verified');
    expect(r.merged!.find(m => m.id === 'f2')!.poc_mark).toBe('❌ not exploited');
    expect(r.merged!.find(m => m.id === 'f3')!.poc_mark).toBe('⚠️ not verified');
  });
  test('returns spawn-failed when runner throws', async () => {
    const runner: SpawnRunner = async () => { throw new Error('boom'); };
    const probe: PortProbe = async () => true;
    const r = await runPoCVerification(sampleFindings, { target: 'mock', runner, probe });
    expect(r.ok).toBe(false);
    expect(r.skipped).toBe('spawn-failed');
    expect(r.message).toContain('boom');
  });
  test('returns spawn-failed when exit code != 0', async () => {
    const runner: SpawnRunner = async () => ({ stdout: '', stderr: 'usage error', exitCode: 2 });
    const probe: PortProbe = async () => true;
    const r = await runPoCVerification(sampleFindings, { target: 'mock', runner, probe });
    expect(r.ok).toBe(false);
    expect(r.skipped).toBe('spawn-failed');
    expect(r.message).toContain('exit 2');
  });
  test('returns parse-failed when output is not valid JSON', async () => {
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], 'not-json');
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const r = await runPoCVerification(sampleFindings, { target: 'mock', runner, probe });
    expect(r.ok).toBe(false);
    expect(r.skipped).toBe('parse-failed');
  });
  test('passes --target flag to runner when target != auto', async () => {
    let capturedCmd: string[] = [];
    const runner: SpawnRunner = async (cmd) => {
      capturedCmd = cmd;
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], JSON.stringify(makeVerifyOutput()));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    await runPoCVerification(sampleFindings, { target: 'dvwa', runner, probe });
    expect(capturedCmd).toContain('--target');
    expect(capturedCmd[capturedCmd.indexOf('--target') + 1]).toBe('dvwa');
  });
  test('does not pass --target flag for auto', async () => {
    let capturedCmd: string[] = [];
    const runner: SpawnRunner = async (cmd) => {
      capturedCmd = cmd;
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], JSON.stringify(makeVerifyOutput()));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    await runPoCVerification(sampleFindings, { target: 'auto', runner, probe });
    expect(capturedCmd).not.toContain('--target');
  });
  test('writes input findings file before spawning', async () => {
    let capturedInput = '';
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const i = args.indexOf('--findings');
      const o = args.indexOf('--output');
      capturedInput = readFileSync(args[i + 1], 'utf-8');
      writeFileSync(args[o + 1], JSON.stringify(makeVerifyOutput()));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    await runPoCVerification(sampleFindings, { target: 'mock', runner, probe });
    const parsed = JSON.parse(capturedInput);
    expect(parsed.findings.length).toBe(3);
    expect(parsed.findings[0].id).toBe('f1');
  });
});

describe('cli: verifyPocCommand', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('--help exits 0 and prints usage', async () => {
    const captured: string[] = [];
    const orig = console.log;
    (console as any).log = (...a: any[]) => { captured.push(a.join(' ')); };
    try {
      const code = await verifyPocCommand(['--help']);
      expect(code).toBe(0);
    } finally {
      (console as any).log = orig;
    }
    expect(captured.join('\n')).toContain('verify-poc');
    expect(captured.join('\n')).toContain('--target');
  });
  test('exits 2 when no findings path', async () => {
    const origErr = console.error;
    let err = '';
    (console as any).error = (...a: any[]) => { err += a.join(' ') + '\n'; };
    try {
      const code = await verifyPocCommand([]);
      expect(code).toBe(2);
    } finally {
      (console as any).error = origErr;
    }
    expect(err).toContain('Usage');
  });
  test('exits 2 when findings file missing', async () => {
    const code = await verifyPocCommand([join(dir, 'missing.json')]);
    expect(code).toBe(2);
  });
  test('exits 2 on invalid --target', async () => {
    const findingsFile = join(dir, 'findings.json');
    writeFileSync(findingsFile, JSON.stringify({ findings: sampleFindings }));
    const code = await verifyPocCommand([findingsFile, '--target=foo']);
    expect(code).toBe(2);
  });
  test('writes ok=false fallback when target unreachable', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify({ findings: sampleFindings }));
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], {
      probe: async () => false,
    });
    expect(code).toBe(1);
    expect(existsSync(outputFile)).toBe(true);
    const out = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(out.ok).toBe(false);
    expect(out.skipped).toBe('no-target');
  });
  test('writes verification result on success', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify({ findings: sampleFindings }));
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], JSON.stringify(makeVerifyOutput()));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], { runner, probe });
    expect(code).toBe(0);
    const out = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(out.ok).toBe(true);
    expect(out.verification.verified).toBe(1);
    expect(out.merged.length).toBe(3);
    expect(out.merged.find((m: any) => m.id === 'f1').poc_mark).toBe('✅ verified');
  });
  test('handles spawn-failed by writing ok=false fallback', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify({ findings: sampleFindings }));
    const runner: SpawnRunner = async () => { throw new Error('python3 not found'); };
    const probe: PortProbe = async () => true;
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], { runner, probe });
    expect(code).toBe(1);
    const out = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(out.ok).toBe(false);
    expect(out.skipped).toBe('spawn-failed');
    expect(out.message).toContain('python3 not found');
  });
  test('handles non-zero exit by writing ok=false fallback', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify({ findings: sampleFindings }));
    const runner: SpawnRunner = async () => ({ stdout: '', stderr: 'crash', exitCode: 3 });
    const probe: PortProbe = async () => true;
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], { runner, probe });
    expect(code).toBe(1);
    const out = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(out.ok).toBe(false);
    expect(out.skipped).toBe('spawn-failed');
  });
  test('reads findings as bare array (not wrapped)', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify(sampleFindings));
    const runner: SpawnRunner = async (cmd) => {
      const args = cmd.slice(2);
      const o = args.indexOf('--output');
      writeFileSync(args[o + 1], JSON.stringify(makeVerifyOutput()));
      return { stdout: '', stderr: '', exitCode: 0 };
    };
    const probe: PortProbe = async () => true;
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], { runner, probe });
    expect(code).toBe(0);
    const out = JSON.parse(readFileSync(outputFile, 'utf-8'));
    expect(out.merged.length).toBe(3);
  });
  test('exits 2 when findings JSON has no findings array', async () => {
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify({ unrelated: true }));
    const code = await verifyPocCommand([findingsFile, '--target=mock', '--output', outputFile], {
      runner: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
      probe: async () => true,
    });
    expect(code).toBe(2);
  });
});
