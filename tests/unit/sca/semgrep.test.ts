import { describe, test, expect } from 'bun:test';
import {
  SemgrepAdapter,
  parseSemgrepOutput,
  DEFAULT_SEMGREP_ARGS,
  SEMGREP_NAME,
  type SpawnRunner,
} from '../../../src/sca/semgrep.js';

const okRunner: SpawnRunner = async (cmd) => {
  return {
    stdout: JSON.stringify({
      results: [
        {
          check_id: 'python.lang.security.audit.eval',
          path: 'app.py',
          start: { line: 10 },
          end: { line: 10 },
          extra: {
            severity: 'ERROR',
            message: 'Detected eval() — code injection',
            metadata: { cwe: ['CWE-95: Eval Injection'] },
          },
        },
        {
          check_id: 'javascript.lang.security.audit.xss',
          path: 'web.js',
          start: { line: 22 },
          end: { line: 24 },
          extra: {
            severity: 'WARNING',
            message: 'Possible XSS',
            metadata: { cwe: 'CWE-79' },
          },
        },
        {
          check_id: 'generic.secrets',
          path: 'config.yaml',
          start: { line: 5 },
          end: { line: 5 },
          extra: { severity: 'INFO', message: 'Found API key' },
        },
      ],
    }),
    stderr: '',
    exitCode: 0,
  };
};

describe('sca/semgrep: parseSemgrepOutput', () => {
  test('parses multiple results with severity mapping', async () => {
    const raw = await okRunner([]).then(r => r.stdout);
    const findings = parseSemgrepOutput(raw);
    expect(findings.length).toBe(3);
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].file).toBe('app.py');
    expect(findings[0].line).toBe(10);
    expect(findings[0].type).toBe('python.lang.security.audit.eval');
    expect(findings[0].source).toBe(SEMGREP_NAME);
    expect(findings[0].cwe).toContain('CWE-95');
    expect(findings[1].severity).toBe('HIGH');
    expect(findings[1].cwe).toBe('CWE-79');
    expect(findings[2].severity).toBe('LOW');
  });
  test('returns [] on empty input', () => {
    expect(parseSemgrepOutput('')).toEqual([]);
    expect(parseSemgrepOutput('   ')).toEqual([]);
  });
  test('returns [] on malformed JSON', () => {
    expect(parseSemgrepOutput('not-json{')).toEqual([]);
  });
  test('returns [] when results missing', () => {
    expect(parseSemgrepOutput(JSON.stringify({}))).toEqual([]);
    expect(parseSemgrepOutput(JSON.stringify({ errors: [] }))).toEqual([]);
  });
  test('skips results without path', () => {
    const raw = JSON.stringify({
      results: [
        { check_id: 'r1', start: { line: 1 }, extra: { severity: 'ERROR' } },
        { check_id: 'r2', path: 'a.js', start: { line: 5 }, extra: { severity: 'WARNING' } },
      ],
    });
    const out = parseSemgrepOutput(raw);
    expect(out.length).toBe(1);
    expect(out[0].file).toBe('a.js');
  });
  test('default line=1 when start missing', () => {
    const raw = JSON.stringify({
      results: [{ check_id: 'r', path: 'a.js', extra: { severity: 'ERROR' } }],
    });
    const out = parseSemgrepOutput(raw);
    expect(out[0].line).toBe(1);
  });
  test('uses check_id as type and message as title/description', () => {
    const raw = JSON.stringify({
      results: [{
        check_id: 'r.id',
        path: 'a.js',
        start: { line: 1 },
        extra: { severity: 'ERROR', message: 'the message' },
      }],
    });
    const out = parseSemgrepOutput(raw);
    expect(out[0].type).toBe('r.id');
    expect(out[0].title).toBe('the message');
    expect(out[0].description).toBe('the message');
  });
  test('falls back to check_id for title/description when message missing', () => {
    const raw = JSON.stringify({
      results: [{ check_id: 'r.id', path: 'a.js', start: { line: 1 }, extra: { severity: 'ERROR' } }],
    });
    const out = parseSemgrepOutput(raw);
    expect(out[0].type).toBe('r.id');
    expect(out[0].title).toBe('r.id');
  });
  test('source can be overridden', () => {
    const raw = JSON.stringify({
      results: [{ check_id: 'r', path: 'a.js', start: { line: 1 }, extra: { severity: 'ERROR' } }],
    });
    const out = parseSemgrepOutput(raw, 'custom-source');
    expect(out[0].source).toBe('custom-source');
  });
  test('confidence defaults to 0.8', () => {
    const raw = JSON.stringify({
      results: [{ check_id: 'r', path: 'a.js', start: { line: 1 }, extra: { severity: 'ERROR' } }],
    });
    const out = parseSemgrepOutput(raw);
    expect(out[0].confidence).toBe(0.8);
  });
});

describe('sca/semgrep: SemgrepAdapter', () => {
  test('exposes name and binary', () => {
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    expect(a.name).toBe('semgrep');
    expect(a.binary).toBe('semgrep');
  });
  test('isAvailable returns true when binaryPath provided', () => {
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    expect(a.isAvailable()).toBe(true);
  });
  test('isAvailable uses Bun.which for default binaryPath', () => {
    const a = new SemgrepAdapter();
    const available = a.isAvailable();
    expect(typeof available).toBe('boolean');
  });
  test('scan invokes runner with semgrep args + path', async () => {
    let captured: string[] | null = null;
    const captureRunner: SpawnRunner = async (cmd) => {
      captured = cmd;
      return { stdout: JSON.stringify({ results: [] }), stderr: '', exitCode: 0 };
    };
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    await a.scan('/tmp/x', { runner: captureRunner });
    expect(captured).not.toBeNull();
    expect(captured![0]).toBe('/usr/bin/semgrep');
    for (const arg of DEFAULT_SEMGREP_ARGS) {
      expect(captured).toContain(arg);
    }
    expect(captured).toContain('/tmp/x');
  });
  test('scan returns findings on exit code 0', async () => {
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    const out = await a.scan('/tmp', { runner: okRunner });
    expect(out.length).toBe(3);
  });
  test('scan returns findings on exit code 1 (findings found)', async () => {
    const exitOne: SpawnRunner = async (cmd) => {
      const r = await okRunner(cmd);
      return { ...r, exitCode: 1 };
    };
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    const out = await a.scan('/tmp', { runner: exitOne });
    expect(out.length).toBe(3);
  });
  test('scan returns [] on non-zero/non-one exit (warning logged)', async () => {
    const exitTwo: SpawnRunner = async () => ({ stdout: '{}', stderr: 'boom', exitCode: 2 });
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    const out = await a.scan('/tmp', { runner: exitTwo });
    expect(out).toEqual([]);
  });
  test('scan returns [] when runner throws (warning logged, non-fatal)', async () => {
    const throwingRunner: SpawnRunner = async () => { throw new Error('ENOENT'); };
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    const out = await a.scan('/tmp', { runner: throwingRunner });
    expect(out).toEqual([]);
  });
  test('scan returns [] on malformed JSON', async () => {
    const badJson: SpawnRunner = async () => ({ stdout: 'definitely not json', stderr: '', exitCode: 0 });
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    const out = await a.scan('/tmp', { runner: badJson });
    expect(out).toEqual([]);
  });
  test('scan passes cwd and timeoutMs to runner', async () => {
    let received: { cwd?: string; timeoutMs?: number } | null = null;
    const captureRunner: SpawnRunner = async (_cmd, opts) => {
      received = opts || null;
      return { stdout: JSON.stringify({ results: [] }), stderr: '', exitCode: 0 };
    };
    const a = new SemgrepAdapter({ binaryPath: '/usr/bin/semgrep' });
    await a.scan('/tmp', { runner: captureRunner, cwd: '/work', timeoutMs: 5000 });
    expect(received).toEqual({ cwd: '/work', timeoutMs: 5000 });
  });
});
