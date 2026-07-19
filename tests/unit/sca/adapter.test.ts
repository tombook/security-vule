import { describe, test, expect } from 'bun:test';
import {
  mapSeverity,
  fingerprintOf,
  dedupFindings,
  isSupportedAdapter,
  SUPPORTED_ADAPTERS,
  type SCAAdapter,
  type SCAFinding,
  type SpawnRunner,
} from '../../../src/sca/adapter.js';

describe('sca/adapter: mapSeverity', () => {
  test('critical → CRITICAL', () => {
    expect(mapSeverity('critical')).toBe('CRITICAL');
  });
  test('high → HIGH', () => {
    expect(mapSeverity('high')).toBe('HIGH');
  });
  test('medium → MEDIUM', () => {
    expect(mapSeverity('medium')).toBe('MEDIUM');
  });
  test('low → LOW', () => {
    expect(mapSeverity('low')).toBe('LOW');
  });
  test('unknown → LOW (fallback)', () => {
    expect(mapSeverity('weird-value')).toBe('LOW');
    expect(mapSeverity('')).toBe('LOW');
  });
  test('moderate (trivy alias) → MEDIUM', () => {
    expect(mapSeverity('moderate')).toBe('MEDIUM');
  });
  test('info → LOW', () => {
    expect(mapSeverity('info')).toBe('LOW');
    expect(mapSeverity('informational')).toBe('LOW');
  });
  test('case-insensitive', () => {
    expect(mapSeverity('HIGH')).toBe('HIGH');
    expect(mapSeverity('Critical')).toBe('CRITICAL');
  });
});

describe('sca/adapter: fingerprintOf', () => {
  test('produces file:line:type', () => {
    expect(fingerprintOf({ file: 'a.js', line: 3, type: 'sql-injection' })).toBe('a.js:3:sql-injection');
  });
  test('deterministic', () => {
    const a = fingerprintOf({ file: 'x.php', line: 1, type: 't' });
    const b = fingerprintOf({ file: 'x.php', line: 1, type: 't' });
    expect(a).toBe(b);
  });
});

describe('sca/adapter: dedupFindings', () => {
  test('keeps primary duplicates only once', () => {
    const f = (file: string, line: number) => ({ file, line, type: 'sql' });
    const out = dedupFindings<SCAFinding>([f('a.js', 1) as any, f('a.js', 1) as any], []);
    expect(out.length).toBe(1);
  });
  test('drops secondary when same fp in primary', () => {
    const f = (file: string, line: number) => ({ file, line, type: 'sql' });
    const primary = [f('a.js', 1) as any];
    const secondary = [f('a.js', 1) as any, f('a.js', 2) as any];
    const out = dedupFindings(primary, secondary);
    expect(out.length).toBe(2);
    expect(out[1].line).toBe(2);
  });
  test('preserves order: primary first, then secondary', () => {
    const f = (file: string, line: number) => ({ file, line, type: 'sql' });
    const out = dedupFindings<SCAFinding>([f('a.js', 1) as any], [f('b.js', 1) as any]);
    expect(out[0].file).toBe('a.js');
    expect(out[1].file).toBe('b.js');
  });
  test('empty inputs', () => {
    expect(dedupFindings([], []).length).toBe(0);
  });
});

describe('sca/adapter: isSupportedAdapter', () => {
  test('semgrep supported', () => {
    expect(isSupportedAdapter('semgrep')).toBe(true);
  });
  test('trivy supported', () => {
    expect(isSupportedAdapter('trivy')).toBe(true);
  });
  test('unknown not supported', () => {
    expect(isSupportedAdapter('snort')).toBe(false);
    expect(isSupportedAdapter('')).toBe(false);
  });
  test('SUPPORTED_ADAPTERS list', () => {
    expect(SUPPORTED_ADAPTERS).toContain('semgrep');
    expect(SUPPORTED_ADAPTERS).toContain('trivy');
  });
});

describe('sca/adapter: SCAAdapter interface contract', () => {
  const fakeRunner: SpawnRunner = async () => ({ stdout: '{}', stderr: '', exitCode: 0 });
  const mk = (name: string, available: boolean): SCAAdapter => ({
    name,
    binary: name,
    isAvailable: () => available,
    scan: async (path, opts) => {
      const runner = opts?.runner || fakeRunner;
      await runner([name, path]);
      return [];
    },
  });
  test('adapter exposes name/binary/isAvailable/scan', () => {
    const a = mk('semgrep', true);
    expect(a.name).toBe('semgrep');
    expect(a.binary).toBe('semgrep');
    expect(a.isAvailable()).toBe(true);
    expect(typeof a.scan).toBe('function');
  });
  test('scan returns array', async () => {
    const a = mk('semgrep', true);
    const out = await a.scan('/tmp', { runner: fakeRunner });
    expect(Array.isArray(out)).toBe(true);
  });
  test('error in runner does not throw — non-fatal by contract', async () => {
    const failingRunner: SpawnRunner = async () => { throw new Error('boom'); };
    const a: SCAAdapter = {
      name: 'semgrep',
      binary: 'semgrep',
      isAvailable: () => true,
      scan: async (path, opts) => {
        const runner = opts?.runner || failingRunner;
        try { await runner([a.binary, path]); return []; }
        catch { return []; }
      },
    };
    const out = await a.scan('/tmp', { runner: failingRunner });
    expect(out).toEqual([]);
  });
});
