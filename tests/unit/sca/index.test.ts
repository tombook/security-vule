import { describe, test, expect } from 'bun:test';
import {
  runSCA,
  combineFindings,
  SUPPORTED_ADAPTERS,
  type SCAAdapter,
  type SCAFinding,
  type SpawnRunner,
} from '../../../src/sca/index.js';
import type { VulnerabilityFinding } from '../../../src/engine/analyzer.js';

function mkSCA(name: string, findings: SCAFinding[] = [], available = true): SCAAdapter {
  return {
    name,
    binary: name,
    isAvailable: () => available,
    scan: async () => findings,
  };
}

function mkFinding(file: string, line: number, type: string, source: string = 'test'): SCAFinding {
  return {
    id: `${source}-${file}-${line}-${type}`,
    type,
    severity: 'MEDIUM',
    title: 't',
    description: 'd',
    file,
    line,
    confidence: 0.5,
    source,
  };
}

describe('sca/index: SUPPORTED_ADAPTERS', () => {
  test('contains semgrep and trivy', () => {
    expect(SUPPORTED_ADAPTERS).toContain('semgrep');
    expect(SUPPORTED_ADAPTERS).toContain('trivy');
  });
});

describe('sca/index: runSCA', () => {
  test('returns empty result when enabledList is empty', async () => {
    const r = await runSCA('/tmp', [], { adapters: {} });
    expect(r.findings).toEqual([]);
    expect(r.skipped).toEqual([]);
  });
  test('returns empty result when enabledList is undefined', async () => {
    const r = await runSCA('/tmp');
    expect(r.findings).toEqual([]);
  });
  test('runs semgrep and trivy concurrently (Promise.all path)', async () => {
    const events: Array<{ name: string; t: number; kind: 'start' | 'end' }> = [];
    const t0 = Date.now();
    const record = (name: string, kind: 'start' | 'end') => events.push({ name, t: Date.now() - t0, kind });
    const slowScan = (name: string, delayMs: number, finding: SCAFinding): SCAAdapter => ({
      name,
      binary: name,
      isAvailable: () => true,
      scan: async () => {
        record(name, 'start');
        await new Promise(r => setTimeout(r, delayMs));
        record(name, 'end');
        return [finding];
      },
    });
    const fSemi = mkFinding('a.js', 1, 'sql', 'semgrep');
    const fTrivy = mkFinding('p.json', 1, 'rce', 'trivy');
    const r = await runSCA('/tmp', ['semgrep', 'trivy'], {
      adapters: { semgrep: slowScan('semgrep', 80, fSemi), trivy: slowScan('trivy', 80, fTrivy) },
    });
    expect(r.findings.length).toBe(2);
    expect(events.length).toBe(4);
    const semiStart = events.find(e => e.name === 'semgrep' && e.kind === 'start')!.t;
    const trivyEnd = events.find(e => e.name === 'trivy' && e.kind === 'end')!.t;
    const semiEnd = events.find(e => e.name === 'semgrep' && e.kind === 'end')!.t;
    expect(semiStart).toBeLessThan(semiEnd);
    expect(trivyEnd - semiStart).toBeLessThan(semiEnd - semiStart + 60);
  });
  test('total wall time is closer to max-delay than sum-of-delays (parallel)', async () => {
    const DELAY = 60;
    const make = (name: string, finding: SCAFinding): SCAAdapter => ({
      name,
      binary: name,
      isAvailable: () => true,
      scan: async () => {
        await new Promise(r => setTimeout(r, DELAY));
        return [finding];
      },
    });
    const fSemi = mkFinding('a.js', 1, 'sql', 'semgrep');
    const fTrivy = mkFinding('p.json', 1, 'rce', 'trivy');
    const t0 = Date.now();
    await runSCA('/tmp', ['semgrep', 'trivy'], {
      adapters: { semgrep: make('semgrep', fSemi), trivy: make('trivy', fTrivy) },
    });
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeLessThan(2 * DELAY - 5);
  });
  test('skips unknown adapter names', async () => {
    const r = await runSCA('/tmp', ['bogus'], { adapters: {} });
    expect(r.findings).toEqual([]);
    expect(r.skipped).toEqual([{ name: 'bogus', reason: 'unsupported-adapter' }]);
  });
  test('skips adapter when binary not available', async () => {
    const r = await runSCA('/tmp', ['semgrep'], {
      adapters: { semgrep: mkSCA('semgrep', [], false) },
    });
    expect(r.findings).toEqual([]);
    expect(r.skipped).toEqual([{ name: 'semgrep', reason: 'binary-not-found' }]);
  });
  test('runs semgrep when enabled and available', async () => {
    const f = mkFinding('a.js', 1, 'sql-injection', 'semgrep');
    const r = await runSCA('/tmp', ['semgrep'], {
      adapters: { semgrep: mkSCA('semgrep', [f], true) },
    });
    expect(r.findings.length).toBe(1);
    expect(r.findings[0]).toBe(f);
  });
  test('runs trivy when enabled and available', async () => {
    const f = mkFinding('package.json', 1, 'trivy-vuln:lodash', 'trivy');
    const r = await runSCA('/tmp', ['trivy'], {
      adapters: { trivy: mkSCA('trivy', [f], true) },
    });
    expect(r.findings.length).toBe(1);
    expect(r.findings[0]).toBe(f);
  });
  test('runs both adapters in parallel-style sequence', async () => {
    const fSemi = mkFinding('a.js', 1, 'sql-injection', 'semgrep');
    const fTrivy = mkFinding('p.json', 1, 'trivy-vuln:x', 'trivy');
    const r = await runSCA('/tmp', ['semgrep', 'trivy'], {
      adapters: {
        semgrep: mkSCA('semgrep', [fSemi], true),
        trivy: mkSCA('trivy', [fTrivy], true),
      },
    });
    expect(r.findings.length).toBe(2);
    expect(r.findings).toContain(fSemi);
    expect(r.findings).toContain(fTrivy);
  });
  test('skips adapter when scan throws (non-fatal)', async () => {
    const failing: SCAAdapter = {
      name: 'semgrep',
      binary: 'semgrep',
      isAvailable: () => true,
      scan: async () => { throw new Error('boom'); },
    };
    const r = await runSCA('/tmp', ['semgrep'], { adapters: { semgrep: failing } });
    expect(r.findings).toEqual([]);
    expect(r.skipped).toEqual([{ name: 'semgrep', reason: 'scan-error' }]);
  });
  test('passes path to adapter.scan', async () => {
    let receivedPath: string | null = null;
    const capturing: SCAAdapter = {
      name: 'semgrep',
      binary: 'semgrep',
      isAvailable: () => true,
      scan: async (p) => { receivedPath = p; return []; },
    };
    await runSCA('/some/path', ['semgrep'], { adapters: { semgrep: capturing } });
    expect(receivedPath).toBe('/some/path');
  });
  test('passes cwd and timeoutMs to adapter.scan', async () => {
    let received: { cwd?: string; timeoutMs?: number } | null = null;
    const capturing: SCAAdapter = {
      name: 'semgrep',
      binary: 'semgrep',
      isAvailable: () => true,
      scan: async (_p, opts) => { received = { cwd: opts?.cwd, timeoutMs: opts?.timeoutMs }; return []; },
    };
    await runSCA('/tmp', ['semgrep'], {
      adapters: { semgrep: capturing },
      cwd: '/work',
      timeoutMs: 9999,
    });
    expect(received).toEqual({ cwd: '/work', timeoutMs: 9999 });
  });
  test('unknown + known both work; unknown goes to skipped', async () => {
    const f = mkFinding('a.js', 1, 'sql-injection', 'semgrep');
    const r = await runSCA('/tmp', ['bogus', 'semgrep'], {
      adapters: { semgrep: mkSCA('semgrep', [f], true) },
    });
    expect(r.findings).toEqual([f]);
    expect(r.skipped).toEqual([{ name: 'bogus', reason: 'unsupported-adapter' }]);
  });
  test('does not dedup within a single adapter (caller responsibility)', async () => {
    const f1 = mkFinding('a.js', 1, 'sql', 'semgrep');
    const f2 = mkFinding('a.js', 1, 'sql', 'semgrep');
    const r = await runSCA('/tmp', ['semgrep'], {
      adapters: { semgrep: mkSCA('semgrep', [f1, f2], true) },
    });
    expect(r.findings.length).toBe(2);
  });
});

describe('sca/index: combineFindings', () => {
  test('merges DFG + SCA, dedup by file:line:type', () => {
    const dfg: VulnerabilityFinding[] = [
      { id: 'd1', type: 'sql', severity: 'HIGH', title: 't', description: 'd', file: 'a.js', line: 1, confidence: 0.9 },
      { id: 'd2', type: 'xss', severity: 'MEDIUM', title: 't', description: 'd', file: 'b.js', line: 5, confidence: 0.7 },
    ];
    const sca: SCAFinding[] = [
      { ...mkFinding('a.js', 1, 'sql', 'semgrep'), id: 's1', severity: 'HIGH' },
      { ...mkFinding('c.js', 9, 'rce', 'semgrep'), id: 's2', severity: 'CRITICAL' },
    ];
    const out = combineFindings(dfg, sca);
    expect(out.length).toBe(3);
    expect(out[0].id).toBe('d1');
    expect(out[1].id).toBe('d2');
    expect(out[2].id).toBe('s2');
  });
  test('DFG findings win (kept first) on collision', () => {
    const dfg: VulnerabilityFinding[] = [
      { id: 'd1', type: 'sql', severity: 'HIGH', title: 'dfg', description: 'd', file: 'a.js', line: 1, confidence: 0.9 },
    ];
    const sca: SCAFinding[] = [
      { id: 's1', type: 'sql', severity: 'CRITICAL', title: 'sca', description: 'd', file: 'a.js', line: 1, confidence: 0.5, source: 'semgrep' },
    ];
    const out = combineFindings(dfg, sca);
    expect(out.length).toBe(1);
    expect(out[0].id).toBe('d1');
    expect(out[0].title).toBe('dfg');
  });
  test('empty inputs', () => {
    expect(combineFindings([], []).length).toBe(0);
  });
  test('SCA-only result preserves source field', () => {
    const sca: SCAFinding[] = [
      { ...mkFinding('a.js', 1, 'rce', 'trivy'), id: 's1', severity: 'CRITICAL' },
    ];
    const out = combineFindings([], sca);
    expect(out.length).toBe(1);
    expect(out[0].source).toBe('trivy');
  });
});
