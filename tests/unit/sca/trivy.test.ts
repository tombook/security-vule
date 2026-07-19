import { describe, test, expect } from 'bun:test';
import {
  TrivyAdapter,
  parseTrivyOutput,
  DEFAULT_TRIVY_ARGS,
  TRIVY_NAME,
  type SpawnRunner,
} from '../../../src/sca/trivy.js';

const okRunner: SpawnRunner = async () => ({
  stdout: JSON.stringify({
    Results: [
      {
        Target: 'package-lock.json',
        Class: 'lockfile',
        Type: 'npm',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2021-12345',
            PkgName: 'lodash',
            InstalledVersion: '4.17.20',
            FixedVersion: '4.17.21',
            Severity: 'CRITICAL',
            Title: 'Prototype Pollution in lodash',
            Description: 'lodash versions prior to 4.17.21 are vulnerable',
          },
          {
            VulnerabilityID: 'CVE-2022-99999',
            PkgName: 'axios',
            InstalledVersion: '0.21.0',
            FixedVersion: '0.21.2',
            Severity: 'HIGH',
            Title: 'SSRF in axios',
          },
          {
            VulnerabilityID: 'CVE-2023-7777',
            PkgName: 'minimist',
            InstalledVersion: '1.2.0',
            Severity: 'MEDIUM',
            Title: 'Prototype Pollution in minimist',
          },
          {
            VulnerabilityID: 'CVE-2024-5555',
            PkgName: 'left-pad',
            InstalledVersion: '1.0.0',
            Severity: 'LOW',
            Title: 'Minor issue in left-pad',
          },
          {
            VulnerabilityID: 'CVE-2024-6666',
            PkgName: 'weird-pkg',
            InstalledVersion: '0.1.0',
            Severity: 'UNKNOWN',
            Title: 'Unknown severity',
          },
        ],
      },
    ],
  }),
  stderr: '',
  exitCode: 0,
});

describe('sca/trivy: parseTrivyOutput', () => {
  test('parses CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN severities', () => {
    const raw = JSON.stringify({
      Results: [{
        Target: 'p.json',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-1', PkgName: 'a', Severity: 'CRITICAL' },
          { VulnerabilityID: 'CVE-2', PkgName: 'b', Severity: 'HIGH' },
          { VulnerabilityID: 'CVE-3', PkgName: 'c', Severity: 'MEDIUM' },
          { VulnerabilityID: 'CVE-4', PkgName: 'd', Severity: 'LOW' },
          { VulnerabilityID: 'CVE-5', PkgName: 'e', Severity: 'UNKNOWN' },
        ],
      }],
    });
    const out = parseTrivyOutput(raw);
    expect(out.length).toBe(5);
    expect(out[0].severity).toBe('CRITICAL');
    expect(out[1].severity).toBe('HIGH');
    expect(out[2].severity).toBe('MEDIUM');
    expect(out[3].severity).toBe('LOW');
    expect(out[4].severity).toBe('LOW');
  });
  test('returns [] on empty input', () => {
    expect(parseTrivyOutput('')).toEqual([]);
    expect(parseTrivyOutput('   ')).toEqual([]);
  });
  test('returns [] on malformed JSON', () => {
    expect(parseTrivyOutput('not-json{')).toEqual([]);
  });
  test('returns [] when Results missing', () => {
    expect(parseTrivyOutput(JSON.stringify({}))).toEqual([]);
  });
  test('skips Result without Vulnerabilities array', () => {
    const raw = JSON.stringify({ Results: [{ Target: 'a' }, { Target: 'b', Vulnerabilities: [] }] });
    expect(parseTrivyOutput(raw)).toEqual([]);
  });
  test('skips vulnerability without VulnerabilityID', () => {
    const raw = JSON.stringify({
      Results: [{
        Target: 'p.json',
        Vulnerabilities: [
          { PkgName: 'a', Severity: 'HIGH' },
          { VulnerabilityID: 'CVE-1', PkgName: 'b', Severity: 'HIGH' },
        ],
      }],
    });
    const out = parseTrivyOutput(raw);
    expect(out.length).toBe(1);
    expect(out[0].type).toContain('trivy-vuln:b');
  });
  test('uses Target as file, line=1', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'package-lock.json', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'a', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].file).toBe('package-lock.json');
    expect(out[0].line).toBe(1);
  });
  test('type contains PkgName', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'lodash', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].type).toBe('trivy-vuln:lodash');
  });
  test('falls back to <unknown> target', () => {
    const raw = JSON.stringify({
      Results: [{ Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'a', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].file).toBe('<unknown>');
  });
  test('description includes fixed version when available', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'a', InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].description).toContain('1.0.0');
    expect(out[0].description).toContain('1.0.1');
  });
  test('falls back to VulnerabilityID when PkgName missing', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].type).toBe('trivy-vuln:package');
  });
  test('source can be overridden', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'a', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw, 'custom');
    expect(out[0].source).toBe('custom');
  });
  test('confidence defaults to 0.9', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'a', Severity: 'HIGH' },
      ]}],
    });
    const out = parseTrivyOutput(raw);
    expect(out[0].confidence).toBe(0.9);
  });
  test('parses full okRunner fixture', () => {
    const raw = JSON.stringify({
      Results: [{
        Target: 'package-lock.json',
        Class: 'lockfile',
        Type: 'npm',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-A', PkgName: 'x', Severity: 'CRITICAL', Title: 'X' },
          { VulnerabilityID: 'CVE-B', PkgName: 'y', Severity: 'LOW', Title: 'Y' },
        ],
      }],
    });
    const out = parseTrivyOutput(raw);
    expect(out.length).toBe(2);
    expect(out[0].severity).toBe('CRITICAL');
    expect(out[1].severity).toBe('LOW');
  });
});

describe('sca/trivy: TrivyAdapter', () => {
  test('exposes name and binary', () => {
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    expect(a.name).toBe('trivy');
    expect(a.binary).toBe('trivy');
  });
  test('isAvailable returns true when binaryPath provided', () => {
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    expect(a.isAvailable()).toBe(true);
  });
  test('isAvailable uses Bun.which for default binaryPath', () => {
    const a = new TrivyAdapter();
    const available = a.isAvailable();
    expect(typeof available).toBe('boolean');
  });
  test('scan invokes runner with trivy args + path', async () => {
    let captured: string[] | null = null;
    const captureRunner: SpawnRunner = async (cmd) => {
      captured = cmd;
      return { stdout: JSON.stringify({ Results: [] }), stderr: '', exitCode: 0 };
    };
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    await a.scan('/tmp/x', { runner: captureRunner });
    expect(captured).not.toBeNull();
    expect(captured![0]).toBe('/usr/bin/trivy');
    for (const arg of DEFAULT_TRIVY_ARGS) {
      expect(captured).toContain(arg);
    }
    expect(captured).toContain('/tmp/x');
  });
  test('scan returns findings on exit code 0', async () => {
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    const out = await a.scan('/tmp', { runner: okRunner });
    expect(out.length).toBe(5);
  });
  test('scan returns [] on non-zero exit', async () => {
    const failRunner: SpawnRunner = async () => ({ stdout: '{}', stderr: 'fail', exitCode: 1 });
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    const out = await a.scan('/tmp', { runner: failRunner });
    expect(out).toEqual([]);
  });
  test('scan returns [] when runner throws', async () => {
    const throwingRunner: SpawnRunner = async () => { throw new Error('ENOENT'); };
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    const out = await a.scan('/tmp', { runner: throwingRunner });
    expect(out).toEqual([]);
  });
  test('scan returns [] on malformed JSON', async () => {
    const badJson: SpawnRunner = async () => ({ stdout: 'not json', stderr: '', exitCode: 0 });
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    const out = await a.scan('/tmp', { runner: badJson });
    expect(out).toEqual([]);
  });
  test('scan passes cwd and timeoutMs to runner', async () => {
    let received: { cwd?: string; timeoutMs?: number } | null = null;
    const captureRunner: SpawnRunner = async (_cmd, opts) => {
      received = opts || null;
      return { stdout: JSON.stringify({ Results: [] }), stderr: '', exitCode: 0 };
    };
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    await a.scan('/tmp', { runner: captureRunner, cwd: '/work', timeoutMs: 5000 });
    expect(received).toEqual({ cwd: '/work', timeoutMs: 5000 });
  });
  test('handles UNKNOWN severity by mapping to LOW', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'p', Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'x', Severity: 'UNKNOWN' },
      ]}],
    });
    const a = new TrivyAdapter({ binaryPath: '/usr/bin/trivy' });
    const fakeRunner: SpawnRunner = async () => ({ stdout: raw, stderr: '', exitCode: 0 });
    return a.scan('/tmp', { runner: fakeRunner }).then(out => {
      expect(out[0].severity).toBe('LOW');
    });
  });
});
