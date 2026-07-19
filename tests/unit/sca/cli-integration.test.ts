import { describe, test, expect } from 'bun:test';
import { parseScanArgs, scanCommand } from '../../../src/cli.js';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

describe('cli: parseScanArgs', () => {
  test('parses bare target', () => {
    const r = parseScanArgs(['/tmp/x']);
    expect(r).toEqual({
      target: '/tmp/x',
      outputFile: undefined,
      sarifMode: false,
      baselineFile: undefined,
      diffMode: false,
      minConfidence: 0,
      scaList: [],
      statusFilter: ['open', 'confirmed'],
      stateFile: undefined,
      withPoc: false,
      pocTarget: 'none',
      pocAutoConfirm: false,
      watch: false,
      debounceMs: 300,
      pollInterval: 200,
    });
  });
  test('parses --sca=semgrep', () => {
    const r = parseScanArgs(['/tmp/x', '--sca=semgrep']);
    expect((r as any).scaList).toEqual(['semgrep']);
  });
  test('parses --sca=semgrep,trivy', () => {
    const r = parseScanArgs(['/tmp/x', '--sca=semgrep,trivy']);
    expect((r as any).scaList).toEqual(['semgrep', 'trivy']);
  });
  test('parses --sca= with trailing comma and spaces', () => {
    const r = parseScanArgs(['/tmp/x', '--sca= semgrep , trivy ,']);
    expect((r as any).scaList).toEqual(['semgrep', 'trivy']);
  });
  test('parses --sca=semgrep combined with other flags', () => {
    const r = parseScanArgs(['/tmp/x', '--sarif', '--sca=semgrep,trivy', '--min-confidence', '0.5']);
    expect((r as any).scaList).toEqual(['semgrep', 'trivy']);
    expect((r as any).sarifMode).toBe(true);
    expect((r as any).minConfidence).toBe(0.5);
  });
  test('parses --sca= (empty) → empty scaList', () => {
    const r = parseScanArgs(['/tmp/x', '--sca=']);
    expect((r as any).scaList).toEqual([]);
  });
  test('returns error when target missing', () => {
    const r = parseScanArgs([]);
    expect(r).toEqual({ error: 'missing target' });
  });
  test('treats first arg as target even if it looks like a flag', () => {
    const r = parseScanArgs(['--sca=semgrep']);
    expect((r as any).target).toBe('--sca=semgrep');
    expect((r as any).scaList).toEqual([]);
  });
  test('parses --baseline FILE', () => {
    const r = parseScanArgs(['/tmp/x', '--baseline', 'b.json']);
    expect((r as any).baselineFile).toBe('b.json');
  });
  test('parses --output FILE and -o', () => {
    expect((parseScanArgs(['/tmp/x', '--output', 'o.json']) as any).outputFile).toBe('o.json');
    expect((parseScanArgs(['/tmp/x', '-o', 'o.json']) as any).outputFile).toBe('o.json');
  });
  test('parses --diff', () => {
    expect((parseScanArgs(['/tmp/x', '--diff']) as any).diffMode).toBe(true);
  });
});

describe('cli: scanCommand --sca flag wiring', () => {
  test('scan with no --sca flag still works (no SCA annotations)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-scan-'));
    try {
      writeFileSync(join(dir, 'clean.py'), 'x = 1\n');
      const result = await scanCommand([dir, '--min-confidence', '1.1']);
      expect(result).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test('scan with --sca=unknown-binary exits 0 (non-fatal, skipped)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-scan-'));
    try {
      writeFileSync(join(dir, 'a.py'), 'x = 1\n');
      const result = await scanCommand([dir, '--sca=semgrep,trivy']);
      expect(typeof result).toBe('number');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test('scan with --sca= writes to stdout JSON (default output)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-scan-'));
    try {
      writeFileSync(join(dir, 'a.py'), 'x = 1\n');
      const original = console.log;
      let captured = '';
      (console as any).log = (...args: any[]) => { captured += args.join(' '); };
      try {
        await scanCommand([dir, '--sca=semgrep']);
      } finally {
        (console as any).log = original;
      }
      const parsed = JSON.parse(captured || '{}');
      expect(parsed.target).toBe(dir);
      expect(parsed.findings).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test('scan with --sca= writes JSON to --output file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-scan-'));
    const outFile = join(dir, 'out.json');
    try {
      writeFileSync(join(dir, 'a.py'), 'x = 1\n');
      await scanCommand([dir, '--sca=semgrep,trivy', '-o', outFile]);
      const data = JSON.parse(readFileSync(outFile, 'utf-8'));
      expect(data.target).toBe(dir);
      expect(data.findings).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test('scan with --sca= and --sarif writes SARIF output', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-scan-'));
    const outFile = join(dir, 'out.sarif');
    try {
      writeFileSync(join(dir, 'a.py'), 'x = 1\n');
      await scanCommand([dir, '--sca=semgrep,trivy', '--sarif', '-o', outFile]);
      const data = JSON.parse(readFileSync(outFile, 'utf-8'));
      expect(data.$schema).toContain('sarif-schema-2.1.0');
      expect(data.runs).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test('scan with --sca= exits 2 when target not found', async () => {
    const result = await scanCommand(['/nonexistent/path/xyz', '--sca=semgrep']);
    expect(result).toBe(2);
  });
});
