/**
 * Tests for IncrementalScanner — CodeQL-style delta analysis.
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { IncrementalScanner } from '../../../src/scanner/incremental.js';

let tmpDir: string;
let cachePath: string;

const mockScan = async (path: string, content: string): Promise<string[]> => {
  const findings: string[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/eval\s*\(/i.test(lines[i] ?? '')) {
      findings.push(`${path}:${i + 1}:eval`);
    }
  }
  return findings;
};

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'incr-'));
  cachePath = join(tmpDir, 'cache.json');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('IncrementalScanner — first scan', () => {
  test('all files treated as added', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');
    writeFileSync(join(tmpDir, 'b.php'), '<?php $x =1;');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    const r = await scanner.scan();

    expect(r.added).toHaveLength(2);
    expect(r.modified).toHaveLength(0);
    expect(r.unchanged).toHaveLength(0);
    expect(r.toScan).toHaveLength(2);
    expect(r.cacheHitRate).toBe(0);
    expect(r.newFindings.length).toBeGreaterThanOrEqual(1);
  });

  test('cache file is created after scan', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php $x =1;');
    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();
    expect(existsSync(cachePath)).toBe(true);
  });
});

describe('IncrementalScanner — second scan (cache hit)', () => {
  test('unchanged files return cache hit', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();
    const r = await scanner.scan();

    expect(r.added).toHaveLength(0);
    expect(r.modified).toHaveLength(0);
    expect(r.unchanged).toHaveLength(1);
    expect(r.toScan).toHaveLength(0);
    expect(r.cacheHitRate).toBeGreaterThan(0.9);
  });

  test('cache survives scanner restart', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');

    let scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();

    scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    const r = await scanner.scan();
    expect(r.unchanged).toHaveLength(1);
    expect(r.cacheHitRate).toBeGreaterThan(0.9);
  });
});

describe('IncrementalScanner — modified files', () => {
  test('detects modifications via hash', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php $x =1;');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();

    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["y"]);');
    const r = await scanner.scan();

    expect(r.modified).toHaveLength(1);
    expect(r.added).toHaveLength(0);
    expect(r.toScan).toHaveLength(1);
  });

  test('only modified file is re-scanned', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php $x =1;');
    writeFileSync(join(tmpDir, 'b.php'), '<?php $y =2;');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();

    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');
    const r = await scanner.scan();

    expect(r.toScan).toHaveLength(1);
    expect(r.toScan[0]).toContain('a.php');
  });
});

describe('IncrementalScanner — deleted files', () => {
  test('deleted file reported as removed', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();
    rmSync(join(tmpDir, 'a.php'));

    const r = await scanner.scan();
    expect(r.deleted).toHaveLength(1);
    expect(r.removedFindings.length).toBeGreaterThan(0);
  });
});

describe('IncrementalScanner — performance', () => {
  test('cacheHitRate=1.0 when nothing changed', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php $x =1;');
    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    await scanner.scan();
    const r = await scanner.scan();
    expect(r.cacheHitRate).toBe(1);
  });

  test('5-10x speedup: cache scan < full scan', async () => {
    for (let i = 0; i < 20; i++) {
      writeFileSync(join(tmpDir, `f${i}.php`), '<?php $x =1;');
    }
    const slowScan = async () => {
      await new Promise((r) => setTimeout(r, 30));
      return [`finding-${Date.now()}`];
    };

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: slowScan });
    await scanner.scan();

    const t0 = Date.now();
    const r = await scanner.scan();
    const cacheTime = Date.now() - t0;

    expect(cacheTime).toBeLessThan(50);
    expect(r.cacheHitRate).toBe(1);
  });
});

describe('IncrementalScanner — options', () => {
  test('filters by fileExtensionFilter', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');
    writeFileSync(join(tmpDir, 'b.txt'), 'eval($_GET["x"]);');

    const scanner = new IncrementalScanner({
      sourceDir: tmpDir,
      cachePath,
      scanFile: mockScan,
      fileExtensionFilter: /\.php$/i,
    });
    const r = await scanner.scan();
    expect(r.added).toHaveLength(1);
    expect(r.added[0]).toContain('a.php');
  });

  test('respects maxChangedFiles cap', async () => {
    for (let i = 0; i < 20; i++) {
      writeFileSync(join(tmpDir, `f${i}.php`), '<?php eval($_GET["x"]);');
    }

    const scanner = new IncrementalScanner({
      sourceDir: tmpDir,
      cachePath,
      scanFile: mockScan,
      maxChangedFiles: 5,
    });
    const r = await scanner.scan();
    expect(r.toScan).toHaveLength(5);
    expect(r.added.length).toBe(20);
  });

  test('skips node_modules + .git directories', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');
    const fs = require('fs');
    fs.mkdirSync(join(tmpDir, 'node_modules'), { recursive: true });
    writeFileSync(join(tmpDir, 'node_modules', 'evil.php'), '<?php eval($_GET["x"]);');

    const scanner = new IncrementalScanner({ sourceDir: tmpDir, cachePath, scanFile: mockScan });
    const r = await scanner.scan();
    expect(r.added).toHaveLength(1);
    expect(r.added[0]).toContain('a.php');
  });
});
