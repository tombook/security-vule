/**
 * Tests for incremental scan CLI option.
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { analyzeCommand } from '../../../src/integration/commands/analyze.js';

let tmpDir: string;
let cachePath: string;
let exportPath: string;
const logs: string[] = [];
const origLog = console.log;
const origErr = console.error;

const captureOutput = (fn: () => Promise<void>): Promise<void> => {
  logs.length = 0;
  console.log = (msg: string) => logs.push(msg);
  console.error = (msg: string) => logs.push(msg);
  return fn().finally(() => {
    console.log = origLog;
    console.error = origErr;
  });
};

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'inc-cli-'));
  cachePath = join(tmpDir, 'cache.json');
  exportPath = join(tmpDir, 'report.json');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('analyzeCommand --incremental', () => {
  test('errors if target is a file (must be directory)', async () => {
    const filePath = join(tmpDir, 'a.php');
    writeFileSync(filePath, '<?php $x =1;');

    const exitCode = await captureOutput(async () => {
      const origExit = process.exit;
      process.exit = (() => {
        throw new Error('EXIT');
      }) as never;
      try {
        await analyzeCommand(filePath, { incremental: true });
      } catch (e) {
        process.exit = origExit;
      }
    }).catch(() => {});
  });

  test('first run: all files treated as added', async () => {
    writeFileSync(
      join(tmpDir, 'sqli.php'),
      '<?php\nmysql_query("SELECT * FROM x WHERE id=" . $_GET["x"]);\n'
    );

    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    expect(logs.some((l) => /added:\s*1\b/.test(l))).toBe(true);
    expect(logs.some((l) => /cache hit rate:\s*0\.0%/.test(l))).toBe(true);
    expect(logs.some((l) => /new findings:\s*1\b/.test(l))).toBe(true);
    expect(existsSync(cachePath)).toBe(true);
  });

  test('second run: cache hit rate=100%', async () => {
    writeFileSync(
      join(tmpDir, 'sqli.php'),
      '<?php\nmysql_query("SELECT * FROM x WHERE id=" . $_GET["x"]);\n'
    );
    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    expect(logs.some((l) => /added:\s*0\b/.test(l))).toBe(true);
    expect(logs.some((l) => /unchanged:\s*1\b/.test(l))).toBe(true);
    expect(logs.some((l) => /cache hit rate:\s*100\.0%/.test(l))).toBe(true);
  });

  test('modified file triggers re-scan', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php $x =1;');
    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    writeFileSync(join(tmpDir, 'a.php'), '<?php\neval($_GET["y"]);\n');
    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    expect(logs.some((l) => /modified:\s*1\b/.test(l))).toBe(true);
  });

  test('deleted file reported as removed', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php eval($_GET["x"]);');
    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    rmSync(join(tmpDir, 'a.php'));
    await captureOutput(() => analyzeCommand(tmpDir, { incremental: true, cachePath }));

    expect(logs.some((l) => /deleted:\s*1\b/.test(l))).toBe(true);
  });

  test('JSON export writes report', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php\neval($_GET["x"]);\n');

    await captureOutput(() =>
      analyzeCommand(tmpDir, { incremental: true, cachePath, export: exportPath })
    );

    expect(existsSync(exportPath)).toBe(true);
    const report = JSON.parse(require('fs').readFileSync(exportPath, 'utf8')) as {
      mode: string;
      findings: unknown[];
    };
    expect(report.mode).toBe('incremental');
    expect(report.findings.length).toBeGreaterThan(0);
  });
});
