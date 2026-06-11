/**
 * Tests for VuleDaemon QUERY socket command (SOP v1.0 iteration).
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { connect } from 'net';
import { VuleDaemon } from '../../../src/daemon/vule-daemon.js';

let tmpDir: string;
let socketPath: string;
let baselinePath: string;
let daemon: VuleDaemon | null = null;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'vule-d-q-'));
  socketPath = join(tmpDir, 'vule.sock');
  baselinePath = join(tmpDir, 'baseline.json');
});

afterEach(async () => {
  await daemon?.stop();
  daemon = null;
  if (existsSync(socketPath)) {
    try {
      require('fs').unlinkSync(socketPath);
    } catch {}
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

const sendCommand = (socketPath: string, command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('socket timeout')), 3000);
    const client = connect(socketPath, () => {
      client.write(command + '\n');
    });
    const chunks: Buffer[] = [];
    client.on('data', (c: Buffer) => {
      chunks.push(c);
      clearTimeout(timer);
      client.end();
      resolve(Buffer.concat(chunks).toString().trim());
    });
    client.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
};

describe('VuleDaemon — QUERY socket command', () => {
  test('filters by severity', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php\nsystem($_GET["c"]);\n');
    writeFileSync(join(tmpDir, 'b.php'), '<?php\n$x = $_GET["x"];\n');
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await daemon.scanNow('a.php');
    await daemon.scanNow('b.php');
    await new Promise((r) => setTimeout(r, 200));

    const result = JSON.parse(await sendCommand(socketPath, 'QUERY severity=critical')) as {
      matches: number;
      findings: Array<{ severity: string }>;
    };
    expect(result.matches).toBeGreaterThan(0);
    expect(result.findings.every((f) => f.severity.toUpperCase() === 'CRITICAL')).toBe(true);
  });

  test('filters by type', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php\nsystem($_GET["c"]);\n');
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await daemon.scanNow('a.php');
    await new Promise((r) => setTimeout(r, 200));

    const result = JSON.parse(await sendCommand(socketPath, 'QUERY type=command')) as {
      matches: number;
      findings: Array<{ type: string }>;
    };
    expect(result.matches).toBeGreaterThan(0);
    expect(result.findings.every((f) => f.type.toLowerCase().includes('command'))).toBe(true);
  });

  test('returns empty when no matches', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php\n$x = $_GET["x"];\n');
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await daemon.scanNow('a.php');
    await new Promise((r) => setTimeout(r, 200));

    const result = JSON.parse(await sendCommand(socketPath, 'QUERY severity=nonexistent')) as {
      matches: number;
      findings: unknown[];
    };
    expect(result.matches).toBe(0);
    expect(result.findings).toEqual([]);
  });

  test('returns all findings without filters', async () => {
    writeFileSync(join(tmpDir, 'a.php'), '<?php\nsystem($_GET["c"]);\neval($_GET["e"]);\n');
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await daemon.scanNow('a.php');
    await new Promise((r) => setTimeout(r, 200));

    const result = JSON.parse(await sendCommand(socketPath, 'QUERY all')) as {
      matches: number;
    };
    expect(result.matches).toBeGreaterThan(0);
  });
});
