/**
 * Tests for VuleDaemon — persistent watcher with socket events.
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { connect } from 'net';
import { VuleDaemon, type DaemonEvent } from '../../../src/daemon/vule-daemon.js';

let tmpDir: string;
let socketPath: string;
let baselinePath: string;
let daemon: VuleDaemon | null = null;
const events: DaemonEvent[] = [];

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), 'vule-daemon-'));
  socketPath = join(tmpDir, 'vule.sock');
  baselinePath = join(tmpDir, 'baseline.json');
  events.length = 0;
});

afterEach(async () => {
  await daemon?.stop();
  daemon = null;
  rmSync(tmpDir, { recursive: true, force: true });
});

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('VuleDaemon — lifecycle', () => {
  test('starts and stops cleanly', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    expect(daemon.state().running).toBe(true);
    await daemon.stop();
    expect(daemon.state().running).toBe(false);
  });

  test('throws on missing watchDir', async () => {
    daemon = new VuleDaemon({ watchDir: '/nonexistent', socketPath });
    await expect(daemon.start()).rejects.toThrow('does not exist');
  });

  test('throws if already running', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await expect(daemon.start()).rejects.toThrow('already running');
    await daemon.stop();
  });

  test('state() reports uptime when running', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await wait(100);
    const s = daemon.state();
    expect(s.uptime).toBeGreaterThan(0);
    expect(s.startedAt).toBeGreaterThan(0);
    await daemon.stop();
  });
});

describe('VuleDaemon — file scanning', () => {
  test('scanNow returns findings for vulnerable file', async () => {
    writeFileSync(
      join(tmpDir, 'test.php'),
      '<?php\n$x = $_GET["id"];\nmysql_query("SELECT * FROM x WHERE id=" . $_GET["id"]);\n'
    );
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    const findings = await daemon.scanNow('test.php');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.type === 'sql-injection')).toBe(true);
    await daemon.stop();
  });

  test('baseline persists across restart', async () => {
    writeFileSync(
      join(tmpDir, 'a.php'),
      '<?php\nmysql_query("SELECT * FROM users WHERE id=" . $_GET["x"]);'
    );
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    await daemon.scanNow('a.php');
    await daemon.stop();

    expect(existsSync(baselinePath)).toBe(true);

    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    const s = daemon.state();
    expect(s.findingsTotal).toBeGreaterThan(0);
    await daemon.stop();
  });

  test('diff: removed file emits finding-removed event', async () => {
    writeFileSync(
      join(tmpDir, 'a.php'),
      '<?php\nmysql_query("SELECT * FROM users WHERE id=" . $_GET["x"]);'
    );
    daemon = new VuleDaemon({
      watchDir: tmpDir,
      socketPath,
      baselinePath,
      onEvent: (e) => events.push(e),
    });
    await daemon.start();
    await daemon.scanNow('a.php');
    rmSync(join(tmpDir, 'a.php'));
    await daemon.scanNow('a.php');
    expect(events.some((e) => e.type === 'finding-removed')).toBe(true);
    await daemon.stop();
  });

  test('diff: new file emits finding-added event', async () => {
    daemon = new VuleDaemon({
      watchDir: tmpDir,
      socketPath,
      baselinePath,
      onEvent: (e) => events.push(e),
    });
    await daemon.start();
    writeFileSync(
      join(tmpDir, 'new.php'),
      '<?php\nmysql_query("SELECT * FROM users WHERE id=" . $_GET["x"]);'
    );
    await daemon.scanNow('new.php');
    expect(events.some((e) => e.type === 'finding-added')).toBe(true);
    await daemon.stop();
  });
});

describe('VuleDaemon — socket commands', () => {
  test('STATE returns JSON state', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();

    const res = await sendCommand(socketPath, 'STATE');
    const state = JSON.parse(res) as { running: boolean };
    expect(state.running).toBe(true);
    await daemon.stop();
  });

  test('SCAN triggers immediate scan', async () => {
    writeFileSync(
      join(tmpDir, 'sqli.php'),
      '<?php\nmysql_query("SELECT * FROM x WHERE id=" . $_GET["id"]);\n'
    );
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    const res = await sendCommand(socketPath, 'SCAN sqli.php');
    const data = JSON.parse(res) as { count: number; findings: Array<{ type: string }> };
    expect(data.count).toBeGreaterThan(0);
    expect(data.findings.some((f) => f.type === 'sql-injection')).toBe(true);
    await daemon.stop();
  });

  test('unknown command returns error JSON', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();
    const res = await sendCommand(socketPath, 'FOO');
    expect(res).toContain('unknown command');
    await daemon.stop();
  });
});

function sendCommand(socketPath: string, command: string): Promise<string> {
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
      resolve(Buffer.concat(chunks).toString());
    });
    client.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
