/**
 * Tests for vule daemon CLI command (handler-level).
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { daemonCommand } from '../../../src/integration/commands/daemon.js';
import { VuleDaemon } from '../../../src/daemon/vule-daemon.js';

let tmpDir: string;
let socketPath: string;
let baselinePath: string;
let daemon: VuleDaemon | null = null;
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
  tmpDir = mkdtempSync(join(tmpdir(), 'vule-cli-'));
  socketPath = join(tmpDir, 'vule.sock');
  baselinePath = join(tmpDir, 'baseline.json');
});

afterEach(async () => {
  await daemon?.stop();
  daemon = null;
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('daemon command — status (no daemon running)', () => {
  test('reports not running when socket missing', async () => {
    await captureOutput(() =>
      daemonCommand({ action: 'status', watchDir: tmpDir, socketPath: join(tmpDir, 'no.sock') })
    );
    expect(logs.some((l) => l.includes('not running'))).toBe(true);
  });

  test('reports not running with JSON output', async () => {
    await captureOutput(() =>
      daemonCommand({
        action: 'status',
        watchDir: tmpDir,
        socketPath: join(tmpDir, 'no.sock'),
        json: true,
      })
    );
    expect(logs.some((l) => l.includes('error'))).toBe(true);
  });
});

describe('daemon command — status (daemon running)', () => {
  test('reports running when daemon is alive', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();

    await captureOutput(() => daemonCommand({ action: 'status', watchDir: tmpDir, socketPath }));
    expect(logs.some((l) => l.includes('running'))).toBe(true);
  });

  test('JSON status returns parseable object', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();

    await captureOutput(() =>
      daemonCommand({ action: 'status', watchDir: tmpDir, socketPath, json: true })
    );
    const jsonLine = logs.find((l) => l.trim().startsWith('{'));
    expect(jsonLine).toBeDefined();
    const parsed = JSON.parse(jsonLine ?? '{}') as { running: boolean };
    expect(typeof parsed.running).toBe('boolean');
    expect(parsed.running).toBe(true);
  });
});

describe('daemon command — stop (daemon running)', () => {
  test('stop command sends STOP and acknowledges', async () => {
    daemon = new VuleDaemon({ watchDir: tmpDir, socketPath, baselinePath });
    await daemon.start();

    await captureOutput(() => daemonCommand({ action: 'stop', watchDir: tmpDir, socketPath }));
    expect(logs.some((l) => l.includes('stopped'))).toBe(true);
  });
});
