import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const MOCK_PORT = 8080;

async function portOpen(host: string, port: number, timeoutMs = 500): Promise<boolean> {
  try {
    const net = await import('net');
    return await new Promise<boolean>((resolve) => {
      const sock = new net.Socket();
      let settled = false;
      const done = (v: boolean) => {
        if (settled) return;
        settled = true;
        try { sock.destroy(); } catch {}
        resolve(v);
      };
      sock.setTimeout(timeoutMs);
      sock.once('connect', () => done(true));
      sock.once('timeout', () => done(false));
      sock.once('error', () => done(false));
      sock.connect(port, host);
    });
  } catch {
    return false;
  }
}

const findingsFixture = {
  findings: [
    {
      id: 'f-sqli-1',
      type: 'sql',
      severity: 'CRITICAL',
      title: 'SQL Injection in id',
      description: 'user input id flows into SQL query',
      file: '/tmp/integration-app/users.php',
      line: 5,
      confidence: 0.95,
      cwe: 'CWE-89',
    },
    {
      id: 'f-shell-1',
      type: 'shell',
      severity: 'CRITICAL',
      title: 'Command Injection in ip',
      description: 'user input ip flows into shell_exec',
      file: '/tmp/integration-app/ping.php',
      line: 7,
      confidence: 0.95,
      cwe: 'CWE-78',
    },
    {
      id: 'f-xss-1',
      type: 'xss',
      severity: 'HIGH',
      title: 'Reflected XSS in name',
      description: 'user input name echoed back',
      file: '/tmp/integration-app/search.php',
      line: 3,
      confidence: 0.85,
      cwe: 'CWE-79',
    },
  ],
};

let mockProc: ReturnType<typeof Bun.spawn> | null = null;
let mockStarted = false;
let skipReason = '';

async function ensureMockServer(): Promise<boolean> {
  if (mockStarted) return true;
  if (await portOpen('localhost', MOCK_PORT, 200)) {
    mockStarted = true;
    return true;
  }
  const py = process.env.PYTHON_BIN || 'python3';
  const script = join(process.cwd(), 'poc-validator', 'mock_dvwa.py');
  if (!existsSync(script)) {
    skipReason = `mock_dvwa.py not found at ${script}`;
    return false;
  }
  try {
    mockProc = Bun.spawn([py, script, String(MOCK_PORT)], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
  } catch (e) {
    skipReason = `failed to spawn mock_dvwa.py: ${(e as Error).message}`;
    return false;
  }
  for (let i = 0; i < 60; i++) {
    if (await portOpen('localhost', MOCK_PORT, 200)) {
      mockStarted = true;
      return true;
    }
    await new Promise(r => setTimeout(r, 200));
  }
  try { mockProc.kill(); } catch {}
  mockProc = null;
  skipReason = 'mock_dvwa.py did not start within 12s';
  return false;
}

async function stopMockServer(): Promise<void> {
  if (mockProc) {
    try { mockProc.kill(); } catch {}
    mockProc = null;
  }
  mockStarted = false;
}

describe('integration: end-to-end PoC verification against mock DVWA', () => {
  let dir: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'sv-int-poc-'));
    const inUse = await portOpen('localhost', MOCK_PORT, 100);
    if (inUse) {
      skipReason = `port ${MOCK_PORT} already in use (Docker or other service); cannot start mock_dvwa.py`;
      console.warn(`[skip] ${skipReason}`);
      mockStarted = false;
      return;
    }
    const ok = await ensureMockServer();
    if (!ok) {
      console.warn(`[skip] ${skipReason}`);
    }
  }, 30_000);

  afterAll(async () => {
    await stopMockServer();
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  test('end-to-end verify-poc against mock_dvwa.py (via dvwa target)', async () => {
    if (!mockStarted) {
      console.warn(`[skip] ${skipReason}`);
      return;
    }
    const { runPoCVerification } = await import('../../src/poc/runner.js');
    const result = await runPoCVerification(findingsFixture.findings, { target: 'dvwa', timeoutMs: 30_000 });
    expect(result.ok).toBe(true);
    expect(result.merged).toBeDefined();
    expect(result.merged!.length).toBe(3);
    const sqli = result.merged!.find(m => m.id === 'f-sqli-1');
    const shell = result.merged!.find(m => m.id === 'f-shell-1');
    const xss = result.merged!.find(m => m.id === 'f-xss-1');
    expect(sqli).toBeDefined();
    expect(shell).toBeDefined();
    expect(xss).toBeDefined();
    expect(sqli!.exploit_proven).toBe(true);
    expect(shell!.exploit_proven).toBe(true);
    expect(xss!.exploit_proven).toBe(true);
    expect(sqli!.poc_mark).toBe('✅ verified');
    expect(shell!.poc_mark).toBe('✅ verified');
    expect(xss!.poc_mark).toBe('✅ verified');
    expect(result.verification!.verified).toBeGreaterThanOrEqual(2);
  }, 60_000);

  test('end-to-end verifyPocCommand writes merged results JSON', async () => {
    if (!mockStarted) {
      console.warn(`[skip] ${skipReason}`);
      return;
    }
    const { verifyPocCommand } = await import('../../src/cli.js');
    const findingsFile = join(dir, 'findings.json');
    const outputFile = join(dir, 'verified.json');
    writeFileSync(findingsFile, JSON.stringify(findingsFixture));
    const code = await verifyPocCommand([findingsFile, '--target=dvwa', '--output', outputFile]);
    expect(code).toBe(0);
    expect(existsSync(outputFile)).toBe(true);
    const out = JSON.parse(await Bun.file(outputFile).text());
    expect(out.ok).toBe(true);
    expect(out.merged.length).toBe(3);
    for (const m of out.merged) {
      expect('exploit_proven' in m).toBe(true);
      expect('poc_mark' in m).toBe(true);
    }
  }, 60_000);

  test('end-to-end scan --with-poc --poc-target=mock writes exploit_proven into output JSON', async () => {
    if (!mockStarted) {
      console.warn(`[skip] ${skipReason}`);
      return;
    }
    const { scanCommand } = await import('../../src/cli.js');
    const projectDir = mkdtempSync(join(tmpdir(), 'sv-int-scan-'));
    try {
      writeFileSync(join(projectDir, 'a.py'), `import os
user_input = os.environ.get("INPUT", "")
os.system("echo " + user_input)
`);
      const outputFile = join(projectDir, 'findings.json');
      let capturedOut = '';
      const origLog = console.log;
      (console as any).log = (s: string) => { capturedOut += s; };
      try {
        await scanCommand([projectDir, '--min-confidence', '0', '--with-poc', '--poc-target=mock', '-o', outputFile]);
      } finally {
        (console as any).log = origLog;
      }
      expect(existsSync(outputFile)).toBe(true);
      const summary = JSON.parse(await Bun.file(outputFile).text());
      expect(summary.findings.length).toBeGreaterThan(0);
      for (const f of summary.findings) {
        expect('exploit_proven' in f).toBe(true);
        expect('poc_mark' in f).toBe(true);
      }
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
    }
  }, 60_000);

  test('mock_dvwa.py itself is reachable on configured port', async () => {
    if (!mockStarted) {
      console.warn(`[skip] ${skipReason}`);
      return;
    }
    const ok = await portOpen('localhost', MOCK_PORT, 1000);
    expect(ok).toBe(true);
  });
});
