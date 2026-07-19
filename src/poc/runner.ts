/**
 * Wave 3 · PoC 验证 runner
 *
 * 通过 Bun.spawn 调用 poc-validator/verify_poc.py,对 cli scan 的 JSON findings
 * 进行 PoC 运行时验证。提供目标健康检查、进程包装、结果解析、与原 findings 合并
 * 等能力。verify_poc.py 是 Python 脚本,本模块不引入 python-shell 等额外依赖。
 */
import type { VulnerabilityFinding } from '../engine/analyzer.js';

export type PoCTarget = 'mock' | 'dvwa' | 'bwapp' | 'sqlilabs' | 'pikachu' | 'auto' | 'none';

export interface PoCRunOptions {
  /** Python 二进制路径,默认 'python3' */
  pythonBin?: string;
  /** verify_poc.py 相对项目根的路径,默认 'poc-validator/verify_poc.py' */
  scriptPath?: string;
  /** 显式指定目标(dvwa/bwapp/sqlilabs/pikachu/mock/auto/none);auto 表示让脚本自己探测 */
  target?: PoCTarget;
  /** spawn 进程的超时时间(毫秒) */
  timeoutMs?: number;
  /** 注入用于测试的 spawn runner(代替 Bun.spawn) */
  runner?: SpawnRunner;
  /** TCP connect 注入(用于测试) */
  probe?: PortProbe;
  /** 静默模式:不打印警告到 stderr */
  silent?: boolean;
}

export type SpawnRunner = (
  cmd: string[],
  options?: { cwd?: string; timeoutMs?: number }
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export type PortProbe = (host: string, port: number, timeoutMs?: number) => Promise<boolean>;

export interface VerifiedFinding {
  finding: VulnerabilityFinding;
  verification: {
    verified: boolean | null;
    reason?: string;
    pocs_attempted?: number;
    pocs_verified?: number;
    details?: Array<Record<string, unknown>>;
  };
}

export interface PoCVerificationOutput {
  tool: string;
  mode: string;
  target: string;
  total_findings: number;
  verified: number;
  unverified: number;
  unconfirmed: number;
  findings: VerifiedFinding[];
}

export interface MergedFinding extends VulnerabilityFinding {
  exploit_proven: boolean | null;
  poc_mark: '✅ verified' | '❌ not exploited' | '⚠️ not verified';
}

export interface PoCRunResult {
  ok: boolean;
  skipped?: 'no-target' | 'spawn-failed' | 'parse-failed' | 'no-findings';
  message?: string;
  verification?: PoCVerificationOutput;
  merged?: MergedFinding[];
  stdout?: string;
  stderr?: string;
}

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_PYTHON = 'python3';
const DEFAULT_SCRIPT = 'poc-validator/verify_poc.py';
const DEFAULT_TARGET: PoCTarget = 'auto';

export const TARGET_PORTS: Record<string, { host: string; port: number; baseUrl: string }> = {
  mock: { host: 'localhost', port: 8080, baseUrl: 'http://localhost:8080' },
  dvwa: { host: 'localhost', port: 8080, baseUrl: 'http://localhost:8080' },
  bwapp: { host: 'localhost', port: 8081, baseUrl: 'http://localhost:8081' },
  sqlilabs: { host: 'localhost', port: 8082, baseUrl: 'http://localhost:8082' },
  pikachu: { host: 'localhost', port: 8083, baseUrl: 'http://localhost:8083' },
};

export async function portOpen(host: string, port: number, timeoutMs = 500): Promise<boolean> {
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

export interface TargetHealth {
  target: PoCTarget;
  reachable: boolean;
  baseUrl?: string;
  host?: string;
  port?: number;
}

export async function detectTargetHealth(
  target: PoCTarget,
  probe: PortProbe = portOpen
): Promise<TargetHealth> {
  if (target === 'none') {
    return { target, reachable: false };
  }
  if (target === 'auto') {
    if (await probe('localhost', 8080, 300)) {
      return { target, reachable: true, host: 'localhost', port: 8080, baseUrl: 'http://localhost:8080' };
    }
    for (const k of ['dvwa', 'bwapp', 'sqlilabs', 'pikachu'] as const) {
      const info = TARGET_PORTS[k];
      if (await probe(info.host, info.port, 300)) {
        return { target: k, reachable: true, host: info.host, port: info.port, baseUrl: info.baseUrl };
      }
    }
    return { target, reachable: false };
  }
  const info = TARGET_PORTS[target];
  if (!info) return { target, reachable: false };
  const ok = await probe(info.host, info.port, 500);
  return ok
    ? { target, reachable: true, host: info.host, port: info.port, baseUrl: info.baseUrl }
    : { target, reachable: false, host: info.host, port: info.port, baseUrl: info.baseUrl };
}

export function parseVerifyPocOutput(raw: string): PoCVerificationOutput | null {
  if (!raw || !raw.trim()) return null;
  let parsed: any;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!parsed || typeof parsed !== 'object') return null;
  if (!Array.isArray(parsed.findings)) return null;
  return {
    tool: String(parsed.tool || 'security-vule + PoC verification'),
    mode: String(parsed.mode || 'unknown'),
    target: String(parsed.target || ''),
    total_findings: Number(parsed.total_findings ?? parsed.findings.length),
    verified: Number(parsed.verified ?? 0),
    unverified: Number(parsed.unverified ?? 0),
    unconfirmed: Number(parsed.unconfirmed ?? 0),
    findings: parsed.findings as VerifiedFinding[],
  };
}

export function createDefaultRunner(pythonBin: string, scriptPath: string): SpawnRunner {
  return async (cmd, opts) => {
    const proc = Bun.spawn(cmd, {
      cwd: opts?.cwd,
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    const timer = setTimeout(() => { try { proc.kill(); } catch {} }, opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    clearTimeout(timer);
    return { stdout, stderr, exitCode };
  };
}

export function fingerprintOf(f: { file: string; line: number; type: string }): string {
  return `${f.file}:${f.line}:${f.type}`;
}

export function mergeFindings(
  findings: VulnerabilityFinding[],
  verification: PoCVerificationOutput
): MergedFinding[] {
  const byKey = new Map<string, VerifiedFinding>();
  for (const v of verification.findings) {
    const f = v.finding;
    if (!f) continue;
    const key = fingerprintOf({ file: String(f.file || ''), line: Number(f.line || 0), type: String(f.type || '') });
    byKey.set(key, v);
  }
  return findings.map((f) => {
    const key = fingerprintOf({ file: String(f.file || ''), line: Number(f.line || 0), type: String(f.type || '') });
    const v = byKey.get(key);
    let exploit_proven: boolean | null = null;
    let mark: MergedFinding['poc_mark'] = '⚠️ not verified';
    if (v) {
      const verified = v.verification?.verified;
      if (verified === true) { exploit_proven = true; mark = '✅ verified'; }
      else if (verified === false) { exploit_proven = false; mark = '❌ not exploited'; }
      else { exploit_proven = null; mark = '⚠️ not verified'; }
    }
    return { ...f, exploit_proven, poc_mark: mark } as MergedFinding;
  });
}

export async function runPoCVerification(
  findingsInput: VulnerabilityFinding[],
  options: PoCRunOptions = {}
): Promise<PoCRunResult> {
  const target: PoCTarget = options.target ?? DEFAULT_TARGET;
  if (target === 'none') {
    return { ok: false, skipped: 'no-target', message: 'poc-target=none; skipping verification' };
  }
  const probe = options.probe ?? portOpen;
  const health = await detectTargetHealth(target, probe);
  if (!health.reachable) {
    return {
      ok: false,
      skipped: 'no-target',
      message: `no PoC target reachable (requested=${target}); start mock_dvwa.py on :8080 or use --poc-target=none to skip`,
    };
  }
  const py = options.pythonBin ?? DEFAULT_PYTHON;
  const script = options.scriptPath ?? DEFAULT_SCRIPT;
  const outFile = `/tmp/sv_poc_${Date.now()}_${Math.floor(Math.random() * 1e6)}.json`;
  const inputFile = `/tmp/sv_findings_${Date.now()}_${Math.floor(Math.random() * 1e6)}.json`;
  await Bun.write(inputFile, JSON.stringify({ findings: findingsInput }, null, 2));
  const args = [py, script, '--findings', inputFile, '--output', outFile];
  if (target !== 'auto') args.push('--target', target);
  const runner = options.runner ?? createDefaultRunner(py, script);
  let spawnResult: { stdout: string; stderr: string; exitCode: number };
  try {
    spawnResult = await runner(args, { timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS });
  } catch (e) {
    if (!options.silent) {
      console.error(`[security-vule/poc] spawn failed: ${(e as Error).message}`);
    }
    return { ok: false, skipped: 'spawn-failed', message: (e as Error).message };
  }
  if (spawnResult.exitCode !== 0) {
    if (!options.silent) {
      console.error(`[security-vule/poc] verify_poc.py exited ${spawnResult.exitCode}: ${spawnResult.stderr.slice(0, 300)}`);
    }
    return { ok: false, skipped: 'spawn-failed', message: `exit ${spawnResult.exitCode}`, stdout: spawnResult.stdout, stderr: spawnResult.stderr };
  }
  let rawOut: string;
  try {
    rawOut = await Bun.file(outFile).text();
  } catch (e) {
    return { ok: false, skipped: 'parse-failed', message: `read output failed: ${(e as Error).message}`, stdout: spawnResult.stdout, stderr: spawnResult.stderr };
  }
  const verification = parseVerifyPocOutput(rawOut);
  if (!verification) {
    return { ok: false, skipped: 'parse-failed', message: 'verify_poc.py output is not valid JSON', stdout: spawnResult.stdout, stderr: spawnResult.stderr };
  }
  const merged = mergeFindings(findingsInput, verification);
  return { ok: true, verification, merged, stdout: spawnResult.stdout, stderr: spawnResult.stderr };
}

export function isPoCTarget(value: string): value is PoCTarget {
  return ['mock', 'dvwa', 'bwapp', 'sqlilabs', 'pikachu', 'auto', 'none'].includes(value);
}
