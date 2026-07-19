// apps/api/src/services/poc/sandbox.ts
// P4.3 真 Docker 沙箱(--network=none + timeout + read-only + 资源限制)

import { spawn } from 'node:child_process';
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface SandboxResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  behaviorReport: BehaviorReport;
  exploitProven: boolean;
  durationMs: number;
  errorMessage?: string;
}

export interface BehaviorReport {
  networkCalls: number;
  fileReads: number;
  fileWrites: number;
  syscalls: number;
  indicatorsMatch: number;
  evidenceLines: string[];
}

export interface SandboxOptions {
  script: string;
  runtime?: 'python3' | 'node20' | 'bash';
  timeoutMs?: number;
  memoryMb?: number;
  cpuLimit?: number;
  enableNetwork?: boolean;
}

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_MEMORY = 128;
const DEFAULT_CPU = 0.5;
const MAX_OUTPUT_BYTES = 64 * 1024;

const DANGEROUS_TOKENS = [
  'rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero', 'chmod 777 /',
  '/etc/shadow', '/etc/passwd', 'os.system', '__import__', 'eval(', 'exec(',
];

export async function runInDockerSandbox(opts: SandboxOptions): Promise<SandboxResult> {
  const runtime = opts.runtime ?? 'python3';
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT;
  const memoryMb = opts.memoryMb ?? DEFAULT_MEMORY;
  const cpuLimit = opts.cpuLimit ?? DEFAULT_CPU;

  for (const tok of DANGEROUS_TOKENS) {
    if (opts.script.includes(tok)) {
      return {
        exitCode: -1, stdout: '', stderr: '', durationMs: 0,
        behaviorReport: { networkCalls: 0, fileReads: 0, fileWrites: 0, syscalls: 0, indicatorsMatch: 0, evidenceLines: [] },
        exploitProven: false,
        errorMessage: `Sandbox refused: script contains forbidden token '${tok}'`,
      };
    }
  }

  const dir = await mkdtemp(join(tmpdir(), 'poc-'));
  const scriptName = runtime === 'python3' ? 'poc.py' : runtime === 'node20' ? 'poc.mjs' : 'poc.sh';
  const scriptPath = join(dir, scriptName);
  await writeFile(scriptPath, opts.script, 'utf-8');

  const image = runtime === 'python3' ? 'python:3.12-alpine'
    : runtime === 'node20' ? 'node:20-alpine'
    : 'alpine:3.20';

  const args = [
    'run', '--rm',
    `--memory=${memoryMb}m`,
    `--cpus=${cpuLimit}`,
    '--read-only',
    '--tmpfs=/tmp:size=32m,noexec,nosuid',
    ...(opts.enableNetwork ? [] : ['--network=none']),
    '-v', `${scriptPath}:/poc:ro`,
    image,
    ...(runtime === 'python3' ? ['python', '/poc']
      : runtime === 'node20' ? ['node', '/poc']
      : ['sh', '/poc']),
  ];

  const start = Date.now();
  return new Promise((resolve) => {
    const proc = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
    }, timeoutMs);

    proc.stdout.on('data', (d: Buffer) => {
      if (stdoutBytes < MAX_OUTPUT_BYTES) {
        const s = d.toString();
        stdout += s;
        stdoutBytes += s.length;
      }
    });
    proc.stderr.on('data', (d: Buffer) => {
      if (stderr.length < MAX_OUTPUT_BYTES) {
        stderr += d.toString();
      }
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      rm(dir, { recursive: true, force: true }).catch(() => {});
      const durationMs = Date.now() - start;
      const report = analyzeBehavior(opts.script, stdout, stderr, code, killed);
      const exploitProven = report.indicatorsMatch >= 2;
      resolve({
        exitCode: code, stdout, stderr, behaviorReport: report,
        exploitProven: !killed && code === 0 && exploitProven,
        durationMs,
        errorMessage: killed ? `Timeout after ${timeoutMs}ms` : undefined,
      });
    });
    proc.on('error', (err) => {
      clearTimeout(timer);
      rm(dir, { recursive: true, force: true }).catch(() => {});
      resolve({
        exitCode: -1, stdout, stderr, durationMs: Date.now() - start,
        behaviorReport: { networkCalls: 0, fileReads: 0, fileWrites: 0, syscalls: 0, indicatorsMatch: 0, evidenceLines: [] },
        exploitProven: false,
        errorMessage: err.message,
      });
    });
  });
}

function analyzeBehavior(script: string, stdout: string, stderr: string, code: number | null, killed: boolean): BehaviorReport {
  const combined = `${stdout}\n${stderr}`;
  const lines = combined.split('\n').filter((l) => l.trim());
  const indicators: string[] = [];

  if (script.includes('requests.') || script.includes('urllib') || script.includes('http.client')) {
    indicators.push('network_lib_detected');
  }
  if (/2[0-9]{2}|3[0-9]{2}|401|403|500|OK|Forbidden|sql syntax|mysql_|postgres_|root@|uid=|Syntax error/i.test(combined)) {
    indicators.push('http_or_sql_response');
  }
  if (/vuln|exploit|inject|pwn|root|admin|flag|password|secret/i.test(combined)) {
    indicators.push('exploit_keywords');
  }
  if (code === 0 && !killed) {
    indicators.push('clean_exit');
  }

  return {
    networkCalls: (stdout.match(/(GET|POST|PUT|DELETE|HTTP\/) /g) ?? []).length,
    fileReads: (script.match(/open\(|read\(|with open\(/g) ?? []).length,
    fileWrites: (script.match(/write\(|os\.write\(/g) ?? []).length,
    syscalls: (combined.match(/\b(exec|open|read|write|connect)\(/g) ?? []).length,
    indicatorsMatch: indicators.length,
    evidenceLines: lines.slice(0, 20),
  };
}

export async function isDockerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('docker', ['version', '--format', '{{.Server.Version}}']);
    proc.on('close', (code) => resolve(code === 0));
    proc.on('error', () => resolve(false));
  });
}