import type { VulnerabilityFinding } from '../engine/analyzer.js';

export interface SCAFinding extends VulnerabilityFinding {
  source: 'semgrep' | 'trivy' | string;
}

export interface ScanOptions {
  cwd?: string;
  timeoutMs?: number;
  runner?: SpawnRunner;
}

export type SpawnRunner = (
  cmd: string[],
  options?: { cwd?: string; timeoutMs?: number }
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export interface SCAAdapter {
  readonly name: string;
  readonly binary: string;
  isAvailable(): boolean;
  scan(path: string, options?: ScanOptions): Promise<SCAFinding[]>;
}

export function mapSeverity(severity: string): VulnerabilityFinding['severity'] {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'error' || s === 'blocker') return 'CRITICAL';
  if (s === 'high' || s === 'warning') return 'HIGH';
  if (s === 'medium' || s === 'moderate') return 'MEDIUM';
  if (s === 'low' || s === 'info' || s === 'informational' || s === 'note') return 'LOW';
  return 'LOW';
}

export function fingerprintOf(f: { file: string; line: number; type: string }): string {
  return `${f.file}:${f.line}:${f.type}`;
}

export function dedupFindings<T extends { file: string; line: number; type: string }>(
  primary: T[],
  secondary: T[]
): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const f of primary) {
    const fp = fingerprintOf(f);
    if (seen.has(fp)) continue;
    seen.add(fp);
    out.push(f);
  }
  for (const f of secondary) {
    const fp = fingerprintOf(f);
    if (seen.has(fp)) continue;
    seen.add(fp);
    out.push(f);
  }
  return out;
}

export const SUPPORTED_ADAPTERS = ['semgrep', 'trivy'] as const;
export type SupportedAdapter = typeof SUPPORTED_ADAPTERS[number];

export function isSupportedAdapter(name: string): name is SupportedAdapter {
  return (SUPPORTED_ADAPTERS as readonly string[]).includes(name);
}

export function createDefaultRunner(binaryPath: string, timeoutMs: number): SpawnRunner {
  return async (cmd, opts) => {
    const fullCmd = [binaryPath, ...cmd.slice(1)];
    const proc = Bun.spawn(fullCmd, {
      cwd: opts?.cwd,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const timer = setTimeout(() => { try { proc.kill(); } catch {} }, opts?.timeoutMs ?? timeoutMs);
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    clearTimeout(timer);
    return { stdout, stderr, exitCode };
  };
}

export abstract class BaseSCAAdapter implements SCAAdapter {
  readonly name: string;
  readonly binary: string;
  protected readonly binaryPath: string;

  constructor(name: string, binaryPath?: string) {
    this.name = name;
    this.binary = name;
    this.binaryPath = binaryPath || name;
  }

  isAvailable(): boolean {
    if (this.binaryPath !== this.name) return true;
    return typeof Bun !== 'undefined' && typeof Bun.which === 'function'
      ? Bun.which(this.name) !== null
      : false;
  }

  async scan(path: string, options: ScanOptions = {}): Promise<SCAFinding[]> {
    const runner = options.runner || createDefaultRunner(this.binaryPath, this.getTimeoutMs());
    const cmd = [this.binaryPath, ...this.getDefaultArgs(), path];
    let result: { stdout: string; stderr: string; exitCode: number };
    try {
      result = await runner(cmd, { cwd: options.cwd, timeoutMs: options.timeoutMs });
    } catch (e) {
      console.error(`[security-vule/sca/${this.name}] runner error: ${(e as Error).message}`);
      return [];
    }
    if (!this.isSuccessExitCode(result.exitCode)) {
      console.error(`[security-vule/sca/${this.name}] non-zero exit (${result.exitCode}): ${result.stderr.slice(0, 200)}`);
      return [];
    }
    return this.parseOutput(result.stdout);
  }

  protected abstract getDefaultArgs(): readonly string[];
  protected abstract getTimeoutMs(): number;
  protected abstract isSuccessExitCode(exitCode: number): boolean;
  protected abstract parseOutput(raw: string): SCAFinding[];
}
