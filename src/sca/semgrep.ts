import {
  type SCAFinding,
  type SpawnRunner,
  createDefaultRunner,
  BaseSCAAdapter,
  mapSeverity,
} from './adapter.js';

export const SEMGREP_NAME = 'semgrep' as const;

export const DEFAULT_SEMGREP_ARGS = ['--config=auto', '--json', '--quiet', '--error', '--no-git-ignore'] as const;

export const DEFAULT_SEMGREP_TIMEOUT_MS = 120_000;

export function defaultRunner(binaryPath: string): SpawnRunner {
  return createDefaultRunner(binaryPath, DEFAULT_SEMGREP_TIMEOUT_MS);
}

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  end?: { line?: number };
  extra?: {
    severity?: string;
    message?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      'security-severity'?: string;
    };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: unknown[];
}

function pickCwe(cwe: string | string[] | undefined): string | undefined {
  if (!cwe) return undefined;
  if (Array.isArray(cwe)) return cwe[0];
  return cwe;
}

function pickCweFromResult(r: SemgrepResult): string | undefined {
  return pickCwe(r.extra?.metadata?.cwe);
}

export function parseSemgrepOutput(raw: string, source: string = SEMGREP_NAME): SCAFinding[] {
  if (!raw || !raw.trim()) return [];
  let parsed: SemgrepOutput;
  try { parsed = JSON.parse(raw); }
  catch { return []; }
  if (!parsed || !Array.isArray(parsed.results)) return [];
  const findings: SCAFinding[] = [];
  for (const r of parsed.results) {
    if (!r || !r.path) continue;
    const line = Number(r.start?.line) || 1;
    const sev = mapSeverity(r.extra?.severity || '');
    const cwe = pickCweFromResult(r);
    findings.push({
      id: `semgrep-${r.check_id || 'rule'}-${line}-${findings.length}`,
      type: r.check_id || 'semgrep-finding',
      severity: sev,
      title: r.extra?.message || r.check_id || 'Semgrep finding',
      description: r.extra?.message || `Semgrep rule ${r.check_id} matched`,
      file: r.path,
      line,
      confidence: 0.8,
      cwe,
      source,
    });
  }
  return findings;
}

export class SemgrepAdapter extends BaseSCAAdapter {
  constructor(opts: { binaryPath?: string } = {}) {
    super(SEMGREP_NAME, opts.binaryPath);
  }

  protected getDefaultArgs(): readonly string[] { return DEFAULT_SEMGREP_ARGS; }
  protected getTimeoutMs(): number { return DEFAULT_SEMGREP_TIMEOUT_MS; }
  protected isSuccessExitCode(exitCode: number): boolean { return exitCode === 0 || exitCode === 1; }
  protected parseOutput(raw: string): SCAFinding[] { return parseSemgrepOutput(raw, this.name); }
}
