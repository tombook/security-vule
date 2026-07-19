import {
  type SCAFinding,
  type SpawnRunner,
  createDefaultRunner,
  BaseSCAAdapter,
  mapSeverity,
} from './adapter.js';

export const TRIVY_NAME = 'trivy' as const;

export const DEFAULT_TRIVY_ARGS = ['fs', '--format', 'json', '--quiet', '--no-progress', '--scanners', 'vuln'] as const;

export const DEFAULT_TRIVY_TIMEOUT_MS = 180_000;

export function defaultTrivyRunner(binaryPath: string): SpawnRunner {
  return createDefaultRunner(binaryPath, DEFAULT_TRIVY_TIMEOUT_MS);
}

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  References?: string[];
}

interface TrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVuln[];
}

interface TrivyOutput {
  Results?: TrivyResult[];
}

export function parseTrivyOutput(raw: string, source: string = TRIVY_NAME): SCAFinding[] {
  if (!raw || !raw.trim()) return [];
  let parsed: TrivyOutput;
  try { parsed = JSON.parse(raw); }
  catch { return []; }
  if (!parsed || !Array.isArray(parsed.Results)) return [];
  const findings: SCAFinding[] = [];
  for (const r of parsed.Results) {
    if (!r || !Array.isArray(r.Vulnerabilities)) continue;
    const target = r.Target || '<unknown>';
    for (const v of r.Vulnerabilities) {
      if (!v || !v.VulnerabilityID) continue;
      const sev = mapSeverity(v.Severity || '');
      const id = v.PkgName ? `${v.PkgName}@${v.InstalledVersion || '?'}` : (v.VulnerabilityID);
      const fixed = v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : '';
      findings.push({
        id: `trivy-${v.VulnerabilityID}-${id}-${findings.length}`,
        type: `trivy-vuln:${v.PkgName || 'package'}`,
        severity: sev,
        title: v.Title || `${v.VulnerabilityID} in ${v.PkgName || 'package'}`,
        description: `${v.VulnerabilityID} affects ${id}${fixed}. ${v.Title || ''}`.trim(),
        file: target,
        line: 1,
        confidence: 0.9,
        cwe: undefined,
        source,
      });
    }
  }
  return findings;
}

export class TrivyAdapter extends BaseSCAAdapter {
  constructor(opts: { binaryPath?: string } = {}) {
    super(TRIVY_NAME, opts.binaryPath);
  }

  protected getDefaultArgs(): readonly string[] { return DEFAULT_TRIVY_ARGS; }
  protected getTimeoutMs(): number { return DEFAULT_TRIVY_TIMEOUT_MS; }
  protected isSuccessExitCode(exitCode: number): boolean { return exitCode === 0; }
  protected parseOutput(raw: string): SCAFinding[] { return parseTrivyOutput(raw, this.name); }
}
