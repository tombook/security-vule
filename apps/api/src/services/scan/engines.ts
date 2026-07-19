// apps/api/src/services/scan/engines.ts
// P3.1 真实引擎集成(scaffold)
// 调用 Semgrep / Trivy / 自研 DFG 子进程,JSON 解析归一为 detection.findings

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

export interface RawFinding {
  rule_id: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file_path: string;
  start_line: number;
  end_line?: number;
  code_snippet?: string;
  cwe_ids?: string[];
  owasp_ids?: string[];
  confidence?: 'high' | 'medium' | 'low';
  engine: string;
}

export interface EngineResult {
  engine: string;
  findings: RawFinding[];
  durationMs: number;
  status: 'success' | 'partial' | 'failed' | 'timeout';
  errorMessage?: string;
}

function genFindingId(ruleId: string, filePath: string, startLine: number): string {
  return createHash('sha256')
    .update(`${ruleId}|${filePath}|${startLine}`)
    .digest('hex')
    .slice(0, 32);
}

async function runProc(cmd: string, args: string[], cwd: string, timeoutMs = 60_000): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { cwd });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill('SIGKILL');
    }, timeoutMs);
    proc.stdout.on('data', (d) => stdout += d);
    proc.stderr.on('data', (d) => stderr += d);
    proc.on('close', (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code, timedOut });
    });
    proc.on('error', (err) => {
      clearTimeout(timer);
      resolve({ stdout, stderr: err.message, code: -1, timedOut: false });
    });
  });
}

export async function runSemgrep(projectDir: string, timeoutMs = 120_000): Promise<EngineResult> {
  const start = Date.now();
  const args = [
    'scan',
    '--config=auto',
    '--json',
    '--quiet',
    '--disable-version-check',
    projectDir,
  ];
  const { stdout, stderr, code, timedOut } = await runProc('semgrep', args, projectDir, timeoutMs);
  const durationMs = Date.now() - start;
  if (code === -1 || timedOut) {
    return { engine: 'semgrep', findings: [], durationMs, status: timedOut ? 'timeout' : 'failed', errorMessage: stderr.slice(0, 500) };
  }
  try {
    const data = JSON.parse(stdout);
    const findings: RawFinding[] = (data.results ?? []).map((r: any) => ({
      rule_id: r.check_id ?? 'unknown',
      title: r.extra?.message ?? r.check_id ?? 'Unknown',
      description: r.extra?.metadata?.short_description ?? '',
      severity: mapSeverity(r.extra?.severity ?? 'WARNING'),
      file_path: r.path,
      start_line: r.start?.line ?? 0,
      end_line: r.end?.line ?? undefined,
      code_snippet: r.extra?.lines?.slice(0, 5)?.join('\n'),
      cwe_ids: r.extra?.metadata?.cwe ?? [],
      owasp_ids: r.extra?.metadata?.owasp ?? [],
      confidence: 'high',
      engine: 'semgrep',
    }));
    return { engine: 'semgrep', findings, durationMs, status: 'success' };
  } catch (err: any) {
    return { engine: 'semgrep', findings: [], durationMs, status: 'partial', errorMessage: `Parse error: ${err.message}; stderr=${stderr.slice(0, 200)}` };
  }
}

export async function runTrivy(projectDir: string, timeoutMs = 120_000): Promise<EngineResult> {
  const start = Date.now();
  const { stdout, stderr, code, timedOut } = await runProc('trivy', [
    'fs', '--format', 'json', '--quiet', '--scanners', 'vuln,secret', projectDir,
  ], projectDir, timeoutMs);
  const durationMs = Date.now() - start;
  if (code === -1 || timedOut) {
    return { engine: 'trivy', findings: [], durationMs, status: timedOut ? 'timeout' : 'failed', errorMessage: stderr.slice(0, 500) };
  }
  try {
    const reports: any[] = JSON.parse(stdout) ?? [];
    const findings: RawFinding[] = [];
    for (const r of reports) {
      for (const v of r.Results ?? []) {
        for (const vuln of v.Vulnerabilities ?? []) {
          findings.push({
            rule_id: vuln.VulnerabilityID ?? 'CVE-UNKNOWN',
            title: `${vuln.PkgName} ${vuln.InstalledVersion}: ${vuln.Title ?? vuln.VulnerabilityID}`,
            description: vuln.Description ?? '',
            severity: mapSeverity(vuln.Severity),
            file_path: v.Target,
            start_line: 0,
            cwe_ids: vuln.CweIDs ?? [],
            owasp_ids: vuln.References?.filter((r: string) => r.includes('owasp.org')) ?? [],
            confidence: 'high',
            engine: 'trivy',
          });
        }
      }
    }
    return { engine: 'trivy', findings, durationMs, status: 'success' };
  } catch (err: any) {
    return { engine: 'trivy', findings: [], durationMs, status: 'partial', errorMessage: `Parse error: ${err.message}` };
  }
}

export async function runDFG(projectDir: string, timeoutMs = 180_000): Promise<EngineResult> {
  const start = Date.now();
  const bunBin = process.env.BUN_BIN ?? 'bun';
  const { stdout, stderr, code, timedOut } = await runProc(bunBin, [
    'run', 'src/cli.ts', 'scan', projectDir, '--json', '--engine=dfg', '--no-poc', '--no-report',
  ], process.env.PROJECT_ROOT ?? projectDir, timeoutMs);
  const durationMs = Date.now() - start;
  if (code === -1 || timedOut) {
    return { engine: 'dfg', findings: [], durationMs, status: timedOut ? 'timeout' : 'failed', errorMessage: stderr.slice(0, 500) };
  }
  try {
    const data = JSON.parse(stdout);
    const findings: RawFinding[] = (data.findings ?? []).map((f: any) => ({
      rule_id: f.rule_id ?? 'dfg-custom',
      title: f.title ?? 'DFG-detected vulnerability',
      description: f.description ?? '',
      severity: mapSeverity(f.severity ?? 'medium'),
      file_path: f.file_path,
      start_line: f.start_line ?? 0,
      end_line: f.end_line,
      code_snippet: f.code_snippet,
      cwe_ids: f.cwe_ids ?? [],
      owasp_ids: f.owasp_ids ?? [],
      confidence: f.confidence ?? 'high',
      engine: 'dfg',
    }));
    return { engine: 'dfg', findings, durationMs, status: 'success' };
  } catch (err: any) {
    return { engine: 'dfg', findings: [], durationMs, status: 'partial', errorMessage: `DFG output parse: ${err.message}` };
  }
}

export async function runAllEngines(projectDir: string): Promise<EngineResult[]> {
  const [semgrep, trivy, dfg] = await Promise.all([
    runSemgrep(projectDir).catch((err): EngineResult => ({
      engine: 'semgrep', findings: [], durationMs: 0, status: 'failed', errorMessage: err.message,
    })),
    runTrivy(projectDir).catch((err): EngineResult => ({
      engine: 'trivy', findings: [], durationMs: 0, status: 'failed', errorMessage: err.message,
    })),
    runDFG(projectDir).catch((err): EngineResult => ({
      engine: 'dfg', findings: [], durationMs: 0, status: 'failed', errorMessage: err.message,
    })),
  ]);
  return [semgrep, trivy, dfg];
}

export function dedupeFindings(allResults: EngineResult[]): RawFinding[] {
  const byFingerprint = new Map<string, RawFinding>();
  for (const result of allResults) {
    for (const f of result.findings) {
      const fingerprint = genFindingId(f.rule_id, f.file_path, f.start_line);
      const existing = byFingerprint.get(fingerprint);
      if (!existing) {
        byFingerprint.set(fingerprint, f);
      } else {
        if (severityRank(f.severity) > severityRank(existing.severity)) {
          existing.severity = f.severity;
        }
        if (!existing.cwe_ids?.length) existing.cwe_ids = f.cwe_ids;
      }
    }
  }
  return Array.from(byFingerprint.values());
}

function mapSeverity(s: string): RawFinding['severity'] {
  const u = (s ?? '').toUpperCase();
  if (u === 'CRITICAL' || u === 'ERROR') return 'critical';
  if (u === 'HIGH' || u === 'WARNING') return 'high';
  if (u === 'MEDIUM' || u === 'INFO') return 'medium';
  return 'low';
}

function severityRank(s: string): number {
  return ({ critical: 4, high: 3, medium: 2, low: 1 } as any)[s] ?? 0;
}