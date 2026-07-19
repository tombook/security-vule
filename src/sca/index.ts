export {
  type SCAAdapter,
  type SCAFinding,
  type ScanOptions,
  type SpawnRunner,
  type SupportedAdapter,
  SUPPORTED_ADAPTERS,
  isSupportedAdapter,
  mapSeverity,
  fingerprintOf,
  dedupFindings,
  createDefaultRunner,
  BaseSCAAdapter,
} from './adapter.js';
export {
  SemgrepAdapter,
  SEMGREP_NAME,
  DEFAULT_SEMGREP_ARGS,
  DEFAULT_SEMGREP_TIMEOUT_MS,
  defaultRunner as defaultSemgrepRunner,
  parseSemgrepOutput,
} from './semgrep.js';
export {
  TrivyAdapter,
  TRIVY_NAME,
  DEFAULT_TRIVY_ARGS,
  DEFAULT_TRIVY_TIMEOUT_MS,
  defaultTrivyRunner,
  parseTrivyOutput,
} from './trivy.js';
import type { VulnerabilityFinding } from '../engine/analyzer.js';
import { type SCAFinding, type ScanOptions, type SCAAdapter, dedupFindings, isSupportedAdapter } from './adapter.js';
import { SemgrepAdapter } from './semgrep.js';
import { TrivyAdapter } from './trivy.js';

export interface RunSCAOptions extends ScanOptions {
  adapters?: { semgrep?: SCAAdapter; trivy?: SCAAdapter };
}

export interface RunSCAResult {
  findings: SCAFinding[];
  skipped: Array<{ name: string; reason: string }>;
}

function defaultAdapters(): { semgrep: SemgrepAdapter; trivy: TrivyAdapter } {
  return { semgrep: new SemgrepAdapter(), trivy: new TrivyAdapter() };
}

interface AdapterOutcome {
  findings: SCAFinding[];
  skipped: Array<{ name: string; reason: string }>;
}

async function runAdapter(
  adapter: SCAAdapter,
  path: string,
  options: ScanOptions
): Promise<AdapterOutcome> {
  if (!adapter.isAvailable()) {
    console.error(`[security-vule/sca] ${adapter.name} not found in PATH; skipping`);
    return { findings: [], skipped: [{ name: adapter.name, reason: 'binary-not-found' }] };
  }
  try {
    const findings = await adapter.scan(path, options);
    return { findings, skipped: [] };
  } catch (e) {
    console.error(`[security-vule/sca] ${adapter.name} scan error: ${(e as Error).message}`);
    return { findings: [], skipped: [{ name: adapter.name, reason: 'scan-error' }] };
  }
}

export async function runSCA(
  path: string,
  enabledList: string[] = [],
  options: RunSCAOptions = {}
): Promise<RunSCAResult> {
  const result: RunSCAResult = { findings: [], skipped: [] };
  if (!Array.isArray(enabledList) || enabledList.length === 0) {
    return result;
  }
  const adapters = options.adapters || defaultAdapters();
  const wanted = new Set(enabledList.filter(n => isSupportedAdapter(n)));
  for (const unknown of enabledList.filter(n => !isSupportedAdapter(n))) {
    result.skipped.push({ name: unknown, reason: 'unsupported-adapter' });
  }
  const tasks: Array<Promise<AdapterOutcome>> = [];
  if (wanted.has('semgrep')) {
    tasks.push(runAdapter(adapters.semgrep || new SemgrepAdapter(), path, options));
  }
  if (wanted.has('trivy')) {
    tasks.push(runAdapter(adapters.trivy || new TrivyAdapter(), path, options));
  }
  const outcomes = await Promise.all(tasks);
  for (const o of outcomes) {
    result.findings.push(...o.findings);
    result.skipped.push(...o.skipped);
  }
  return result;
}

export function combineFindings(
  dfgFindings: VulnerabilityFinding[],
  scaFindings: SCAFinding[]
): (VulnerabilityFinding & { source?: string })[] {
  return dedupFindings<VulnerabilityFinding & { source?: string }>(
    dfgFindings,
    scaFindings
  );
}
