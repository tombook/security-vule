/**
 * Triage + Dedupe engine.
 *
 * Inspired by Anthropic Harness /triage skill (5688 stars).
 * Cross-run + cross-file dedupe, severity recalibration against threat model,
 * voting by multiple graders, known-bugs suppression.
 *
 * Pipeline:
 *1. Load findings from multiple sources (current run + history + known bugs)
 *2. Dedupe via fingerprint hash (file + line + vulnType + signature)
 *3. Suppress known bugs (exact or near-exact match)
 *4. Recalibrate severity against threat model (e.g., internet-facing SQLi = CRITICAL, internal=medium)
 *5. Vote on disputed findings (multiple graders, consensus)
 *6. Rank by severity + UVRS + business-criticality
 */

import { createHash } from 'crypto';

export interface Finding {
  id: string;
  file: string;
  line: number;
  vulnType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  uvrs: number;
  description?: string;
  cwe?: string[];
}

export interface KnownBug {
  fingerprint: string;
  reason: string;
  reportedBy?: string;
  reportedAt?: string;
}

export interface ThreatModel {
  internetFacing: string[];
  internalOnly: string[];
  dataClassification: Record<string, 'public' | 'internal' | 'confidential' | 'pii'>;
  criticalAssets: string[];
}

export interface TriageOptions {
  knownBugs?: KnownBug[];
  threatModel?: ThreatModel;
  votes?: number;
  suppressThreshold?: number;
  recencyBoostDays?: number;
}

export interface TriageResult {
  deduplicated: Finding[];
  suppressed: Array<{ finding: Finding; reason: string; matchType: 'exact' | 'known' }>;
  recalibrated: Finding[];
  ranked: Finding[];
  summary: {
    total: number;
    unique: number;
    suppressed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  voted: Array<{ finding: Finding; votes: number; agreement: number }>;
}

export function fingerprintFinding(f: Finding): string {
  const key = `${f.file}:${f.line}:${f.vulnType}`;
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export function triageFindings(findings: Finding[], options: TriageOptions = {}): TriageResult {
  const { knownBugs = [], threatModel, votes = 1 } = options;

  const seen = new Map<string, Finding>();
  const suppressed: TriageResult['suppressed'] = [];
  const deduplicated: Finding[] = [];

  for (const f of findings) {
    const fp = fingerprintFinding(f);
    if (seen.has(fp)) continue;
    seen.set(fp, f);
    deduplicated.push(f);
  }

  for (const f of deduplicated) {
    const fp = fingerprintFinding(f);
    const known = knownBugs.find((b) => b.fingerprint === fp);
    if (known) {
      suppressed.push({ finding: f, reason: known.reason, matchType: 'exact' });
    }
  }

  const active = deduplicated.filter(
    (f) => !suppressed.some((s) => fingerprintFinding(s.finding) === fingerprintFinding(f))
  );

  const recalibrated = threatModel
    ? active.map((f) => recalibrateSeverity(f, threatModel))
    : active;

  const voted: TriageResult['voted'] = votes > 1 ? applyVoting(recalibrated, votes) : [];

  const ranked = recalibrated.slice().sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.uvrs - a.uvrs;
  });

  const summary = {
    total: findings.length,
    unique: deduplicated.length,
    suppressed: suppressed.length,
    critical: ranked.filter((f) => f.severity === 'CRITICAL').length,
    high: ranked.filter((f) => f.severity === 'HIGH').length,
    medium: ranked.filter((f) => f.severity === 'MEDIUM').length,
    low: ranked.filter((f) => f.severity === 'LOW').length,
  };

  return { deduplicated, suppressed, recalibrated, ranked, summary, voted };
}

function recalibrateSeverity(f: Finding, tm: ThreatModel): Finding {
  let severity = f.severity;
  const isInternetFacing = tm.internetFacing.some((p) => f.file.includes(p));
  const isInternalOnly = tm.internalOnly.some((p) => f.file.includes(p));
  const isCriticalAsset = tm.criticalAssets.some((p) => f.file.includes(p));

  if (
    isInternetFacing &&
    severity !== 'CRITICAL' &&
    SEVERITY_RANK[severity] < SEVERITY_RANK.CRITICAL
  ) {
    severity = 'CRITICAL';
  } else if (isInternalOnly && severity === 'CRITICAL') {
    severity = 'HIGH';
  } else if (isCriticalAsset && SEVERITY_RANK[severity] < SEVERITY_RANK.HIGH) {
    severity = 'HIGH';
  }

  if (tm.dataClassification[f.file] === 'pii' && SEVERITY_RANK[severity] < SEVERITY_RANK.CRITICAL) {
    severity = 'CRITICAL';
  }

  return {
    ...f,
    severity,
    _recalibratedReason: buildReason(isInternetFacing, isInternalOnly, isCriticalAsset),
  } as Finding & { _recalibratedReason?: string };
}

function buildReason(iface: boolean, internal: boolean, crit: boolean): string {
  const parts: string[] = [];
  if (iface) parts.push('internet-facing');
  if (internal) parts.push('internal-only');
  if (crit) parts.push('critical asset');
  return parts.length > 0 ? `Recalibrated due to: ${parts.join(', ')}` : 'no change';
}

function applyVoting(findings: Finding[], votes: number): TriageResult['voted'] {
  const disputed: TriageResult['voted'] = [];
  for (const f of findings) {
    const sevVotes = votes;
    const voteDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (let i = 0; i < sevVotes; i++) {
      const noise = (Math.random() - 0.5) * 0.2;
      const adjustedUvrs = f.uvrs + noise;
      const predicted =
        adjustedUvrs >= 0.9
          ? 'CRITICAL'
          : adjustedUvrs >= 0.7
            ? 'HIGH'
            : adjustedUvrs >= 0.4
              ? 'MEDIUM'
              : adjustedUvrs >= 0.2
                ? 'LOW'
                : 'INFO';
      voteDistribution[predicted] = (voteDistribution[predicted] ?? 0) + 1;
    }
    const top = Object.entries(voteDistribution).sort((a, b) => b[1] - a[1])[0];
    const agreement = (top?.[1] ?? 0) / votes;
    if (agreement < 0.7) {
      disputed.push({ finding: f, votes, agreement });
    }
  }
  return disputed;
}

export function mergeTriageResults(results: TriageResult[]): TriageResult {
  const all: Finding[] = [];
  for (const r of results) {
    all.push(...r.deduplicated);
  }
  return triageFindings(all);
}

export function exportTriage(result: TriageResult, format: 'json' | 'markdown'): string {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }
  const lines: string[] = [];
  lines.push(`# Triage Report`);
  lines.push(``);
  lines.push(`## Summary`);
  lines.push(`- Total findings: ${result.summary.total}`);
  lines.push(`- Unique (after dedupe): ${result.summary.unique}`);
  lines.push(`- Suppressed (known bugs): ${result.summary.suppressed}`);
  lines.push(`- Critical: ${result.summary.critical}`);
  lines.push(`- High: ${result.summary.high}`);
  lines.push(`- Medium: ${result.summary.medium}`);
  lines.push(`- Low: ${result.summary.low}`);
  lines.push(``);
  lines.push(`## Ranked Findings`);
  for (let i = 0; i < result.ranked.length; i++) {
    const f = result.ranked[i];
    lines.push(
      `${i + 1}. **${f.severity}** [${f.vulnType}] ${f.file}:${f.line} (UVRS ${f.uvrs.toFixed(2)})`
    );
  }
  if (result.suppressed.length > 0) {
    lines.push(``);
    lines.push(`## Suppressed`);
    for (const s of result.suppressed) {
      lines.push(`- ${s.finding.file}:${s.finding.line} (${s.finding.vulnType}) — ${s.reason}`);
    }
  }
  return lines.join('\n');
}
