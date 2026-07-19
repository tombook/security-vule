/**
 * Multi-Model Consensus for high-severity findings.
 *
 * For CRITICAL/HIGH findings, two independent LLMs analyze the same code.
 * Only findings both models agree on are reported as confirmed.
 * Disagreements are reported as "unconfirmed by consensus" with full
 * disclosure of what each model said.
 */

import type { ChatMessage } from '../llm/types.js';
import type { LLMRouter } from '../llm/router.js';
import type { VulnerabilityContext, VulnerabilityFinding, LLMAnalysisResult } from '../detection/llm-agent.js';
import { buildAnalysisPrompt, LLMAgent } from '../detection/llm-agent.js';
import { redactSecrets, validateFinding } from './security.js';

export type ConsensusStatus = 'confirmed' | 'disputed' | 'rejected' | 'only-a' | 'only-b';

export interface ConsensusEntry {
  status: ConsensusStatus;
  findingA?: VulnerabilityFinding;
  findingB?: VulnerabilityFinding;
  reason?: string;
}

export interface ConsensusResult {
  confirmed: VulnerabilityFinding[];
  disputed: ConsensusEntry[];
  rejected: ConsensusEntry[];
  onlyA: ConsensusEntry[];
  onlyB: ConsensusEntry[];
  stats: {
    aTotal: number;
    bTotal: number;
    confirmedCount: number;
    disputedCount: number;
    matchRate: number;
  };
}

function lineDistance(a: number, b: number): number {
  return Math.abs(a - b);
}

export function findMatch(finding: VulnerabilityFinding, candidates: VulnerabilityFinding[]): VulnerabilityFinding | undefined {
  const normTypeA = finding.type.toLowerCase().replace(/[^a-z]/g, '');
  return candidates.find(c => {
    const normTypeC = c.type.toLowerCase().replace(/[^a-z]/g, '');
    if (normTypeA !== normTypeC) return false;
    return lineDistance(finding.line, c.line) <= 3;
  });
}

export async function runConsensus(
  ctx: VulnerabilityContext,
  agentA: LLMAgent,
  agentB: LLMAgent,
  opts: { minSeverity?: 'high' | 'critical' } = {}
): Promise<ConsensusResult> {
  const minSeverity = opts.minSeverity ?? 'high';
  const sevRank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const minRank = sevRank[minSeverity];

  const redaction = redactSecrets(ctx.code);
  const safeCtx: VulnerabilityContext = { ...ctx, code: redaction.text };

  const [resA, resB] = await Promise.all([agentA.analyzeVulnerabilities(safeCtx), agentB.analyzeVulnerabilities(safeCtx)]);
  const findingsA = resA.findings.filter(f => (sevRank[f.severity] ?? 0) >= minRank);
  const findingsB = resB.findings.filter(f => (sevRank[f.severity] ?? 0) >= minRank);

  const confirmed: VulnerabilityFinding[] = [];
  const matchedB = new Set<VulnerabilityFinding>();
  const onlyA: ConsensusEntry[] = [];
  const onlyB: ConsensusEntry[] = [];
  const disputed: ConsensusEntry[] = [];
  const rejected: ConsensusEntry[] = [];

  for (const fa of findingsA) {
    const matchB = findMatch(fa, findingsB);
    if (matchB) {
      matchedB.add(matchB);
      const sevDiff = Math.abs(sevRank[fa.severity] - sevRank[matchB.severity]);
      if (sevDiff > 1) {
        disputed.push({ status: 'disputed', findingA: fa, findingB: matchB, reason: `severity mismatch: A=${fa.severity} B=${matchB.severity}` });
      } else {
        const merged: VulnerabilityFinding = {
          ...fa,
          confidence: Math.min(1, (fa.confidence + matchB.confidence) / 2 + 0.1),
          description: fa.description.length > matchB.description.length ? fa.description : matchB.description,
          remediation: fa.remediation.length > matchB.remediation.length ? fa.remediation : matchB.remediation,
        };
        confirmed.push(merged);
      }
    } else {
      onlyA.push({ status: 'only-a', findingA: fa, reason: 'no matching finding from model B' });
    }
  }
  for (const fb of findingsB) {
    if (!matchedB.has(fb)) {
      onlyB.push({ status: 'only-b', findingB: fb, reason: 'no matching finding from model A' });
    }
  }

  const matchRate = findingsA.length > 0 ? confirmed.length / findingsA.length : 0;
  return {
    confirmed,
    disputed,
    rejected,
    onlyA,
    onlyB,
    stats: {
      aTotal: findingsA.length,
      bTotal: findingsB.length,
      confirmedCount: confirmed.length,
      disputedCount: disputed.length,
      matchRate,
    },
  };
}

export function formatConsensusReport(r: ConsensusResult): string {
  const lines: string[] = [];
  lines.push(`## Multi-Model Consensus Report`);
  lines.push(``);
  lines.push(`Model A findings: ${r.stats.aTotal}`);
  lines.push(`Model B findings: ${r.stats.bTotal}`);
  lines.push(`**Confirmed (both models agree)**: ${r.stats.confirmedCount}`);
  lines.push(`Disputed: ${r.stats.disputedCount}`);
  lines.push(`Only A: ${r.onlyA.length}`);
  lines.push(`Only B: ${r.onlyB.length}`);
  lines.push(`Match rate: ${(r.stats.matchRate * 100).toFixed(1)}%`);
  lines.push(``);
  if (r.confirmed.length > 0) {
    lines.push(`### Confirmed Findings`);
    for (const f of r.confirmed) {
      lines.push(`- **${f.type}** at line ${f.line} (${f.severity}, confidence ${(f.confidence * 100).toFixed(0)}%)`);
    }
  }
  if (r.disputed.length > 0) {
    lines.push(``);
    lines.push(`### Disputed (severity differs)`);
    for (const d of r.disputed) {
      lines.push(`- Line ${d.findingA?.line}: A=${d.findingA?.severity} B=${d.findingB?.severity} — ${d.reason}`);
    }
  }
  if (r.onlyA.length > 0) {
    lines.push(``);
    lines.push(`### Only Model A`);
    for (const a of r.onlyA) {
      lines.push(`- ${a.findingA?.type} at line ${a.findingA?.line} — ${a.reason}`);
    }
  }
  if (r.onlyB.length > 0) {
    lines.push(``);
    lines.push(`### Only Model B`);
    for (const b of r.onlyB) {
      lines.push(`- ${b.findingB?.type} at line ${b.findingB?.line} — ${b.reason}`);
    }
  }
  return lines.join('\n');
}
