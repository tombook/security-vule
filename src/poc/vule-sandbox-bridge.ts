/**
 * VuleSandboxBridge — connects PocSandbox runtime verification to VuleEngine UVRS scoring.
 *
 * Architecture:
 *   PocResult → PocVerification → UVRS `verify` dimension → VuleEngine
 *
 * The bridge:
 * 1. Runs PoCs against live targets via PocSandbox
 * 2. Aggregates results into per-vulnerability verification records
 * 3. Maps verification confidence to UVRS `verify` component (0-1)
 * 4. Feeds into VuleEngine's computeUVRS() pipeline
 *
 * Spec: §4.1 UVRS, §5.3 Runtime Verification
 */

import {
  PocSandbox,
  type PocResult,
  type PocVerificationStatus,
  type PocTarget,
  type PocExpectation,
  TARGETS,
} from './sandbox.js';
import {
  type PayloadEntry,
  type InjectionType,
  PAYLOAD_DATABASE,
  getPayloadsByTarget,
  getPayloadsByType,
} from './payload-database.js';
import { UVRS, RiskLevel, type UVRSComponents, type UVRSResult } from '../engine/uvrs.js';

export interface VulnerabilityVerification {
  id: string;
  vulnType: InjectionType;
  target: string;
  results: PocResult[];
  verified: boolean;
  confidence: number;
  attempts: number;
  successes: number;
  bestResult: PocResult | null;
}

export interface BridgeReport {
  generatedAt: string;
  totalVulns: number;
  verifiedVulns: number;
  verificationRate: number;
  verifications: VulnerabilityVerification[];
  uvrsResults: Map<string, UVRSResult>;
  uvrsDistribution: Record<RiskLevel, number>;
}

export type VerificationMapper = (v: VulnerabilityVerification) => number;

export const DEFAULT_VERIFY_MAPPER: VerificationMapper = (v) => {
  if (!v.verified) return 0;
  const baseConfidence = v.confidence;
  const multiHitBonus = v.successes > 1 ? Math.min(0.15, v.successes * 0.05) : 0;
  const crossTargetBonus =
    new Set(
      v.results.map((r) => {
        const match = r.id.match(/^(dvwa|bwapp|sqlilabs|pikachu)/);
        return match ? match[1] : 'unknown';
      })
    ).size > 1
      ? 0.1
      : 0;
  return Math.min(1, baseConfidence + multiHitBonus + crossTargetBonus);
};

const STATUS_WEIGHTS: Record<PocVerificationStatus, number> = {
  verified: 1.0,
  time_based_verified: 0.95,
  rejected: 0,
  table_empty: 0.1,
  no_data_returned: 0.1,
  auth_failed: 0,
  rate_limited: 0,
  payload_filtered: 0.3,
  endpoint_changed: 0,
  timeout: 0,
  connection_error: 0,
  unsupported_target: 0,
};

export class VuleSandboxBridge {
  private readonly sandboxes: Map<string, PocSandbox>;
  private readonly uvrs: UVRS;
  private readonly verifyMapper: VerificationMapper;
  private readonly verifications: Map<string, VulnerabilityVerification> = new Map();

  constructor(options?: {
    targets?: PocTarget['name'][];
    uvrsWeights?: Partial<import('../engine/uvrs.js').UVRSWeights>;
    verifyMapper?: VerificationMapper;
  }) {
    const targets =
      options?.targets ?? (Object.keys(TARGETS) as PocTarget['name'][]).filter((t) => t !== 'mock');
    this.sandboxes = new Map();
    for (const t of targets) {
      this.sandboxes.set(t, new PocSandbox({ target: t, isolation: 'process', retries: 1 }));
    }
    this.uvrs = new UVRS(options?.uvrsWeights);
    this.verifyMapper = options?.verifyMapper ?? DEFAULT_VERIFY_MAPPER;
  }

  async verifyPayload(payload: PayloadEntry): Promise<VulnerabilityVerification> {
    const sandbox = this.sandboxes.get(payload.target);
    if (!sandbox) {
      return {
        id: payload.id,
        vulnType: payload.injectionType,
        target: payload.target,
        results: [],
        verified: false,
        confidence: 0,
        attempts: 1,
        successes: 0,
        bestResult: null,
      };
    }

    const expected = payload.expected as PocExpectation & {
      matches?: RegExp | string;
    };
    if (typeof expected.matches === 'string') {
      const m = expected.matches.trim();
      const match = m.match(/^\/(.+)\/([gimsuy]*)$/);
      try {
        expected.matches = match ? new RegExp(match[1], match[2]) : new RegExp(m);
      } catch {
        expected.matches = new RegExp(m.replace(/^\/|\/[gimsuy]*$/g, ''));
      }
    }

    const req = {
      id: payload.id,
      method: payload.method,
      url: payload.url,
      body: payload.body,
      headers: payload.headers,
      cookies: payload.cookies,
      noFollowRedirect: payload.noFollowRedirect,
      expected,
      timeoutMs: 10000,
    };

    const result = await sandbox.execute(req);
    const existing = this.verifications.get(payload.id);

    const results = existing ? [...existing.results, result] : [result];
    const successes = results.filter((r) => r.success).length;
    const confidence =
      results.reduce((sum, r) => sum + STATUS_WEIGHTS[r.status], 0) / results.length;

    const verification: VulnerabilityVerification = {
      id: payload.id,
      vulnType: payload.injectionType,
      target: payload.target,
      results,
      verified: successes > 0,
      confidence,
      attempts: results.length,
      successes,
      bestResult: successes > 0 ? (results.find((r) => r.success) ?? null) : null,
    };

    this.verifications.set(payload.id, verification);
    return verification;
  }

  async verifyTarget(targetName: PocTarget['name']): Promise<VulnerabilityVerification[]> {
    const payloads = getPayloadsByTarget(targetName);
    const results: VulnerabilityVerification[] = [];
    for (const p of payloads) {
      results.push(await this.verifyPayload(p));
    }
    return results;
  }

  async verifyByType(type: InjectionType): Promise<VulnerabilityVerification[]> {
    const payloads = getPayloadsByType(type);
    const results: VulnerabilityVerification[] = [];
    for (const p of payloads) {
      results.push(await this.verifyPayload(p));
    }
    return results;
  }

  async verifyAll(): Promise<VulnerabilityVerification[]> {
    const results: VulnerabilityVerification[] = [];
    const targets = Array.from(this.sandboxes.keys());
    for (const p of PAYLOAD_DATABASE) {
      if (targets.length > 0 && !targets.includes(p.target)) continue;
      results.push(await this.verifyPayload(p));
    }
    return results;
  }

  computeUVRSForVuln(vulnId: string): UVRSResult | null {
    const v = this.verifications.get(vulnId);
    if (!v) return null;
    return this.mapToUVRS(v);
  }

  private mapToUVRS(v: VulnerabilityVerification): UVRSResult {
    const components: UVRSComponents = {
      verify: this.verifyMapper(v),
      consensus: v.successes > 1 ? Math.min(1, v.successes / v.attempts) : 0,
    };
    return this.uvrs.compute(components);
  }

  generateReport(verifications?: VulnerabilityVerification[]): BridgeReport {
    const all = verifications ?? Array.from(this.verifications.values());
    const verified = all.filter((v) => v.verified);
    const uvrsResults = new Map<string, UVRSResult>();
    const scores: number[] = [];

    for (const v of all) {
      const result = this.mapToUVRS(v);
      uvrsResults.set(v.id, result);
      scores.push(result.score);
    }

    const distribution = this.uvrs.getRiskDistribution(scores);

    return {
      generatedAt: new Date().toISOString(),
      totalVulns: all.length,
      verifiedVulns: verified.length,
      verificationRate: all.length > 0 ? verified.length / all.length : 0,
      verifications: all,
      uvrsResults,
      uvrsDistribution: distribution,
    };
  }

  getVerification(vulnId: string): VulnerabilityVerification | undefined {
    return this.verifications.get(vulnId);
  }

  getVerifiedCount(): number {
    return Array.from(this.verifications.values()).filter((v) => v.verified).length;
  }

  getStatsByType(): Record<InjectionType, { total: number; verified: number; rate: number }> {
    const stats: Record<string, { total: number; verified: number; rate: number }> = {};
    for (const v of this.verifications.values()) {
      if (!stats[v.vulnType]) stats[v.vulnType] = { total: 0, verified: 0, rate: 0 };
      stats[v.vulnType].total++;
      if (v.verified) stats[v.vulnType].verified++;
    }
    for (const s of Object.values(stats)) {
      s.rate = s.total > 0 ? s.verified / s.total : 0;
    }
    return stats as Record<InjectionType, { total: number; verified: number; rate: number }>;
  }
}

export function reportToMarkdown(report: BridgeReport): string {
  const lines: string[] = [];
  lines.push('# VuleSandboxBridge Report');
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(`- Total vulnerabilities: ${report.totalVulns}`);
  lines.push(
    `- Verified: ${report.verifiedVulns}/${report.totalVulns} (${(report.verificationRate * 100).toFixed(1)}%)`
  );
  lines.push(`- UVRS Distribution: ${JSON.stringify(report.uvrsDistribution)}`);
  lines.push('');
  lines.push('## Results by Vulnerability Type');
  lines.push('| Type | Total | Verified | Rate |');
  lines.push('|------|-------|----------|------|');

  const typeMap: Record<string, { total: number; verified: number }> = {};
  for (const v of report.verifications) {
    if (!typeMap[v.vulnType]) typeMap[v.vulnType] = { total: 0, verified: 0 };
    typeMap[v.vulnType].total++;
    if (v.verified) typeMap[v.vulnType].verified++;
  }
  for (const [type, s] of Object.entries(typeMap).sort((a, b) => b[1].total - a[1].total)) {
    const rate = s.total > 0 ? ((s.verified / s.total) * 100).toFixed(0) : '0';
    lines.push(`| ${type} | ${s.total} | ${s.verified} | ${rate}% |`);
  }

  lines.push('');
  lines.push('## Verified PoCs');
  lines.push('| ID | Target | Type | Confidence | UVRS Score | Risk Level |');
  lines.push('|----|--------|------|------------|------------|------------|');
  for (const v of report.verifications.filter((v) => v.verified)) {
    const uvrs = report.uvrsResults.get(v.id);
    lines.push(
      `| ${v.id} | ${v.target} | ${v.vulnType} | ${v.confidence.toFixed(2)} | ${uvrs?.score.toFixed(3) ?? 'N/A'} | ${uvrs?.level ?? 'N/A'} |`
    );
  }

  return lines.join('\n');
}
