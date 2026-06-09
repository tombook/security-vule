/**
 * VuleEngine — unified entry point for cosmic-galaxy dimension analysis.
 * Spec: §4.1
 */
import type { CPG, CPGNode } from './cpg/types.js';
import { UVRS, RiskLevel, type UVRSComponents } from './uvrs.js';
import { DIMENSIONS, getEnabledDimensions } from './dimensions/registry.js';
import { defaultConfig, loadConfig } from './vule-config.js';
import type { VuleConfig } from './vule-config.js';
import type { VuleReport, NodeReport } from './vule-report.js';
import { makeNodeReport, reportToJSON } from './vule-report.js';
import { writeFileSync } from 'fs';

export interface ComputeResult {
  score: number;
  level: RiskLevel;
  dominant: string;
  contributions: Record<string, number>;
}

export class VuleEngine {
  readonly cpg: CPG;
  readonly sinks: string[];
  readonly securityAPIs: string[];
  readonly config: VuleConfig;
  private uvrs: UVRS;

  constructor(cpg: CPG, sinks: string[] = [], securityAPIs: string[] = [], config?: VuleConfig | string) {
    this.cpg = cpg;
    this.sinks = sinks;
    this.securityAPIs = securityAPIs;
    this.config = typeof config === 'string' ? loadConfig(config) : (config || defaultConfig());
    this.uvrs = new UVRS(this.config.weights, this.config.thresholds);
  }

  computeUVRS(nodeId: string): ComputeResult {
    const node = this.cpg.getNode(nodeId);
    if (!node) return { score: 0, level: RiskLevel.LOW, dominant: 'none', contributions: {} };
    const components = this.computeComponents(node);
    const result = this.uvrs.compute(components);
    return { score: result.score, level: result.level, dominant: result.dominantDimension.name, contributions: result.contributions };
  }

  private computeComponents(node: CPGNode): UVRSComponents {
    const components: UVRSComponents = {};
    const enabled = getEnabledDimensions(
      Object.fromEntries(this.config.dimensions.enabled.map(n => [n, true]))
    );
    for (const dim of enabled) {
      try {
        const v = dim.compute(node, this.cpg);
        components[dim.name as keyof UVRSComponents] = Math.max(0, Math.min(1, v));
      } catch {
        // skip failed dimension
      }
    }
    return components;
  }

  analyze(): VuleReport {
    const scores = new Map<string, ComputeResult>();
    for (const id of this.cpg.nodes.keys()) {
      scores.set(id, this.computeUVRS(id));
    }
    const topK = this.config.report.topK;
    const sorted = Array.from(scores.entries())
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, topK);
    const topRisk: NodeReport[] = sorted.map(([id, r]) => {
      const n = this.cpg.getNode(id)!;
      return makeNodeReport(n, r.score, r.level, r.dominant, r.contributions);
    });
    const dist = this.uvrs.getRiskDistribution(Array.from(scores.values()).map(s => s.score));
    return {
      version: '0.3.0',
      generatedAt: new Date().toISOString(),
      nodeCount: this.cpg.nodes.size,
      riskDistribution: dist,
      topRisk,
    };
  }

  topRiskNodes(k?: number): NodeReport[] {
    const report = this.analyze();
    return report.topRisk.slice(0, k ?? this.config.report.topK);
  }

  exportReport(path?: string): string {
    const report = this.analyze();
    const out = path || `${this.config.report.savePath}.${this.config.report.format}`;
    writeFileSync(out, reportToJSON(report));
    return out;
  }
}