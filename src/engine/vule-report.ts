/**
 * VuleReport — analysis output and export to JSON/Markdown.
 * Spec: §4.1 + §6
 */
import type { CPGNode } from './cpg/types.js';
import { RiskLevel } from './uvrs.js';

export interface NodeReport {
  nodeId: string;
  file: string;
  line: number;
  code: string;
  uvrs: number;
  level: RiskLevel;
  dominantDimension: string;
  contributions: Record<string, number>;
}

export interface VuleReport {
  version: string;
  generatedAt: string;
  nodeCount: number;
  riskDistribution: Record<RiskLevel, number>;
  topRisk: NodeReport[];
  blackHoles?: string[];
  tornNodes?: string[];
}

export function makeNodeReport(
  node: CPGNode, uvrs: number, level: RiskLevel,
  dominant: string, contributions: Record<string, number>,
): NodeReport {
  return {
    nodeId: node.id, file: node.file, line: node.line, code: node.code,
    uvrs, level, dominantDimension: dominant, contributions,
  };
}

export function reportToJSON(report: VuleReport): string {
  return JSON.stringify(report, null, 2);
}

export function reportToMarkdown(report: VuleReport): string {
  const lines: string[] = [];
  lines.push(`# VuleEngine Report (v${report.version})`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`\n## Summary`);
  lines.push(`- Nodes: ${report.nodeCount}`);
  lines.push(`- Distribution: ${JSON.stringify(report.riskDistribution)}`);
  lines.push(`\n## Top ${report.topRisk.length} Risk Nodes`);
  lines.push(`| Rank | ID | File:Line | UVRS | Level | Dominant |`);
  lines.push(`|------|----|-----------|------|-------|----------|`);
  report.topRisk.forEach((n, i) => {
    lines.push(`| ${i + 1} | ${n.nodeId} | ${n.file}:${n.line} | ${n.uvrs.toFixed(3)} | ${n.level} | ${n.dominantDimension} |`);
  });
  return lines.join('\n');
}