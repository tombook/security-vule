import type {
  PluginState, PluginMeta, DetectorPlugin, DetectorContext, Detection,
} from '../types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const META: PluginMeta = {
  id: 'detector.ensemble',
  phase: 'detector',
  name: 'Ensemble Detector',
  description: 'Aggregates findings from multiple probes with weighted confidence scoring',
  version: '1.0.0',
  languages: [],
  defaultConfig: {
    weights: { pattern: 0.3, statistical: 0.3, ml: 0.4 },
    minConfidence: 0.3,
  },
  tags: ['ensemble', 'aggregation'],
};

export class EnsembleDetector implements DetectorPlugin {
  readonly meta = META;
  state: PluginState = 'uninitialized';

  async init(): Promise<void> { this.state = 'ready'; }
  async destroy(): Promise<void> { this.state = 'uninitialized'; }

  async execute(ctx: DetectorContext): Promise<Detection[]> {
    const weights = (ctx.config.weights as Record<string, number>) ?? { pattern: 0.3, statistical: 0.3, ml: 0.4 };
    const minConf = (ctx.config.minConfidence as number) ?? 0.3;

    const grouped = new Map<string, { findings: typeof ctx.findings; probeSources: Set<string> }>();

    for (const f of ctx.findings) {
      const key = `${f.ruleId}:${f.line ?? 0}`;
      const existing = grouped.get(key);
      if (existing) {
        existing.findings.push(f);
        existing.probeSources.add(f.source);
      } else {
        grouped.set(key, { findings: [f], probeSources: new Set([f.source]) });
      }
    }

    const detections: Detection[] = [];

    for (const [key, group] of grouped) {
      const scores: Record<string, number> = {};
      let totalWeight = 0;
      let weightedSum = 0;
      let maxSeverity = 'info';

      for (const f of group.findings) {
        const probeName = f.source.replace('probe.', '');
        const w = weights[probeName] ?? 0.2;
        scores[probeName] = Math.max(scores[probeName] ?? 0, f.confidence);
        weightedSum += f.confidence * w;
        totalWeight += w;

        if ((SEVERITY_ORDER[f.severity] ?? 4) < (SEVERITY_ORDER[maxSeverity] ?? 4)) {
          maxSeverity = f.severity;
        }
      }

      const combined = totalWeight > 0 ? weightedSum / totalWeight : 0;
      if (combined < minConf) continue;

      const first = group.findings[0];
      detections.push({
        source: this.meta.id,
        probeSources: Array.from(group.probeSources),
        ruleId: first.ruleId,
        name: first.name,
        message: first.message,
        confidence: combined,
        severity: maxSeverity as Detection['severity'],
        location: first.filePath ? {
          file: first.filePath,
          line: first.line,
          column: first.column,
        } : undefined,
        cwe: first.cwe,
        scores,
        findings: group.findings,
      });
    }

    return detections.sort((a, b) => b.confidence - a.confidence);
  }
}
