import type {
  PluginState, PluginMeta, ProbePlugin, ProbeContext, ProbeFinding,
} from '../types.js';
import type { FeatureVector } from '../../detection/ml-classifier.js';

const META: PluginMeta = {
  id: 'probe.statistical',
  phase: 'probe',
  name: 'Statistical Anomaly Probe',
  description: 'Detects code complexity anomalies via statistical analysis',
  version: '1.0.0',
  languages: [],
  defaultConfig: { threshold: 2.5 },
  tags: ['statistical', 'anomaly', 'complexity'],
};

export class StatisticalProbe implements ProbePlugin {
  readonly meta = META;
  state: PluginState = 'uninitialized';

  async init(): Promise<void> { this.state = 'ready'; }
  async destroy(): Promise<void> { this.state = 'uninitialized'; }

  async execute(ctx: ProbeContext): Promise<ProbeFinding[]> {
    const threshold = (ctx.config.threshold as number) ?? 2.5;
    const lines = ctx.code.split('\n');

    const lineCount = lines.length;
    const funcCount = (ctx.code.match(/function\s+\w+|=>\s*{|const\s+\w+\s*=\s*(\(|function)/g) || []).length;
    const loopCount = (ctx.code.match(/\b(for|while|do)\b/g) || []).length;
    const branchCount = (ctx.code.match(/\b(if|else|switch|case)\b/g) || []).length;
    const maxNesting = this.computeMaxNesting(ctx.code);

    const cyclomatic = branchCount + 1;
    const features = [cyclomatic, lineCount, funcCount, loopCount, maxNesting];
    const mean = features.reduce((a, b) => a + b, 0) / features.length;
    const std = Math.sqrt(features.reduce((s, v) => s + (v - mean) ** 2, 0) / features.length);

    const findings: ProbeFinding[] = [];
    if (std > threshold) {
      findings.push({
        source: this.meta.id,
        ruleId: 'STAT-001',
        name: 'Statistical Anomaly',
        message: `Code complexity anomaly (std=${std.toFixed(2)} > threshold=${threshold})`,
        confidence: Math.min(std / 5, 1),
        severity: 'medium',
        filePath: ctx.filePath,
        metadata: { cyclomatic, lineCount, funcCount, loopCount, maxNesting, std },
      });
    }

    return findings;
  }

  private computeMaxNesting(code: string): number {
    let maxDepth = 0;
    let depth = 0;
    for (const ch of code) {
      if (ch === '{') { depth++; maxDepth = Math.max(maxDepth, depth); }
      if (ch === '}') { depth = Math.max(0, depth - 1); }
    }
    return maxDepth;
  }
}
