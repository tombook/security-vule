import type {
  PluginId, PluginState, PluginMeta, ProbePlugin, ProbeContext, ProbeFinding,
} from '../types.js';
import { detectPattern } from '../../detection/patterns.js';

const META: PluginMeta = {
  id: 'probe.pattern',
  phase: 'probe',
  name: 'Pattern-Based Probe',
  description: 'Regex pattern matching for known vulnerability signatures',
  version: '1.0.0',
  languages: [],
  defaultConfig: {},
  tags: ['pattern', 'regex', 'sqli', 'xss', 'injection'],
};

export class PatternProbe implements ProbePlugin {
  readonly meta = META;
  state: PluginState = 'uninitialized';

  async init(): Promise<void> { this.state = 'ready'; }
  async destroy(): Promise<void> { this.state = 'uninitialized'; }

  async execute(ctx: ProbeContext): Promise<ProbeFinding[]> {
    const matches = detectPattern(ctx.code, ctx.filePath);
    return matches.map(m => ({
      source: this.meta.id,
      ruleId: m.rule_id,
      name: m.name,
      message: m.message,
      confidence: m.confidence,
      severity: m.severity as ProbeFinding['severity'],
      filePath: ctx.filePath,
      line: m.location.line,
      column: m.location.column,
      codeSnippet: m.code_snippet,
      cwe: m.cwe,
      metadata: { patternMatch: true },
    }));
  }
}
