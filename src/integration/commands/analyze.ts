/**
 * vule analyze <path> — main analysis command
 */
import { readFileSync, writeFileSync } from 'fs';
import { CPGBuilder } from '../../engine/cpg/builder.js';
import { VuleEngine } from '../../engine/vule-engine.js';
import { loadConfig } from '../../engine/vule-config.js';
import { generateHTMLReport } from '../../visualization/html-report.js';
import { reportToJSON } from '../../engine/vule-report.js';

export interface AnalyzeOptions {
  config?: string;
  format?: string;
  export?: string;
  dimensions?: string;
}

export async function analyzeCommand(target: string, options: AnalyzeOptions): Promise<void> {
  const config = options.config ? loadConfig(options.config) : undefined;
  const code = readFileSync(target, 'utf-8');

  // Lightweight stub: build a minimal CPG from lines for Sprint 5 smoke testing.
  // Sprint 7 will integrate real parser via parseSource + ProgramGraphBuilder.
  const lines = code.split('\n').filter(l => l.trim());
  const nodes = new Map<string, any>();
  lines.forEach((line, i) => {
    nodes.set(`n${i}`, {
      id: `n${i}`,
      type: 'stmt',
      file: target,
      line: i + 1,
      col: 0,
      code: line,
      language: target.endsWith('.py') ? 'python' : target.endsWith('.ts') ? 'typescript' : target.endsWith('.js') ? 'javascript' : 'php',
      features: {},
    });
  });
  const edges: any[] = [];
  for (let i = 0; i < lines.length - 1; i++) {
    edges.push({ source: `n${i}`, target: `n${i + 1}`, type: 'DFG' });
  }
  const pg = { nodes, edges, nodeCount: lines.length, edgeCount: edges.length, edgeTypeCounts: {}, filePath: target, language: 'php' };
  const lang = target.endsWith('.py') ? 'python' : target.endsWith('.ts') ? 'typescript' : target.endsWith('.js') ? 'javascript' : 'php';
  const cpg = new CPGBuilder(lang as any, target).build(pg as any);

  const sinks = cpg.sinkNodes().map(n => n.id);
  const engine = new VuleEngine(cpg, sinks, [], config);
  if (options.dimensions) {
    engine.config.dimensions.enabled = options.dimensions.split(',');
  }

  const report = engine.analyze();
  if (options.format === 'html') {
    writeFileSync(options.export || 'report.html', generateHTMLReport(report));
    console.log(`HTML report written: ${options.export || 'report.html'}`);
  } else {
    const json = reportToJSON(report);
    if (options.export) {
      writeFileSync(options.export, json);
      console.log(`JSON report written: ${options.export}`);
    } else {
      console.log(json);
    }
  }
}