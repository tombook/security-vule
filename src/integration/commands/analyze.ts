/**
 * vule analyze <path> — main analysis command
 */
import { readFileSync, writeFileSync } from 'fs';
import { CPGBuilder } from '../../engine/cpg/builder.js';
import type { ProgramGraph, PGEdge, PGNode } from '../../engine/program-graph.js';
import type { CPGLanguage } from '../../engine/cpg/types.js';
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
  const lines = code.split('\n').filter((l) => l.trim());
  const nodes = new Map<string, StubNode>();
  const lang = detectLanguage(target);
  lines.forEach((line, i) => {
    const id = `n${i}`;
    const node = {
      id,
      type: 'stmt',
      file: target,
      line: i + 1,
      col: 0,
      code: line,
      language: lang,
      features: new Map(),
    } as unknown as StubNode;
    nodes.set(id, node);
  });
  const edges: StubEdge[] = [];
  for (let i = 0; i < lines.length - 1; i++) {
    edges.push({ source: `n${i}`, target: `n${i + 1}`, type: 'DFG' });
  }
  const pg: StubPG = {
    nodes,
    edges,
    nodeCount: lines.length,
    edgeCount: edges.length,
    edgeTypeCounts: {} as Record<string, number>,
    filePath: target,
    language: 'php',
  };
  const cpg = new CPGBuilder(lang, target).build(pg);

  const sinks = cpg.sinkNodes().map((n) => n.id);
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

function detectLanguage(filePath: string): CPGLanguage {
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) return 'typescript';
  if (
    filePath.endsWith('.js') ||
    filePath.endsWith('.jsx') ||
    filePath.endsWith('.mjs') ||
    filePath.endsWith('.cjs')
  )
    return 'javascript';
  return 'php';
}

interface StubNode extends PGNode {
  file: string;
  line: number;
}

interface StubEdge extends PGEdge {
  type: 'DFG';
}

interface StubPG extends ProgramGraph {
  filePath: string;
  language: string;
}
