/**
 * vule analyze <path> — main analysis command
 */
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { CPGBuilder } from '../../engine/cpg/builder.js';
import type { ProgramGraph, PGEdge, PGNode } from '../../engine/program-graph.js';
import type { CPGLanguage } from '../../engine/cpg/types.js';
import { VuleEngine } from '../../engine/vule-engine.js';
import { loadConfig } from '../../engine/vule-config.js';
import { generateHTMLReport } from '../../visualization/html-report.js';
import { reportToJSON } from '../../engine/vule-report.js';
import { IncrementalScanner } from '../../scanner/incremental.js';

export interface AnalyzeOptions {
  config?: string;
  format?: string;
  export?: string;
  dimensions?: string;
  incremental?: boolean;
  cachePath?: string;
}

export async function analyzeCommand(target: string, options: AnalyzeOptions): Promise<void> {
  if (options.incremental) {
    await incrementalScan(target, options);
    return;
  }
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

async function incrementalScan(target: string, options: AnalyzeOptions): Promise<void> {
  const isDir = existsSync(target) && require('fs').statSync(target).isDirectory();
  if (!isDir) {
    console.error(`--incremental requires a directory, got: ${target}`);
    process.exit(1);
  }
  const cachePath = options.cachePath ?? join(target, '.vule', 'cache.json');
  console.log(`\n🔍 Incremental scan: ${target}`);
  console.log(` cache: ${cachePath}`);

  const scanner = new IncrementalScanner({
    sourceDir: target,
    cachePath,
    scanFile: async (file, content) => {
      const findings: string[] = [];
      const lines = content.split('\n');
      const patterns: Array<{ regex: RegExp; type: string }> = [
        { regex: /\beval\s*\(\s*\$?_?GET/i, type: 'eval' },
        { regex: /\bmysql_query\s*\(/i, type: 'sqli' },
        { regex: /\bsystem\s*\(/i, type: 'cmdi' },
      ];
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.regex.test(lines[i] ?? '')) {
            findings.push(`${file}:${i + 1}:${p.type}`);
          }
        }
      }
      return findings;
    },
  });

  const result = await scanner.scan();

  console.log(``);
  console.log(`📊 Results:`);
  console.log(` added: ${result.added.length} files`);
  console.log(` modified: ${result.modified.length} files`);
  console.log(` unchanged: ${result.unchanged.length} files`);
  console.log(` deleted: ${result.deleted.length} files`);
  console.log(` cache hit rate: ${(result.cacheHitRate * 100).toFixed(1)}%`);
  console.log(` new findings: ${result.newFindings.length}`);
  console.log(` removed findings: ${result.removedFindings.length}`);
  console.log(` duration: ${result.durationMs}ms`);

  if (result.toScan.length > 0 && result.toScan.length <= 20) {
    console.log(``);
    console.log(`📝 Files scanned:`);
    for (const f of result.toScan) {
      const rel = f.startsWith(target) ? f.slice(target.length + 1) : f;
      const fileFindings = result.newFindings.filter((id) => id.startsWith(f));
      console.log(` ${rel} (${fileFindings.length} findings)`);
      for (const finding of fileFindings.slice(0, 5)) {
        const m = finding.match(/:\d+:(.+)$/);
        console.log(` • line ${finding.split(':')[1]}: ${m?.[1] ?? 'unknown'}`);
      }
    }
  }

  if (options.export) {
    const report = {
      tool: 'security-vule',
      mode: 'incremental',
      generatedAt: new Date().toISOString(),
      target,
      summary: {
        added: result.added.length,
        modified: result.modified.length,
        unchanged: result.unchanged.length,
        deleted: result.deleted.length,
        cacheHitRate: result.cacheHitRate,
      },
      findings: result.newFindings.map((id) => {
        const parts = id.split(':');
        return { file: parts[0], line: parseInt(parts[1] ?? '0', 10), type: parts[2] };
      }),
    };
    writeFileSync(options.export, JSON.stringify(report, null, 2));
    console.log(`\nReport written: ${options.export}`);
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
