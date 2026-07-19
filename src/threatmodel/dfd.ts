/**
 * Data Flow Diagram (DFD) — auto-generate from analyzed source code.
 *
 * Components:
 *   - External Entity (EE)  — user, third-party API
 *   - Process (P)            — function/method/endpoint
 *   - Data Store (DS)        — database, file, cache
 *   - Data Flow             — parameter, return value, side effect
 *
 * Trust boundaries are inferred from:
 *   - HTTP entry points (public) vs internal handlers
 *   - DB calls (data tier)
 *   - Third-party HTTP calls (external)
 */

import { readFileSync } from 'fs';

export type DfdNodeType = 'EE' | 'P' | 'DS';

export interface DfdNode {
  id: string;
  type: DfdNodeType;
  label: string;
  file: string;
  line: number;
}

export interface DfdFlow {
  from: string;
  to: string;
  data: string;
  tainted: boolean;
}

export interface TrustBoundary {
  id: string;
  label: string;
  contains: string[];
}

export interface DataFlowDiagram {
  target: string;
  nodes: DfdNode[];
  flows: DfdFlow[];
  boundaries: TrustBoundary[];
  generatedAt: string;
}

const HTTP_SOURCE_PATTERNS = [
  /\$_GET\s*\[/g,
  /\$_POST\s*\[/g,
  /\$_REQUEST\s*\[/g,
  /\$_COOKIE\s*\[/g,
  /\$_SERVER\s*\[/g,
  /\$_FILES\s*\[/g,
  /\$_SESSION\s*\[/g,
];

const DB_SINK_PATTERNS = [
  /mysql_query\s*\(/g,
  /mysqli_query\s*\(/g,
  /\$pdo->query\s*\(/g,
  /\$pdo->exec\s*\(/g,
  /\$pdo->prepare\s*\(/g,
  /\$db->query\s*\(/g,
  /->query\s*\(/g,
  /->execute\s*\(/g,
  /SELECT.*FROM/gi,
  /INSERT\s+INTO/gi,
  /UPDATE\s+\w+\s+SET/gi,
  /DELETE\s+FROM/gi,
];

const EXTERNAL_HTTP_PATTERNS = [
  /file_get_contents\s*\(\s*["']?http/g,
  /curl_init\s*\(\s*["']?http/g,
  /fopen\s*\(\s*["']?http/g,
  /fetch\s*\(\s*["']http/g,
  /axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*["']http/g,
  /https?:\/\//g,
];

const SESSION_STORE_PATTERNS = [
  /\$_SESSION\s*\[/g,
  /session\.set/g,
  /setSession/g,
];

export function generateDfd(target: string, files: string[]): DataFlowDiagram {
  const nodes: DfdNode[] = [];
  const flows: DfdFlow[] = [];
  const seen = new Set<string>();
  const externalEntities = new Set<string>();
  const dataStores = new Set<string>();
  const boundaryInternal: string[] = [];
  const boundaryDataTier: string[] = [];

  for (const file of files) {
    let src: string;
    try { src = readFileSync(file, 'utf-8'); } catch { continue; }
    const lines = src.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNo = i + 1;
      if (HTTP_SOURCE_PATTERNS.some(p => p.test(line))) {
        const id = `ee:http:${file}:${lineNo}`;
        if (!seen.has(id)) {
          seen.add(id);
          externalEntities.add(id);
          nodes.push({ id, type: 'EE', label: 'HTTP user input', file, line: lineNo });
        }
      }
      if (DB_SINK_PATTERNS.some(p => p.test(line))) {
        const id = `ds:db:${file}:${lineNo}`;
        if (!seen.has(id)) {
          seen.add(id);
          dataStores.add(id);
          nodes.push({ id, type: 'DS', label: 'Database', file, line: lineNo });
          boundaryDataTier.push(id);
        }
      }
      if (EXTERNAL_HTTP_PATTERNS.some(p => p.test(line))) {
        const id = `ee:ext:${file}:${lineNo}`;
        if (!seen.has(id)) {
          seen.add(id);
          externalEntities.add(id);
          nodes.push({ id, type: 'EE', label: 'External HTTP', file, line: lineNo });
        }
      }
      const funcMatch = line.match(/function\s+(\w+)\s*\(/);
      if (funcMatch) {
        const id = `p:${file}:${lineNo}:${funcMatch[1]}`;
        if (!seen.has(id)) {
          seen.add(id);
          nodes.push({ id, type: 'P', label: funcMatch[1] + '()', file, line: lineNo });
          boundaryInternal.push(id);
        }
      }
    }
  }
  for (const ee of externalEntities) {
    for (const proc of boundaryInternal) {
      flows.push({ from: ee, to: proc, data: 'untrusted input', tainted: true });
    }
  }
  for (const proc of boundaryInternal) {
    for (const ds of dataStores) {
      flows.push({ from: proc, to: ds, data: 'SQL/tx', tainted: true });
    }
  }
  for (const proc of boundaryInternal) {
    for (const ext of [...externalEntities].filter(e => e.startsWith('ee:ext:'))) {
      flows.push({ from: proc, to: ext, data: 'HTTP request', tainted: true });
    }
  }
  const boundaries: TrustBoundary[] = [
    { id: 'b1', label: 'Public internet (untrusted)', contains: [...externalEntities] },
    { id: 'b2', label: 'Application tier', contains: boundaryInternal },
    { id: 'b3', label: 'Data tier', contains: boundaryDataTier },
  ];
  return {
    target,
    nodes,
    flows,
    boundaries,
    generatedAt: new Date().toISOString(),
  };
}

export function dfdToMermaid(dfd: DataFlowDiagram): string {
  const lines: string[] = ['```mermaid', 'flowchart LR'];
  for (const n of dfd.nodes) {
    const shape = n.type === 'EE' ? `${n.label}[/"${n.label}"/]` : n.type === 'DS' ? `[(${n.label})]` : `(${n.label})`;
    const id = n.id.replace(/[^a-zA-Z0-9]/g, '_');
    lines.push(`  ${id}${shape}`);
  }
  for (const f of dfd.flows) {
    const from = f.from.replace(/[^a-zA-Z0-9]/g, '_');
    const to = f.to.replace(/[^a-zA-Z0-9]/g, '_');
    const label = f.tainted ? `|${f.data}|` : `|"${f.data}"|`;
    lines.push(`  ${from} -->${label} ${to}`);
  }
  for (const b of dfd.boundaries) {
    lines.push(`  subgraph ${b.id}["${b.label}"]`);
    for (const id of b.contains) {
      const mid = id.replace(/[^a-zA-Z0-9]/g, '_');
      lines.push(`    ${mid}`);
    }
    lines.push('  end');
  }
  lines.push('```');
  return lines.join('\n');
}
