# Sprint 1: CPG Core Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the CPG (Code Property Graph) core layer — typed node/edge model, builder from existing AST/CFG/DFG, advanced graph queries, and metrics — to serve as the shared data substrate for all 23+6 cosmic-galaxy dimension detectors.

**Architecture:** Three-layer model — (1) `cpg/types.ts` defines `CPGNode`/`CPGEdge`/`CPG` interfaces aligned with cosmic-galaxy's NetworkX DiGraph metaphor; (2) `cpg/builder.ts` converts existing `ProgramGraph` (already has AST/CFG/DFG/CALL) into CPG with five edge kinds; (3) `cpg/queries.ts` and `cpg/metrics.ts` provide BFS/DFS/shortestPath/pagerank/betweenness. Designed to extend, not replace, the existing `program-graph.ts`.

**Tech Stack:** TypeScript 5.x, Bun runtime, tree-sitter (existing dependency), vitest-style assertions via `bun test`.

**Spec reference:** `docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md` Section 2 (CPG core).

---

## File Structure

| File | Responsibility | Lines (target) |
|------|---------------|----------------|
| `src/engine/cpg/types.ts` | CPGNode, CPGEdge, CPG interface definitions | ~80 |
| `src/engine/cpg/builder.ts` | CPGBuilder: ProgramGraph → CPG conversion | ~150 |
| `src/engine/cpg/queries.ts` | shortestPath, sinkNodes, sourcesFor, callGraph, BFS/DFS | ~120 |
| `src/engine/cpg/metrics.ts` | inDegree, outDegree, pagerank, betweenness | ~150 |
| `src/engine/cpg/sinks.ts` | Language-specific dangerous-sink lookup tables | ~80 |
| `src/engine/cpg/index.ts` | Barrel exports | ~15 |
| `tests/unit/engine/cpg/types.test.ts` | Type/interface smoke tests | ~50 |
| `tests/unit/engine/cpg/builder.test.ts` | Builder tests (PHP fixture) | ~120 |
| `tests/unit/engine/cpg/queries.test.ts` | Query tests | ~150 |
| `tests/unit/engine/cpg/metrics.test.ts` | Metrics tests | ~100 |
| `theory/dimensions/gravity.md` | Dimension #1 (引力度) theory doc | ~50 |
| `config/cpg-sinks.yaml` | Sinks config per language | ~40 |

**Total**: ~11 files, ~1100 lines. Each file has one clear responsibility, fits comfortably in context.

---

## Task 1: CPG Type Definitions

**Files:**
- Create: `src/engine/cpg/types.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/engine/cpg/types.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import type { CPGNode, CPGEdge, CPG } from '../../../../src/engine/cpg/types.js';

describe('CPG types', () => {
  test('CPGNode is constructible with required fields', () => {
    const node: CPGNode = {
      id: 'n1',
      type: 'stmt',
      file: 'a.php',
      line: 1,
      col: 0,
      code: 'mysql_query($q);',
      language: 'php',
      features: { complexity: 2 },
    };
    expect(node.id).toBe('n1');
    expect(node.features.complexity).toBe(2);
  });

  test('CPGEdge supports 5 kinds', () => {
    const kinds: Array<CPGEdge['kind']> = ['data', 'control', 'call', 'def_use', 'ast_child'];
    expect(kinds).toHaveLength(5);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/unit/engine/cpg/types.test.ts`
Expected: FAIL with "Cannot find module '../../../../src/engine/cpg/types.js'"

- [ ] **Step 3: Write minimal implementation**

Create `src/engine/cpg/types.ts`:

```typescript
/**
 * Code Property Graph (CPG) — unified data substrate for cosmic-galaxy
 * dimension detectors.
 *
 * Aligns with cosmic-galaxy's NetworkX DiGraph metaphor:
 *   - CPGNode  ≈  graph vertex (code node)
 *   - CPGEdge  ≈  typed relation (DATA_FLOW, CONTROL_FLOW, CALL, ...)
 *   - CPG      ≈  DiGraph with rich query methods
 *
 * Five edge kinds (matches cosmic-galaxy's mappings.yaml):
 *   data      — taint propagation (variable → sink)
 *   control   — control flow (stmt → stmt)
 *   call      — caller → callee (function)
 *   def_use   — definition → use (variable binding)
 *   ast_child — parent → child in AST
 *
 * Spec: docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md §2.3
 */

export type CPGNodeType = 'stmt' | 'expr' | 'func' | 'var';

export type CPGLanguage = 'php' | 'python' | 'javascript' | 'typescript';

export interface CPGNode {
  id: string;
  type: CPGNodeType;
  file: string;
  line: number;
  col: number;
  code: string;
  language: CPGLanguage;
  features: Record<string, number>;
}

export type CPGEdgeKind = 'data' | 'control' | 'call' | 'def_use' | 'ast_child';

export interface CPGEdge {
  source: string;
  target: string;
  kind: CPGEdgeKind;
  weight?: number;
}

export interface CPG {
  nodes: Map<string, CPGNode>;
  edges: CPGEdge[];
  language: CPGLanguage;

  getNode(id: string): CPGNode | undefined;
  outEdges(id: string, kind?: CPGEdgeKind): CPGEdge[];
  inEdges(id: string, kind?: CPGEdgeKind): CPGEdge[];
  shortestPath(from: string, to: string): string[] | null;
  sinkNodes(): CPGNode[];
  sourcesFor(sinkId: string): CPGNode[];
  functions(): CPGNode[];
  callGraph(callee: string): string[];
  inDegree(id: string): number;
  outDegree(id: string): number;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/unit/engine/cpg/types.test.ts`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/engine/cpg/types.ts tests/unit/engine/cpg/types.test.ts
git commit -m "feat(cpg): add CPG type definitions (node/edge/graph)"
```

---

## Task 2: CPGBuilder Skeleton + Node Conversion

**Files:**
- Create: `src/engine/cpg/builder.ts`
- Create: `src/engine/cpg/sinks.ts`
- Create: `config/cpg-sinks.yaml`
- Test: `tests/unit/engine/cpg/builder.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/engine/cpg/builder.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import { CPGBuilder } from '../../../../src/engine/cpg/builder.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

function makeStubPG(): ProgramGraph {
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'call', code: 'mysql_query($q)', lineStart: 1, lineEnd: 1, properties: new Map() }],
      ['n2', { id: 'n2', type: 'variable', code: '$q', lineStart: 1, lineEnd: 1, properties: new Map() }],
    ]),
    edges: [{ source: 'n2', target: 'n1', type: 'DFG' }],
    nodeCount: 2,
    edgeCount: 1,
    edgeTypeCounts: {} as any,
    filePath: 'a.php',
    language: 'php',
  } as any;
}

describe('CPGBuilder', () => {
  test('builds CPG from ProgramGraph with 2 nodes', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php').build(pg);
    expect(cpg.nodes.size).toBe(2);
    expect(cpg.language).toBe('php');
  });

  test('classifies call expression as stmt node', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php').build(pg);
    const n1 = cpg.nodes.get('n1')!;
    expect(n1.type).toBe('stmt');
    expect(n1.code).toBe('mysql_query($q)');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/unit/engine/cpg/builder.test.ts`
Expected: FAIL with "Cannot find module '../../../../src/engine/cpg/builder.js'"

- [ ] **Step 3: Create sinks configuration**

Create `config/cpg-sinks.yaml`:

```yaml
# Dangerous function sinks per language (for cosmic-galaxy 引力场 dimension)
php:
  sql:
    - mysql_query
    - mysqli_query
    - $pdo->query
  command:
    - shell_exec
    - exec
    - system
    - passthru
    - popen
    - proc_open
  file:
    - include
    - require
    - fopen
    - file_get_contents
    - readfile
    - move_uploaded_file
  output:
    - echo
    - print

python:
  sql:
    - cursor.execute
  command:
    - os.system
    - subprocess.call
    - subprocess.run
    - eval
    - exec
  file:
    - open
  output:
    - print

javascript:
  sql: []
  command:
    - eval
    - Function
  file:
    - require
    - import
  output: []

typescript:
  sql: []
  command:
    - eval
    - Function
  file:
    - require
    - import
  output:
    - console.log
```

- [ ] **Step 4: Create sink loader**

Create `src/engine/cpg/sinks.ts`:

```typescript
/**
 * Sink function lookup tables (per language).
 * Sinks are dangerous functions that should NOT receive untrusted data.
 * Used by CPGBuilder.sinkNodes() and dimension #1 (引力场).
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { CPGLanguage } from './types.js';

export interface SinkConfig {
  [category: string]: string[];
}

export type SinksByLanguage = Record<CPGLanguage, SinkConfig>;

let _cached: SinksByLanguage | null = null;

function loadConfig(): SinksByLanguage {
  if (_cached) return _cached;
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const configPath = join(__dirname, '../../../config/cpg-sinks.yaml');
  if (!existsSync(configPath)) {
    _cached = { php: {}, python: {}, javascript: {}, typescript: {} } as SinksByLanguage;
    return _cached;
  }
  // Minimal YAML parse (only top-level language: { category: [functions] })
  const text = readFileSync(configPath, 'utf-8');
  const result: any = {};
  let currentLang: string | null = null;
  let currentCat: string | null = null;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '');
    if (!line.trim()) continue;
    const langMatch = line.match(/^(\w+):\s*$/);
    const catMatch = line.match(/^\s{2}(\w+):\s*$/);
    const itemMatch = line.match(/^\s{4}-\s*(\S+)/);
    if (langMatch) { currentLang = langMatch[1]; result[currentLang] = {}; }
    else if (catMatch && currentLang) { currentCat = catMatch[1]; result[currentLang][currentCat] = []; }
    else if (itemMatch && currentLang && currentCat) { result[currentLang][currentCat].push(itemMatch[1]); }
  }
  _cached = result as SinksByLanguage;
  return _cached;
}

export function isSinkFunction(funcName: string, language: CPGLanguage): boolean {
  const cfg = loadConfig()[language];
  if (!cfg) return false;
  for (const cat of Object.values(cfg)) {
    if (cat.includes(funcName)) return true;
  }
  return false;
}

export function getSinks(language: CPGLanguage): SinkConfig {
  return loadConfig()[language] || {};
}
```

- [ ] **Step 5: Create CPGBuilder**

Create `src/engine/cpg/builder.ts`:

```typescript
/**
 * CPGBuilder — converts existing ProgramGraph (AST+CFG+DFG+CALL+FALLS_TO)
 * into the unified CPG with five cosmic-galaxy-aligned edge kinds.
 *
 * Maps ProgramGraph edges:
 *   AST        → ast_child
 *   CFG        → control
 *   CFG_TRUE   → control (weight: 0.5)
 *   CFG_FALSE  → control (weight: 0.5)
 *   DFG        → data
 *   CALL       → call
 *   FALLS_TO   → control
 *
 * Spec: docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md §2.4
 */

import type { ProgramGraph, ProgramEdgeType, PGNode } from '../program-graph.js';
import type { CPG, CPGNode, CPGNodeType, CPGLanguage, CPGEdge, CPGEdgeKind } from './types.js';
import { isSinkFunction } from './sinks.js';

const EDGE_KIND_MAP: Record<ProgramEdgeType, CPGEdgeKind> = {
  'AST': 'ast_child',
  'CFG': 'control',
  'CFG_TRUE': 'control',
  'CFG_FALSE': 'control',
  'DFG': 'data',
  'CALL': 'call',
  'FALLS_TO': 'control',
};

function classifyNodeType(pgNode: PGNode): CPGNodeType {
  const t = pgNode.type.toLowerCase();
  if (t === 'function_definition' || t === 'method_declaration' || t.includes('function')) return 'func';
  if (t === 'variable' || t === 'identifier' || t === 'name') return 'var';
  if (t === 'call' || t === 'call_expression' || t === 'invocation') return 'stmt';
  return 'stmt';
}

export class CPGBuilder {
  constructor(private language: CPGLanguage) {}

  build(pg: ProgramGraph): CPG {
    const nodes = new Map<string, CPGNode>();
    const edges: CPGEdge[] = [];

    // Convert nodes
    for (const [id, pn] of pg.nodes) {
      const features: Record<string, number> = {};
      for (const [k, v] of pn.properties) {
        if (typeof v === 'number') features[k] = v;
      }
      const callName = extractCallName(pn.code);
      if (callName && isSinkFunction(callName, this.language)) {
        features['is_sink'] = 1;
      }
      nodes.set(id, {
        id,
        type: classifyNodeType(pn),
        file: pg.filePath || '',
        line: pn.lineStart || 0,
        col: 0,
        code: pn.code || '',
        language: this.language,
        features,
      });
    }

    // Convert edges
    for (const e of pg.edges) {
      const kind = EDGE_KIND_MAP[e.type];
      if (!kind) continue;
      edges.push({ source: e.source, target: e.target, kind });
    }

    return createCPG(nodes, edges, this.language);
  }
}

function extractCallName(code: string | undefined): string | null {
  if (!code) return null;
  const m = code.match(/^\s*([A-Za-z_][\w$]*)\s*\(/);
  return m ? m[1] : null;
}

export function createCPG(
  nodes: Map<string, CPGNode>,
  edges: CPGEdge[],
  language: CPGLanguage,
): CPG {
  const outIndex = new Map<string, CPGEdge[]>();
  const inIndex = new Map<string, CPGEdge[]>();
  for (const e of edges) {
    if (!outIndex.has(e.source)) outIndex.set(e.source, []);
    if (!inIndex.has(e.target)) inIndex.set(e.target, []);
    outIndex.get(e.source)!.push(e);
    inIndex.get(e.target)!.push(e);
  }

  const adjList = new Map<string, string[]>();
  for (const e of edges) {
    if (!adjList.has(e.source)) adjList.set(e.source, []);
    adjList.get(e.source)!.push(e.target);
  }

  function shortestPath(from: string, to: string): string[] | null {
    if (from === to) return [from];
    const visited = new Set<string>([from]);
    const queue: Array<{ node: string; path: string[] }> = [{ node: from, path: [from] }];
    while (queue.length) {
      const { node, path } = queue.shift()!;
      const neighbors = adjList.get(node) || [];
      for (const n of neighbors) {
        if (visited.has(n)) continue;
        const newPath = [...path, n];
        if (n === to) return newPath;
        visited.add(n);
        queue.push({ node: n, path: newPath });
      }
    }
    return null;
  }

  return {
    nodes,
    edges,
    language,
    getNode: (id) => nodes.get(id),
    outEdges: (id, kind) => (outIndex.get(id) || []).filter(e => !kind || e.kind === kind),
    inEdges: (id, kind) => (inIndex.get(id) || []).filter(e => !kind || e.kind === kind),
    shortestPath,
    sinkNodes: () => Array.from(nodes.values()).filter(n => n.features['is_sink'] === 1),
    sourcesFor: (sinkId) => {
      const result: CPGNode[] = [];
      const visited = new Set<string>();
      const queue = [sinkId];
      while (queue.length) {
        const cur = queue.shift()!;
        if (visited.has(cur)) continue;
        visited.add(cur);
        for (const e of inIndex.get(cur) || []) {
          if (e.kind === 'data') {
            const src = nodes.get(e.source);
            if (src) result.push(src);
            queue.push(e.source);
          }
        }
      }
      return result;
    },
    functions: () => Array.from(nodes.values()).filter(n => n.type === 'func'),
    callGraph: (callee) => {
      const callers: string[] = [];
      for (const e of edges) {
        if (e.kind === 'call' && e.target === callee) callers.push(e.source);
      }
      return callers;
    },
    inDegree: (id) => (inIndex.get(id) || []).length,
    outDegree: (id) => (outIndex.get(id) || []).length,
  };
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `bun test tests/unit/engine/cpg/builder.test.ts`
Expected: PASS (2 tests)

- [ ] **Step 7: Commit**

```bash
git add src/engine/cpg/builder.ts src/engine/cpg/sinks.ts config/cpg-sinks.yaml tests/unit/engine/cpg/builder.test.ts
git commit -m "feat(cpg): CPGBuilder with sink classification"
```

---

## Task 3: Graph Queries Module

**Files:**
- Create: `src/engine/cpg/queries.ts`
- Test: `tests/unit/engine/cpg/queries.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/engine/cpg/queries.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import { bfs, dfs, allPaths, downstreamNodes, upstreamNodes } from '../../../../src/engine/cpg/queries.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function fixture(): CPG {
  // n1 → n2 → n3 (sink)
  //  └────────────→ n3
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '$a', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'process($a)', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink($a)', language: 'php', features: { is_sink: 1 } }],
    ]),
    edges: [
      { source: 'n1', target: 'n2', kind: 'data' },
      { source: 'n2', target: 'n3', kind: 'data' },
      { source: 'n1', target: 'n3', kind: 'data' },
    ],
    language: 'php',
    getNode: () => undefined as any,
    outEdges: () => [],
    inEdges: () => [],
    shortestPath: () => null,
    sinkNodes: () => [],
    sourcesFor: () => [],
    functions: () => [],
    callGraph: () => [],
    inDegree: () => 0,
    outDegree: () => 0,
  };
}

describe('CPG queries', () => {
  test('bfs from n1 visits n1, n2, n3', () => {
    const cpg = fixture();
    const visited = bfs(cpg, 'n1');
    expect(visited.sort()).toEqual(['n1', 'n2', 'n3']);
  });

  test('downstreamNodes(n1) returns n2, n3', () => {
    const cpg = fixture();
    const ds = downstreamNodes(cpg, 'n1');
    expect(ds.sort()).toEqual(['n2', 'n3']);
  });

  test('upstreamNodes(n3) returns n1, n2', () => {
    const cpg = fixture();
    const us = upstreamNodes(cpg, 'n3');
    expect(us.sort()).toEqual(['n1', 'n2']);
  });

  test('allPaths from n1 to n3 returns both paths', () => {
    const cpg = fixture();
    const paths = allPaths(cpg, 'n1', 'n3');
    expect(paths).toHaveLength(2);
  });

  test('dfs from n1 visits all 3 nodes', () => {
    const cpg = fixture();
    const visited = dfs(cpg, 'n1');
    expect(visited.sort()).toEqual(['n1', 'n2', 'n3']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/unit/engine/cpg/queries.test.ts`
Expected: FAIL with "Cannot find module"

- [ ] **Step 3: Implement queries module**

Create `src/engine/cpg/queries.ts`:

```typescript
/**
 * CPG queries — BFS, DFS, allPaths, downstream/upstream traversal.
 * Used by dimension detectors (e.g., 引力场 uses downstreamNodes to find sinks).
 *
 * Spec: §2.3 "高级查询"
 */

import type { CPG } from './types.js';

export function bfs(cpg: CPG, start: string): string[] {
  const visited = new Set<string>([start]);
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    result.push(cur);
    for (const e of cpg.outEdges(cur)) {
      if (!visited.has(e.target)) {
        visited.add(e.target);
        queue.push(e.target);
      }
    }
  }
  return result;
}

export function dfs(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const result: string[] = [];
  function recurse(node: string): void {
    if (visited.has(node)) return;
    visited.add(node);
    result.push(node);
    for (const e of cpg.outEdges(node)) recurse(e.target);
  }
  recurse(start);
  return result;
}

export function downstreamNodes(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of cpg.outEdges(cur)) {
      if (!visited.has(e.target)) {
        visited.add(e.target);
        result.push(e.target);
        queue.push(e.target);
      }
    }
  }
  return result;
}

export function upstreamNodes(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of cpg.inEdges(cur)) {
      if (!visited.has(e.source)) {
        visited.add(e.source);
        result.push(e.source);
        queue.push(e.source);
      }
    }
  }
  return result;
}

export function allPaths(cpg: CPG, from: string, to: string, maxPaths = 100): string[][] {
  const paths: string[][] = [];
  const stack: Array<{ node: string; path: string[] }> = [{ node: from, path: [from] }];
  while (stack.length && paths.length < maxPaths) {
    const { node, path } = stack.pop()!;
    if (node === to && path.length > 1) {
      paths.push(path);
      continue;
    }
    for (const e of cpg.outEdges(node)) {
      if (!path.includes(e.target)) {
        stack.push({ node: e.target, path: [...path, e.target] });
      }
    }
  }
  return paths;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/unit/engine/cpg/queries.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/engine/cpg/queries.ts tests/unit/engine/cpg/queries.test.ts
git commit -m "feat(cpg): add BFS/DFS/downstream/upstream/allPaths queries"
```

---

## Task 4: Graph Metrics Module

**Files:**
- Create: `src/engine/cpg/metrics.ts`
- Test: `tests/unit/engine/cpg/metrics.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/engine/cpg/metrics.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import { computePagerank, computeBetweenness, computeDegreeStats } from '../../../../src/engine/cpg/metrics.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function fixture(): CPG {
  // n1 → n2 → n3
  // n1 → n3
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: '', language: 'php', features: {} }],
    ]),
    edges: [
      { source: 'n1', target: 'n2', kind: 'data' },
      { source: 'n2', target: 'n3', kind: 'data' },
      { source: 'n1', target: 'n3', kind: 'data' },
    ],
    language: 'php',
    getNode: () => undefined as any,
    outEdges: (id, k) => {
      const all = [{ s: 'n1', t: 'n2' }, { s: 'n2', t: 'n3' }, { s: 'n1', t: 'n3' }];
      return all.filter(e => e.s === id && (!k || true)).map(e => ({ source: e.s, target: e.t, kind: 'data' as const }));
    },
    inEdges: (id, k) => {
      const all = [{ s: 'n1', t: 'n2' }, { s: 'n2', t: 'n3' }, { s: 'n1', t: 'n3' }];
      return all.filter(e => e.t === id && (!k || true)).map(e => ({ source: e.s, target: e.t, kind: 'data' as const }));
    },
    shortestPath: () => null,
    sinkNodes: () => [],
    sourcesFor: () => [],
    functions: () => [],
    callGraph: () => [],
    inDegree: (id) => ['', 'n2', 'n3'].filter(x => x === id).length,
    outDegree: (id) => ['', 'n3', ''].filter(x => x === id).length,
  };
}

describe('CPG metrics', () => {
  test('pagerank sums to ~1.0', () => {
    const cpg = fixture();
    const pr = computePagerank(cpg, 50);
    const sum = Array.from(pr.values()).reduce((s, v) => s + v, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });

  test('pagerank assigns highest score to n1 (most outgoing)', () => {
    const cpg = fixture();
    const pr = computePagerank(cpg, 50);
    expect(pr.get('n1')!).toBeGreaterThan(pr.get('n3')!);
  });

  test('betweenness gives n2 the highest (middle of path)', () => {
    const cpg = fixture();
    const bc = computeBetweenness(cpg);
    expect(bc.get('n2')!).toBeGreaterThan(0);
  });

  test('degreeStats returns aggregate counts', () => {
    const cpg = fixture();
    const stats = computeDegreeStats(cpg);
    expect(stats.nodeCount).toBe(3);
    expect(stats.edgeCount).toBe(3);
    expect(stats.avgDegree).toBeCloseTo(2, 1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/unit/engine/cpg/metrics.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement metrics module**

Create `src/engine/cpg/metrics.ts`:

```typescript
/**
 * CPG metrics — pagerank, betweenness centrality, degree statistics.
 * Used by dimension detectors for graph-theoretic risk signals.
 *
 * Spec: §2.3 "图论指标"
 */

import type { CPG, CPGNode } from './types.js';

export interface DegreeStats {
  nodeCount: number;
  edgeCount: number;
  avgDegree: number;
  maxInDegree: number;
  maxOutDegree: number;
  isolatedCount: number;
}

export function computePagerank(cpg: CPG, iterations = 50, damping = 0.85): Map<string, number> {
  const ids = Array.from(cpg.nodes.keys());
  const N = ids.length;
  if (N === 0) return new Map();
  const pr = new Map<string, number>(ids.map(id => [id, 1 / N]));
  const outDegree = new Map<string, number>(ids.map(id => [id, cpg.outEdges(id).length]));
  for (let i = 0; i < iterations; i++) {
    const next = new Map<string, number>();
    let danglingSum = 0;
    for (const id of ids) {
      if (outDegree.get(id) === 0) danglingSum += pr.get(id)!;
    }
    for (const id of ids) {
      let rank = (1 - damping) / N + (damping * danglingSum) / N;
      for (const e of cpg.inEdges(id)) {
        const srcOut = outDegree.get(e.source)!;
        if (srcOut > 0) rank += damping * pr.get(e.source)! / srcOut;
      }
      next.set(id, rank);
    }
    for (const id of ids) pr.set(id, next.get(id)!);
  }
  return pr;
}

export function computeBetweenness(cpg: CPG): Map<string, number> {
  const ids = Array.from(cpg.nodes.keys());
  const bc = new Map<string, number>(ids.map(id => [id, 0]));
  for (const s of ids) {
    const stack: string[] = [];
    const pred = new Map<string, string[]>(ids.map(id => [id, []]));
    const sigma = new Map<string, number>(ids.map(id => [id, 0]));
    sigma.set(s, 1);
    const dist = new Map<string, number>(ids.map(id => [id, -1]));
    dist.set(s, 0);
    const queue: string[] = [s];
    while (queue.length) {
      const v = queue.shift()!;
      stack.push(v);
      for (const e of cpg.outEdges(v)) {
        const w = e.target;
        if (dist.get(w)! < 0) {
          dist.set(w, dist.get(v)! + 1);
          queue.push(w);
        }
        if (dist.get(w)! === dist.get(v)! + 1) {
          sigma.set(w, sigma.get(w)! + sigma.get(v)!);
          pred.get(w)!.push(v);
        }
      }
    }
    const delta = new Map<string, number>(ids.map(id => [id, 0]));
    while (stack.length) {
      const w = stack.pop()!;
      for (const v of pred.get(w)!) {
        delta.set(v, delta.get(v)! + (sigma.get(v)! / sigma.get(w)!) * (1 + delta.get(w)!));
      }
      if (w !== s) bc.set(w, bc.get(w)! + delta.get(w)!);
    }
  }
  // Normalize to [0,1] for directed graphs: divide by (N-1)(N-2)
  const norm = ids.length > 2 ? (ids.length - 1) * (ids.length - 2) : 1;
  for (const id of ids) bc.set(id, bc.get(id)! / norm);
  return bc;
}

export function computeDegreeStats(cpg: CPG): DegreeStats {
  const ids = Array.from(cpg.nodes.keys());
  let maxIn = 0, maxOut = 0, totalDeg = 0, isolated = 0;
  for (const id of ids) {
    const inD = cpg.inDegree(id);
    const outD = cpg.outDegree(id);
    maxIn = Math.max(maxIn, inD);
    maxOut = Math.max(maxOut, outD);
    totalDeg += inD + outD;
    if (inD === 0 && outD === 0) isolated++;
  }
  return {
    nodeCount: ids.length,
    edgeCount: cpg.edges.length,
    avgDegree: ids.length ? totalDeg / ids.length : 0,
    maxInDegree: maxIn,
    maxOutDegree: maxOut,
    isolatedCount: isolated,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/unit/engine/cpg/metrics.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/engine/cpg/metrics.ts tests/unit/engine/cpg/metrics.test.ts
git commit -m "feat(cpg): add pagerank, betweenness, degreeStats metrics"
```

---

## Task 5: Barrel Export + Integration Smoke Test

**Files:**
- Create: `src/engine/cpg/index.ts`
- Create: `tests/unit/engine/cpg/smoke.test.ts`
- Create: `theory/dimensions/gravity.md`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/engine/cpg/smoke.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import {
  CPGBuilder,
  createCPG,
  bfs, dfs, allPaths, downstreamNodes, upstreamNodes,
  computePagerank, computeBetweenness, computeDegreeStats,
  isSinkFunction,
} from '../../../../src/engine/cpg/index.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

describe('CPG end-to-end smoke', () => {
  test('build a real CPG from ProgramGraph and query it', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['n2', { id: 'n2', type: 'call', code: 'mysql_query($q)', lineStart: 2, lineEnd: 2, properties: new Map() }],
        ['n3', { id: 'n3', type: 'variable', code: '$q', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [
        { source: 'n1', target: 'n3', type: 'DFG' },
        { source: 'n3', target: 'n2', type: 'DFG' },
      ],
      nodeCount: 3,
      edgeCount: 2,
      edgeTypeCounts: {} as any,
      filePath: 'sqli.php',
      language: 'php',
    } as any;

    const cpg = new CPGBuilder('php').build(pg);

    expect(cpg.nodes.size).toBe(3);
    expect(cpg.edges.filter(e => e.kind === 'data')).toHaveLength(2);

    // mysql_query should be classified as sink
    const sinks = cpg.sinkNodes();
    expect(sinks).toHaveLength(1);
    expect(sinks[0].code).toContain('mysql_query');

    // sourcesFor(sink) should find $_GET["x"]
    const sources = cpg.sourcesFor('n2');
    expect(sources.some(s => s.code.includes('$_GET'))).toBe(true);

    // shortestPath from source to sink
    const path = cpg.shortestPath('n1', 'n2');
    expect(path).toEqual(['n1', 'n3', 'n2']);

    // metrics work
    const stats = computeDegreeStats(cpg);
    expect(stats.nodeCount).toBe(3);
  });

  test('isSinkFunction recognizes common sinks', () => {
    expect(isSinkFunction('mysql_query', 'php')).toBe(true);
    expect(isSinkFunction('shell_exec', 'php')).toBe(true);
    expect(isSinkFunction('safe_func', 'php')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/unit/engine/cpg/smoke.test.ts`
Expected: FAIL with "Cannot find module"

- [ ] **Step 3: Create barrel export**

Create `src/engine/cpg/index.ts`:

```typescript
/**
 * CPG (Code Property Graph) — public API.
 * Cosmic-galaxy aligned: shared data substrate for all 23+6 dimension detectors.
 *
 * Spec: §2 (CPG core)
 */

export * from './types.js';
export { CPGBuilder, createCPG } from './builder.js';
export { bfs, dfs, allPaths, downstreamNodes, upstreamNodes } from './queries.js';
export { computePagerank, computeBetweenness, computeDegreeStats, type DegreeStats } from './metrics.js';
export { isSinkFunction, getSinks, type SinkConfig, type SinksByLanguage } from './sinks.js';
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/unit/engine/cpg/smoke.test.ts`
Expected: PASS (2 tests)

- [ ] **Step 5: Write dimension #1 theory doc**

Create `theory/dimensions/gravity.md`:

```markdown
# Dimension #1: 引力场 (Gravity Field)

**Cosmic-galaxy formula**: `F_ij = Γ · (W_i · W_j) / d_ij²`

**Code mapping**:
- `Γ` (Gamma): project vulnerability density (calibrated by `GammaCalibrator`)
- `W_i`: source weight (CVSS impact + data sensitivity + exposure + privilege)
- `W_j`: sink weight (dangerousness + exploitability + reachability)
- `d_ij`: graph shortest-path distance in CPG

**security-vule implementation** (Sprint 3, P0):
- Reads CPG via `downstreamNodes(cpg, sourceNode)` to enumerate reachable sinks
- For each (source, sink) pair: compute `risk = (W_src * W_sink) / distance²`
- Returns 0-1 normalized risk contribution to UVRS

**Test fixture**: `tests/unit/dimensions/gravity.test.ts` (Sprint 3)

**References**:
- cosmic-galaxy `engine/gravity.py`
- cosmic-galaxy `theory/equations.json` dimension 3_gravity
```

- [ ] **Step 6: Commit**

```bash
git add src/engine/cpg/index.ts tests/unit/engine/cpg/smoke.test.ts theory/dimensions/gravity.md
git commit -m "feat(cpg): barrel export + smoke test + gravity theory doc"
```

---

## Task 6: Run All Tests + Type Check

**Files:**
- (no new files)

- [ ] **Step 1: Run full CPG test suite**

Run: `bun test tests/unit/engine/cpg/`
Expected: 15 tests PASS (2 + 2 + 5 + 4 + 2)

- [ ] **Step 2: Run type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head -20`
Expected: 0 errors (the pre-existing tree-sitter module error is acceptable)

- [ ] **Step 3: Final commit if any fixups**

```bash
git status --short
# If any uncommitted changes:
git add -A && git commit -m "chore(cpg): sprint 1 test/typecheck cleanups"
```

---

## Definition of Done (Sprint 1)

- [ ] All 6 tasks committed
- [ ] 15 CPG tests passing
- [ ] 0 new TypeScript errors
- [ ] `src/engine/cpg/index.ts` barrel exports `CPGBuilder`, queries, metrics, sinks
- [ ] `config/cpg-sinks.yaml` documents dangerous sinks per language
- [ ] `theory/dimensions/gravity.md` written (placeholder for Sprint 3)

**Next sprint**: Sprint 2 — `VuleEngine` unified entry that consumes CPG and runs UVRS across all enabled dimensions.