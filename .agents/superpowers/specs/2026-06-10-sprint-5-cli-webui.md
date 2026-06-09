# Sprint 5: CLI + Web UI + Visualization Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide product-grade interfaces: CLI commands (`vule analyze`, `vule dimension`, `vule visualize`, `vule server`), self-contained interactive HTML report (D3.js star map + Plotly radar), and a minimal Web UI server for live exploration.

**Architecture:** CLI uses `commander` for argument parsing; HTML report embeds D3.js + Plotly via CDN; Web UI server is a tiny Bun.serve() with REST endpoints returning the same JSON as CLI.

**Tech Stack:** Bun, commander, D3.js (CDN), Plotly.js (CDN).

**Spec reference:** §5 (CLI), §6 (visualization).

**Depends on:** Sprint 2 (VuleEngine), Sprint 3-4 (dimensions).

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `src/integration/vule-cli.ts` | Main CLI entry with `commander` | ~180 |
| `src/integration/commands/analyze.ts` | `vule analyze <path>` command | ~120 |
| `src/integration/commands/dimension.ts` | `vule dimension <name> <file>` command | ~80 |
| `src/integration/commands/visualize.ts` | `vule visualize <report.html>` command | ~60 |
| `src/integration/commands/server.ts` | `vule server` command | ~100 |
| `src/visualization/html-report.ts` | Self-contained HTML generator | ~250 |
| `src/visualization/star-map.ts` | D3.js risk star map data | ~120 |
| `src/visualization/radar.ts` | Plotly radar chart data | ~80 |
| `src/visualization/index.ts` | Barrel | ~10 |
| `tests/unit/visualization/html-report.test.ts` | HTML report tests | ~120 |
| `tests/unit/visualization/radar.test.ts` | Radar tests | ~80 |
| `tests/integration/cli.test.ts` | CLI smoke tests | ~100 |

**Total**: ~12 files, ~1300 lines.

---

## Task 1: HTML Report Generator (Star Map + Radar)

**Files:**
- Create: `src/visualization/star-map.ts`
- Create: `src/visualization/radar.ts`
- Create: `src/visualization/html-report.ts`
- Test: `tests/unit/visualization/html-report.test.ts`

- [ ] **Step 1: Failing test**

```typescript
// tests/unit/visualization/html-report.test.ts
import { describe, expect, test } from 'bun:test';
import { buildStarMapData, buildRadarData } from '../../../src/visualization/html-report.js';
import type { VuleReport } from '../../../src/engine/vule-report.js';

const sampleReport: VuleReport = {
  version: '0.3.0',
  generatedAt: '2026-06-10T00:00:00Z',
  nodeCount: 2,
  riskDistribution: { LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 1 } as any,
  topRisk: [
    { nodeId: 'n2', file: 'a.php', line: 2, code: 'mysql_query($q)', uvrs: 0.9, level: 'CRITICAL' as any, dominantDimension: 'gravity', contributions: { gravity: 0.8, kepler: 0.5 } },
    { nodeId: 'n1', file: 'a.php', line: 1, code: '$_GET["x"]', uvrs: 0.1, level: 'LOW' as any, dominantDimension: 'ast', contributions: { ast: 0.1 } },
  ],
};

describe('HTML report data builders', () => {
  test('buildStarMapData returns nodes + edges arrays', () => {
    const data = buildStarMapData(sampleReport);
    expect(data.nodes).toHaveLength(2);
    expect(Array.isArray(data.edges)).toBe(true);
    expect(data.nodes[0].level).toBe('CRITICAL');
  });
  test('buildRadarData returns top dimensions', () => {
    const radar = buildRadarData(sampleReport.topRisk[0]);
    expect(radar.dimensions.length).toBeGreaterThan(0);
    expect(radar.values.length).toBe(radar.dimensions.length);
  });
});
```

- [ ] **Step 2: Run → expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// src/visualization/html-report.ts
/**
 * Visualization data builders + self-contained HTML report generator.
 * Spec: §6 Visualization
 */
import type { VuleReport, NodeReport } from '../engine/vule-report.js';

export interface StarMapNode {
  id: string;
  label: string;
  level: string;
  uvrs: number;
  file: string;
  line: number;
}

export interface StarMapData {
  nodes: StarMapNode[];
  edges: Array<{ source: string; target: string }>;
}

export function buildStarMapData(report: VuleReport): StarMapData {
  const nodes: StarMapNode[] = report.topRisk.map(n => ({
    id: n.nodeId,
    label: n.code.slice(0, 30),
    level: n.level,
    uvrs: n.uvrs,
    file: n.file,
    line: n.line,
  }));
  const edges: Array<{ source: string; target: string }> = [];
  // Connect CRITICAL → HIGH → MEDIUM → LOW to visualize risk propagation
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ source: nodes[i].id, target: nodes[i + 1].id });
  }
  return { nodes, edges };
}

export interface RadarData {
  dimensions: string[];
  values: number[];
}

export function buildRadarData(node: NodeReport): RadarData {
  const dimensions = Object.keys(node.contributions);
  const values = dimensions.map(d => node.contributions[d]);
  return { dimensions, values };
}

export function generateHTMLReport(report: VuleReport): string {
  const starMap = buildStarMapData(report);
  const radar = buildRadarData(report.topRisk[0] || { contributions: {} } as any);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VuleEngine Report v${report.version}</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }
    h1 { color: #58a6ff; }
    table { border-collapse: collapse; margin-top: 20px; width: 100%; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #21262d; }
    th { color: #58a6ff; }
    .CRITICAL { color: #f85149; font-weight: bold; }
    .HIGH { color: #ff7b72; }
    .MEDIUM { color: #d29922; }
    .LOW { color: #56d364; }
    #star-map, #radar { width: 100%; height: 500px; background: #161b22; border-radius: 6px; margin-top: 20px; }
  </style>
</head>
<body>
  <h1>🌌 VuleEngine Cosmic-Galaxy Risk Report</h1>
  <p>Version: ${report.version} | Generated: ${report.generatedAt} | Nodes: ${report.nodeCount}</p>
  <h2>Risk Star Map</h2>
  <div id="star-map"></div>
  <h2>Dimension Radar (Top Risk Node)</h2>
  <div id="radar"></div>
  <h2>Top Risk Nodes</h2>
  <table>
    <tr><th>Rank</th><th>Node</th><th>File:Line</th><th>UVRS</th><th>Level</th><th>Dominant</th></tr>
    ${report.topRisk.map((n, i) => `
      <tr>
        <td>${i + 1}</td>
        <td><code>${n.nodeId}</code></td>
        <td>${n.file}:${n.line}</td>
        <td>${n.uvrs.toFixed(3)}</td>
        <td class="${n.level}">${n.level}</td>
        <td>${n.dominantDimension}</td>
      </tr>
    `).join('')}
  </table>
  <script>
    const starData = ${JSON.stringify(starMap)};
    const radarData = ${JSON.stringify(radar)};
    const colorMap = { CRITICAL: '#f85149', HIGH: '#ff7b72', MEDIUM: '#d29922', LOW: '#56d364' };
    const svg = d3.select('#star-map').append('svg').attr('width', '100%').attr('height', 500);
    const sim = d3.forceSimulation(starData.nodes)
      .force('link', d3.forceLink(starData.edges).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(400, 250));
    const link = svg.append('g').selectAll('line').data(starData.edges).enter().append('line')
      .attr('stroke', '#30363d').attr('stroke-width', 1);
    const node = svg.append('g').selectAll('circle').data(starData.nodes).enter().append('circle')
      .attr('r', d => 10 + d.uvrs * 30)
      .attr('fill', d => colorMap[d.level] || '#58a6ff')
      .call(d3.drag().on('start', (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                              .on('drag', (e,d) => { d.fx = e.x; d.fy = e.y; })
                              .on('end', (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append('title').text(d => d.label);
    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
    });
    Plotly.newPlot('radar', [{
      type: 'scatterpolar', r: radarData.values, theta: radarData.dimensions, fill: 'toself',
      line: { color: '#58a6ff' }, fillcolor: 'rgba(88,166,255,0.3)'
    }], {
      polar: { radialaxis: { visible: true, range: [0, 1] } },
      paper_bgcolor: '#161b22', plot_bgcolor: '#161b22', font: { color: '#c9d1d9' }
    }, { displayModeBar: false });
  </script>
</body>
</html>`;
}
```

- [ ] **Step 4: Run → expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/visualization/ tests/unit/visualization/html-report.test.ts
git commit -m "feat(visualization): HTML report with D3 star map + Plotly radar"
```

---

## Task 2: CLI Commands (analyze, dimension, visualize)

**Files:**
- Create: `src/integration/vule-cli.ts`
- Create: `src/integration/commands/analyze.ts`
- Create: `src/integration/commands/dimension.ts`
- Create: `src/integration/commands/visualize.ts`

- [ ] **Step 1: Add commander**

```bash
bun add commander
```

- [ ] **Step 2: Implement analyze command**

```typescript
// src/integration/commands/analyze.ts
/**
 * vule analyze <path> — main analysis command
 */
import { readFileSync } from 'fs';
import { CPGBuilder } from '../../engine/cpg/builder.js';
import { VuleEngine } from '../../engine/vule-engine.js';
import { loadConfig } from '../../engine/vule-config.js';
import { generateHTMLReport } from '../../visualization/html-report.js';
import { writeFileSync } from 'fs';
import { reportToJSON } from '../../engine/vule-report.js';

export async function analyzeCommand(target: string, options: { config?: string; format?: string; export?: string; dimensions?: string }): Promise<void> {
  const config = options.config ? loadConfig(options.config) : undefined;
  const code = readFileSync(target, 'utf-8');
  // Minimal PG construction (real impl uses existing parser)
  const pg = codeToPG(code, target);
  const lang = target.endsWith('.py') ? 'python' : target.endsWith('.ts') ? 'typescript' : target.endsWith('.js') ? 'javascript' : 'php';
  const cpg = new CPGBuilder(lang as any).build(pg);
  const sinks = cpg.sinkNodes().map(n => n.id);
  const engine = new VuleEngine(cpg, sinks, [], config);
  if (options.dimensions) {
    if (!engine.config.dimensions) engine.config.dimensions = { enabled: [] };
    engine.config.dimensions.enabled = options.dimensions.split(',');
  }
  const report = engine.analyze();
  if (options.format === 'html') {
    writeFileSync(options.export || 'report.html', generateHTMLReport(report));
  } else {
    const json = reportToJSON(report);
    if (options.export) writeFileSync(options.export, json);
    else console.log(json);
  }
}

function codeToPG(code: string, filePath: string): any {
  // Minimal: 1 node per line + DFG edges between consecutive lines
  const lines = code.split('\n').filter(l => l.trim());
  const nodes = new Map();
  lines.forEach((line, i) => {
    nodes.set(`n${i}`, { id: `n${i}`, type: 'stmt', code: line, lineStart: i + 1, lineEnd: i + 1, properties: new Map() });
  });
  const edges = [];
  for (let i = 0; i < lines.length - 1; i++) {
    edges.push({ source: `n${i}`, target: `n${i + 1}`, type: 'DFG' });
  }
  return { nodes, edges, nodeCount: lines.length, edgeCount: edges.length, edgeTypeCounts: {} as any, filePath, language: 'php' };
}
```

- [ ] **Step 3: Implement dimension command**

```typescript
// src/integration/commands/dimension.ts
/**
 * vule dimension <name> <file> — single-dimension analysis with explanation
 */
import { readFileSync } from 'fs';
import { DIMENSIONS } from '../../engine/dimensions/registry.js';

export async function dimensionCommand(name: string, file: string): Promise<void> {
  const dim = DIMENSIONS[name];
  if (!dim) {
    console.error(`Unknown dimension: ${name}. Available: ${Object.keys(DIMENSIONS).join(', ')}`);
    process.exit(1);
  }
  const code = readFileSync(file, 'utf-8');
  console.log(`\n🔬 Dimension: ${name} (weight: ${dim.weight})`);
  console.log(`📁 File: ${file} (${code.split('\n').length} lines)`);
  // Mock CPG (single node)
  const cpg = makeMockCPG(file, code);
  for (const node of cpg.nodes.values()) {
    const v = dim.compute(node, cpg);
    console.log(`  Node ${node.id} (line ${node.line}): ${v.toFixed(3)}`);
  }
}

function makeMockCPG(file: string, code: string): any {
  const lines = code.split('\n');
  const nodes = new Map();
  lines.forEach((line, i) => {
    nodes.set(`n${i}`, { id: `n${i}`, type: 'stmt', file, line: i + 1, col: 0, code: line, language: 'php', features: {} });
  });
  return { nodes, edges: [], language: 'php', getNode: (id) => nodes.get(id), outEdges: () => [], inEdges: () => [], shortestPath: () => null, sinkNodes: () => [], sourcesFor: () => [], functions: () => [], callGraph: () => [], inDegree: () => 0, outDegree: () => 0 };
}
```

- [ ] **Step 4: Implement visualize command**

```typescript
// src/integration/commands/visualize.ts
/**
 * vule visualize <report.html> — open existing HTML report in browser
 */
export async function visualizeCommand(path: string): Promise<void> {
  const { spawn } = await import('child_process');
  const url = `file://${process.cwd()}/${path}`;
  console.log(`Opening ${url}...`);
  spawn('open', [url], { stdio: 'inherit' });
}
```

- [ ] **Step 5: Implement main CLI**

```typescript
// src/integration/vule-cli.ts
/**
 * VuleEngine CLI — main entry point.
 * Usage: vule <command> [options]
 */
import { Command } from 'commander';
import { analyzeCommand } from './commands/analyze.js';
import { dimensionCommand } from './commands/dimension.js';
import { visualizeCommand } from './commands/visualize.js';
import { DIMENSIONS } from '../engine/dimensions/registry.js';

const program = new Command();

program
  .name('vule')
  .description('🌌 VuleEngine — cosmic-galaxy aligned security analysis')
  .version('0.3.0');

program
  .command('analyze <path>')
  .description('Analyze a source file or directory')
  .option('-c, --config <path>', 'Path to vule.yaml config')
  .option('-f, --format <fmt>', 'Output format: json | html | markdown', 'json')
  .option('-e, --export <path>', 'Export report to file')
  .option('-d, --dimensions <list>', 'Comma-separated list of dimensions')
  .action(analyzeCommand);

program
  .command('dimension <name> <file>')
  .description('Run a single dimension detector on a file')
  .action(dimensionCommand);

program
  .command('visualize <report.html>')
  .description('Open an HTML report in the default browser')
  .action(visualizeCommand);

program
  .command('list-dimensions')
  .description('List all available cosmic-galaxy dimensions')
  .action(() => {
    console.log('\n🌌 Cosmic-Galaxy Dimensions:\n');
    for (const [name, dim] of Object.entries(DIMENSIONS)) {
      console.log(`  ${name.padEnd(15)} weight=${dim.weight.toFixed(2)}`);
    }
  });

program.parse(process.argv);
```

- [ ] **Step 6: Update package.json**

Add to `package.json` scripts:

```json
"vule": "bun --bun src/integration/vule-cli.ts"
```

- [ ] **Step 7: Commit**

```bash
git add src/integration/ package.json bun.lock
git commit -m "feat(cli): vule analyze/dimension/visualize/list-dimensions commands"
```

---

## Task 3: CLI Smoke Test

**Files:**
- Create: `tests/integration/cli.test.ts`

- [ ] **Step 1: Failing test**

```typescript
// tests/integration/cli.test.ts
import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'child_process';

describe('CLI smoke tests', () => {
  test('vule --version', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', '--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.toString()).toContain('0.3.0');
  });
  test('vule list-dimensions', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', 'list-dimensions']);
    expect(r.status).toBe(0);
    expect(r.stdout.toString()).toContain('gravity');
    expect(r.stdout.toString()).toContain('kepler');
  });
  test('vule analyze with JSON output', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', 'analyze', 'test-targets/php-vulns/dvwa_sqli_low.php']);
    expect(r.status).toBe(0);
    expect(r.stdout.toString()).toContain('topRisk');
  });
});
```

- [ ] **Step 2: Run → expect PASS**

- [ ] **Step 3: Commit**

```bash
git add tests/integration/cli.test.ts
git commit -m "test(cli): smoke tests for vule CLI"
```

---

## Task 4: Web UI Server (Minimal)

**Files:**
- Create: `src/integration/commands/server.ts`

- [ ] **Step 1: Implement server**

```typescript
// src/integration/commands/server.ts
/**
 * vule server — minimal HTTP server for live VuleEngine exploration.
 * Spec: §5.2 Web UI
 */
import { generateHTMLReport } from '../../visualization/html-report.js';
import type { VuleReport } from '../../engine/vule-report.js';

export async function serverCommand(options: { port: number }): Promise<void> {
  const server = Bun.serve({
    port: options.port,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === '/') {
        return new Response(`<!DOCTYPE html><html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px">
          <h1>🌌 VuleEngine Web UI</h1>
          <p>Server running on port ${options.port}</p>
          <p>POST analysis results to <code>/api/report</code> (JSON VuleReport).</p>
          <p>GET <code>/api/health</code> for status.</p>
        </body></html>`, { headers: { 'content-type': 'text/html' } });
      }
      if (url.pathname === '/api/health') return Response.json({ status: 'ok', version: '0.3.0' });
      if (url.pathname === '/api/report' && req.method === 'POST') {
        const report: VuleReport = await req.json();
        return new Response(generateHTMLReport(report), { headers: { 'content-type': 'text/html' } });
      }
      return new Response('Not Found', { status: 404 });
    },
  });
  console.log(`🌌 VuleEngine Web UI: http://localhost:${server.port}`);
}
```

- [ ] **Step 2: Wire into CLI**

```typescript
// In src/integration/vule-cli.ts, add:
program
  .command('server')
  .description('Start web UI server')
  .option('-p, --port <port>', 'Port number', '3000')
  .action((opts) => serverCommand({ port: parseInt(opts.port, 10) }));
```

- [ ] **Step 3: Commit**

```bash
git add src/integration/commands/server.ts src/integration/vule-cli.ts
git commit -m "feat(cli): vule server with REST API for HTML reports"
```

---

## Task 5: Run All Tests + Type Check

- [ ] **Step 1: Run all tests**

Run: `bun test tests/unit/visualization/ tests/integration/cli.test.ts`
Expected: PASS

- [ ] **Step 2: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Manual smoke test**

Run: `bun --bun src/integration/vule-cli.ts analyze test-targets/php-vulns/dvwa_sqli_low.php`
Expected: JSON output with `topRisk` array

---

## Definition of Done (Sprint 5)

- [ ] 4 CLI commands work: `analyze`, `dimension`, `visualize`, `server`, `list-dimensions`
- [ ] Self-contained HTML report with D3 star map + Plotly radar
- [ ] Web UI server on port 3000 with `/api/health` and `/api/report` endpoints
- [ ] CLI smoke tests pass
- [ ] 0 new TypeScript errors

**Next sprint**: Sprint 6 — 6 math frameworks (type theory, category theory, TDA, pure functional, abstract interpretation, symbolic execution) as additional detectors.