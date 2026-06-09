/**
 * MCP Server for security-vule
 *
 * Implements Model Context Protocol (stdio transport) so AI agents
 * can invoke vulnerability detection as a tool.
 *
 * Tools:
 *   scan_code   — Scan code for vulnerabilities
 *   scan_file   — Scan a file path
 *   list_rules  — List all detection rules
 *   lookup_cwe  — Lookup CWE information
 *
 * Inspired by VulneraMCP's MCP server pattern.
 */

import { detectPattern, ALL_RULES, type PatternMatch } from '../detection/patterns.js';
import { locateLines, type LineLocation } from '../detection/line-locator.js';
import { VulnerabilityKnowledgeBase } from '../detection/rag-index.js';
import { generateThreatModel } from '../threat/model-generator.js';
import { buildProgramGraph } from '../engine/program-graph.js';
import { buildCFG } from '../engine/cfg.js';
import { analyzeTaint } from '../engine/taint.js';
import { parse, type Language } from '../engine/parser.js';

interface MCPRequest {
  jsonrpc: '2.0';
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface MCPResponse {
  jsonrpc: '2.0';
  id?: number | string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const TOOLS: ToolDef[] = [
  {
    name: 'scan_code',
    description: 'Scan source code for security vulnerabilities. Returns detected issues with line-level precision.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code to scan' },
        language: { type: 'string', description: 'Programming language hint (e.g. javascript, python, c)' },
        filePath: { type: 'string', description: 'Optional file path for location reporting' },
        minConfidence: { type: 'number', description: 'Minimum confidence threshold (0-1, default 0.3)' },
      },
      required: ['code'],
    },
  },
  {
    name: 'scan_file',
    description: 'Scan a file for security vulnerabilities by reading it from disk.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute file path to scan' },
        minConfidence: { type: 'number', description: 'Minimum confidence threshold (0-1, default 0.3)' },
      },
      required: ['path'],
    },
  },
  {
    name: 'list_rules',
    description: 'List all available vulnerability detection rules with their CWE mappings.',
    inputSchema: {
      type: 'object',
      properties: {
        category: { type: 'string', description: 'Filter by category: injection, auth, crypto, race, mem' },
        severity: { type: 'string', description: 'Filter by severity: critical, high, medium, low, info' },
      },
    },
  },
  {
    name: 'lookup_cwe',
    description: 'Lookup CWE vulnerability information from the knowledge base.',
    inputSchema: {
      type: 'object',
      properties: {
        cwe: { type: 'string', description: 'CWE ID (e.g. CWE-89)' },
        query: { type: 'string', description: 'Text search query' },
      },
    },
  },
  {
    name: 'threat_model',
    description: 'Generate a STRIDE threat model from source code. Identifies trust boundaries, attack surfaces, and categorized threats with risk priorities.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code to analyze' },
        language: { type: 'string', description: 'Programming language (javascript, python, c, go, java)' },
        filePath: { type: 'string', description: 'File path for scope identification' },
      },
      required: ['code'],
    },
  },
  {
    name: 'attack_surface',
    description: 'Enumerate attack surfaces from source code. Shows entry points, data flow paths crossing trust boundaries, and risk scores.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code to analyze' },
        language: { type: 'string', description: 'Programming language' },
        minRisk: { type: 'number', description: 'Minimum risk score to include (0-100, default 30)' },
      },
      required: ['code'],
    },
  },
];

const kb = new VulnerabilityKnowledgeBase();

export class MCPServer {
  private running = false;

  async start(): Promise<void> {
    this.running = true;
    const decoder = new TextDecoder();
    let buffer = '';

    process.stdin.on('data', (chunk: Buffer) => {
      buffer += decoder.decode(chunk, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        if (line.trim()) {
          this.handleMessage(line.trim());
        }
      }
    });

    process.stdin.on('end', () => {
      this.running = false;
    });
  }

  stop(): void {
    this.running = false;
  }

  private async handleMessage(raw: string): Promise<void> {
    let request: MCPRequest;
    try {
      request = JSON.parse(raw);
    } catch {
      this.sendResponse({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } });
      return;
    }

    const response = await this.route(request);
    this.sendResponse(response);
  }

  private async route(request: MCPRequest): Promise<MCPResponse> {
    const { method, params, id } = request;

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'security-vule', version: '1.0.0' },
        },
      };
    }

    if (method === 'notifications/initialized') {
      return { jsonrpc: '2.0', id };
    }

    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
    }

    if (method === 'tools/call') {
      const toolName = params?.name as string;
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      return { jsonrpc: '2.0', id, result: await this.callTool(toolName, args) };
    }

    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: string; text: string }> }> {
    switch (name) {
      case 'scan_code': return this.scanCode(args);
      case 'scan_file': return this.scanFile(args);
      case 'list_rules': return this.listRules(args);
      case 'lookup_cwe': return this.lookupCwe(args);
      case 'threat_model': return this.threatModel(args);
      case 'attack_surface': return this.attackSurface(args);
      default:
        return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
    }
  }

  private scanCode(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    const code = args.code as string;
    const filePath = args.filePath as string | undefined;
    const language = args.language as string | undefined;
    const minConf = (args.minConfidence as number) ?? 0.3;

    const matches = detectPattern(code, filePath);
    const located = locateLines(
      matches.map(m => ({
        ruleId: m.rule_id,
        name: m.name,
        severity: m.severity,
        confidence: m.confidence,
        filePath: m.location.file,
        startLine: m.location.line - 2 > 0 ? m.location.line - 2 : 1,
        endLine: m.location.line + 2,
        cwe: m.cwe,
        message: m.message,
      })),
      code,
      filePath,
    );

    const filtered = located.filter(d => d.confidence >= minConf);

    if (filtered.length === 0) {
      return { content: [{ type: 'text', text: 'No vulnerabilities detected.' }] };
    }

    const lines = code.split('\n');
    const report = filtered.map(d => {
      const loc = d.lineLocation;
      const locStr = loc ? `:${loc.startLine}-${loc.endLine}` : '';
      let snippet = '';
      if (loc) {
        const start = Math.max(0, loc.startLine - 1);
        const end = Math.min(lines.length, loc.endLine);
        snippet = '\n' + lines.slice(start, end).map((l, i) => `  ${start + i + 1}: ${l}`).join('\n');
      }
      return `[${d.severity.toUpperCase()}] ${d.name} (${d.ruleId})${locStr}\n  Confidence: ${(d.confidence * 100).toFixed(0)}%${d.cwe ? ` | CWE: ${d.cwe.join(', ')}` : ''}${snippet}`;
    });

    return { content: [{ type: 'text', text: `Found ${filtered.length} issue(s):\n\n${report.join('\n\n')}` }] };
  }

  private scanFile(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    const path = args.path as string;
    try {
      const fs = require('fs');
      const code = fs.readFileSync(path, 'utf8');
      return this.scanCode({ ...args, code, filePath: path });
    } catch (err) {
      return { content: [{ type: 'text', text: `Error reading file: ${String(err)}` }] };
    }
  }

  private listRules(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    let rules = ALL_RULES;
    const category = args.category as string | undefined;
    const severity = args.severity as string | undefined;

    if (category) {
      const prefix = category === 'injection' ? 'INJ' : category === 'auth' ? 'AUTH' : category === 'crypto' ? 'CRYPTO' : category === 'race' ? 'RACE' : 'MEM';
      rules = rules.filter(r => r.rule_id.startsWith(prefix));
    }
    if (severity) {
      rules = rules.filter(r => r.severity === severity);
    }

    const text = rules.map(r =>
      `${r.rule_id}: ${r.name} [${r.severity}] (${r.cwe?.join(', ') ?? 'N/A'}) - ${r.description}`
    ).join('\n');

    return { content: [{ type: 'text', text: `${rules.length} rules:\n${text}` }] };
  }

  private lookupCwe(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    const cwe = args.cwe as string | undefined;
    const query = args.query as string | undefined;

    if (cwe) {
      const entries = kb.lookupCwe(cwe);
      if (entries.length > 0) {
        return { content: [{ type: 'text', text: entries.map(e => `${e.id}: ${e.content}`).join('\n\n') }] };
      }
      return { content: [{ type: 'text', text: `No entry found for ${cwe}` }] };
    }

    if (query) {
      const results = kb.search(query, 5);
      return { content: [{ type: 'text', text: results.map(r => `${r.entry.id} (${(r.score * 100).toFixed(0)}%): ${r.entry.content}`).join('\n\n') }] };
    }

    return { content: [{ type: 'text', text: 'Provide either cwe or query parameter.' }] };
  }

  private threatModel(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    const code = args.code as string;
    const filePath = (args.filePath as string) ?? 'input';
    const langHint = args.language as string | undefined;

    const lang: Language = (langHint as Language) || detectLangForMcp(filePath);
    const parsed = parse(code, lang);
    const cfg = buildCFG(parsed.ast);
    const graph = buildProgramGraph(parsed.ast, cfg ?? undefined, code);
    const taint = analyzeTaint(code, filePath);
    const model = generateThreatModel(graph, taint, filePath);

    const threats = model.threats.map(t =>
      `[${t.priority}] ${t.category.toUpperCase()} — ${t.title}\n    CWE: ${t.cwe?.join(', ') ?? 'N/A'} | OWASP: ${t.owasp ?? 'N/A'}\n    Detection rules: ${t.suggestedDetectionRules.join(', ')}`,
    );

    const surfaces = model.attackSurfaces.map(s =>
      `${s.entryPoint} (risk: ${s.riskScore}) — ${s.dataFlowPaths.length} flow paths`,
    );

    const report = [
      `Threat Model: ${model.id}`,
      `Scope: ${model.scope}`,
      `Nodes: ${model.graphStats.nodeCount}, Edges: ${model.graphStats.edgeCount}`,
      `Trust Boundaries: ${model.trustBoundaries.length}`,
      `Attack Surfaces: ${model.attackSurfaces.length}`,
      `Threats: ${model.threats.length}`,
      ``,
      `STRIDE Coverage:`,
      ...Object.entries(model.strideCoverage)
        .map(([k, v]) => `  ${k}: ${v ? 'YES' : 'no'}`),
      ``,
      `Risk Assessment: ${model.riskAssessment.overall}/100`,
      ...Object.entries(model.riskAssessment.byCategory)
        .filter(([_, v]) => v > 0)
        .map(([k, v]) => `  ${k}: ${v}`),
    ];

    if (surfaces.length > 0) {
      report.push('', 'Attack Surfaces:', ...surfaces.slice(0, 10));
    }
    if (threats.length > 0) {
      report.push('', 'Threats (by priority):', ...threats.slice(0, 15));
    }

    return { content: [{ type: 'text', text: report.join('\n') }] };
  }

  private attackSurface(args: Record<string, unknown>): { content: Array<{ type: string; text: string }> } {
    const code = args.code as string;
    const langHint = args.language as string | undefined;
    const minRisk = (args.minRisk as number) ?? 30;

    const lang: Language = (langHint as Language) || detectLangForMcp('input');
    const parsed = parse(code, lang);
    const cfg = buildCFG(parsed.ast);
    const graph = buildProgramGraph(parsed.ast, cfg ?? undefined, code);
    const taint = analyzeTaint(code, 'input');
    const model = generateThreatModel(graph, taint, 'input');

    const surfaces = model.attackSurfaces
      .filter(s => s.riskScore >= minRisk)
      .sort((a, b) => b.riskScore - a.riskScore);

    if (surfaces.length === 0) {
      return { content: [{ type: 'text', text: `No attack surfaces with risk >= ${minRisk} found.` }] };
    }

    const report = surfaces.map(s => {
      const paths = s.dataFlowPaths.slice(0, 3).map(p =>
        `    ${p.source} → ${p.sink} (${p.confidence})`,
      );
      return [
        `Entry: ${s.entryPoint} (${s.entryType}) | Risk: ${s.riskScore}/100`,
        `  Boundaries crossed: ${s.boundariesCrossed.length}`,
        `  Data Flow Paths (${s.dataFlowPaths.length}):`,
        ...paths,
      ].join('\n');
    });

    return { content: [{ type: 'text', text: `${surfaces.length} attack surface(s) (risk >= ${minRisk}):\n\n${report.join('\n\n')}` }] };
  }

  private sendResponse(response: MCPResponse): void {
    process.stdout.write(JSON.stringify(response) + '\n');
  }
}

export async function runMCP(): Promise<void> {
  const server = new MCPServer();
  await server.start();
}

function detectLangForMcp(filePath: string): Language {
  const ext = filePath.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'py': return 'python';
    case 'js': case 'jsx': case 'ts': case 'tsx': case 'mjs': case 'cjs': return 'javascript';
    case 'java': return 'java';
    case 'c': case 'h': case 'cpp': case 'hpp': return 'c';
    case 'go': return 'go';
    default: return 'javascript';
  }
}
