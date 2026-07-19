import type { LLMRouter } from '../llm/router.js';
import type { ChatMessage } from '../llm/types.js';
import type { ProgramGraph, PGNode } from '../engine/program-graph.js';
import type { TaintResult } from '../engine/taint.js';
import type { ThreatModel } from './types.js';
import { GraphQuery } from './graph-query.js';
import { getCategoriesForSourceSink } from './stride-mapper.js';

export interface ThreatToolCall {
  tool: string;
  arguments: Record<string, unknown>;
}

export interface ThreatToolResult {
  tool: string;
  output: string;
  error?: string;
}

export interface ThreatAgentConfig {
  maxIterations?: number;
  preferredProvider?: string;
  preferredModel?: string;
}

export interface ThreatAgentResult {
  findings: ThreatAgentFinding[];
  threatCoverage: string[];
  iterations: number;
  totalTokens: number;
  duration: number;
}

export interface ThreatAgentFinding {
  threatId: string;
  category: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line?: number;
  cwe?: string;
  exploitationPossible: boolean;
  remediation: string;
  confidence: number;
  evidence: string;
}

const TOOL_DEFINITIONS = [
  {
    name: 'query_graph',
    description: 'Query the program graph for nodes, edges, and relationships. Use to find specific code patterns, entry points, or data flow.',
    parameters: {
      type: 'object',
      properties: {
        node_type: { type: 'string', description: 'Filter by node type (source, sink, function, variable, etc.)' },
        direction: { type: 'string', enum: ['forward', 'backward'], description: 'Traversal direction from a starting node' },
        from_node: { type: 'string', description: 'Starting node ID for traversal' },
        depth: { type: 'number', description: 'Max traversal depth (default 5)' },
      },
    },
  },
  {
    name: 'trace_dataflow',
    description: 'Trace data flow from a source to sink, showing all intermediate nodes and sanitizers.',
    parameters: {
      type: 'object',
      properties: {
        source: { type: 'string', description: 'Source node ID or name' },
        sink: { type: 'string', description: 'Sink node ID or name (optional)' },
        max_hops: { type: 'number', description: 'Maximum hops to trace (default 10)' },
      },
      required: ['source'],
    },
  },
  {
    name: 'enumerate_attack_vectors',
    description: 'List all attack vectors (entry points → vulnerable sinks) based on the threat model.',
    parameters: {
      type: 'object',
      properties: {
        category: { type: 'string', description: 'Filter by STRIDE category (spoofing, tampering, repudiation, information_disclosure, denial_of_service, elevation_of_privilege)' },
        min_priority: { type: 'number', description: 'Minimum threat priority to include (0-100)' },
      },
    },
  },
  {
    name: 'verify_exploitation',
    description: 'Check if a specific threat is exploitable by analyzing the code path and sanitizers.',
    parameters: {
      type: 'object',
      properties: {
        threat_id: { type: 'string', description: 'Threat ID from the threat model to verify' },
        check_sanitizers: { type: 'boolean', description: 'Whether to check for effective sanitizers (default true)' },
      },
      required: ['threat_id'],
    },
  },
  {
    name: 'check_sanitizer',
    description: 'Check if a sanitizer on a data flow path is effective for a given vulnerability type.',
    parameters: {
      type: 'object',
      properties: {
        sanitizer_name: { type: 'string', description: 'Name of the sanitizer function/method' },
        vulnerability_type: { type: 'string', description: 'Vulnerability type (sql_injection, xss, command_injection, etc.)' },
      },
      required: ['sanitizer_name', 'vulnerability_type'],
    },
  },
  {
    name: 'get_threat_model',
    description: 'Get the full threat model or a specific threat by ID. Returns STRIDE analysis, attack surfaces, and risk assessment.',
    parameters: {
      type: 'object',
      properties: {
        threat_id: { type: 'string', description: 'Specific threat ID to retrieve (omit for full model summary)' },
        include_surfaces: { type: 'boolean', description: 'Include attack surface details (default false)' },
      },
    },
  },
] as const;

const MAX_ITERATIONS = 8;

export class ThreatAgent {
  private router: LLMRouter;
  private graphQuery: GraphQuery;
  private threatModel: ThreatModel;
  private graph: ProgramGraph;
  private taintResult: TaintResult;
  private config: ThreatAgentConfig;

  constructor(
    router: LLMRouter,
    graph: ProgramGraph,
    taintResult: TaintResult,
    threatModel: ThreatModel,
    config?: ThreatAgentConfig,
  ) {
    this.router = router;
    this.graph = graph;
    this.taintResult = taintResult;
    this.threatModel = threatModel;
    this.graphQuery = new GraphQuery(graph);
    this.config = config ?? {};
  }

  async analyze(): Promise<ThreatAgentResult> {
    const start = Date.now();
    const maxIter = this.config.maxIterations ?? MAX_ITERATIONS;
    let totalTokens = 0;
    let iterations = 0;

    const messages: ChatMessage[] = this.buildInitialMessages();
    const findings: ThreatAgentFinding[] = [];
    const coveredThreats = new Set<string>();

    for (let i = 0; i < maxIter; i++) {
      iterations++;
      const response = await this.router.chat(
        {
          messages,
          model: this.config.preferredModel,
          temperature: 0.1,
          maxTokens: 4096,
          jsonMode: true,
        },
        this.config.preferredProvider,
      );
      totalTokens += response.usage.totalTokens;

      const assistantContent = response.content;
      messages.push({ role: 'assistant', content: assistantContent });

      const toolCalls = this.extractToolCalls(assistantContent);
      if (toolCalls.length === 0) {
        const parsed = this.parseFindings(assistantContent);
        for (const f of parsed.findings) findings.push(f);
        for (const t of parsed.coveredThreats) coveredThreats.add(t);
        break;
      }

      const toolResults: ThreatToolResult[] = [];
      for (const call of toolCalls) {
        const result = this.executeTool(call);
        toolResults.push(result);
      }

      const toolMessage = toolResults.map(r =>
        r.error
          ? `Tool "${r.tool}" error: ${r.error}`
          : `Tool "${r.tool}" result:\n${r.output}`,
      ).join('\n\n');

      messages.push({ role: 'user', content: toolMessage });

      for (const call of toolCalls) {
        if (call.tool === 'verify_exploitation' && call.arguments.threat_id) {
          coveredThreats.add(String(call.arguments.threat_id));
        }
        if (call.tool === 'get_threat_model' && call.arguments.threat_id) {
          coveredThreats.add(String(call.arguments.threat_id));
        }
      }
    }

    if (iterations >= maxIter) {
      messages.push({
        role: 'user',
        content: 'Maximum analysis iterations reached. Please provide your final findings in JSON format now.',
      });
      const finalResponse = await this.router.chat(
        {
          messages,
          model: this.config.preferredModel,
          temperature: 0.1,
          maxTokens: 4096,
          jsonMode: true,
        },
        this.config.preferredProvider,
      );
      totalTokens += finalResponse.usage.totalTokens;
      const parsed = this.parseFindings(finalResponse.content);
      for (const f of parsed.findings) findings.push(f);
      for (const t of parsed.coveredThreats) coveredThreats.add(t);
    }

    return {
      findings,
      threatCoverage: [...coveredThreats],
      iterations,
      totalTokens,
      duration: Date.now() - start,
    };
  }

  private buildInitialMessages(): ChatMessage[] {
    const toolDescriptions = TOOL_DEFINITIONS.map(t =>
      `- ${t.name}: ${t.description}\n  Parameters: ${JSON.stringify(t.parameters)}`,
    ).join('\n\n');

    const threatSummary = this.threatModel.threats.slice(0, 10).map(t =>
      `[${t.id}] ${t.category.toUpperCase()} — ${t.title} (priority: ${t.priority}, CWE: ${t.cwe?.join(',') ?? 'N/A'})`,
    ).join('\n');

    return [
      {
        role: 'system',
        content: `You are a threat-model-driven security analyst. You have access to a program graph, taint analysis results, and an automatically generated threat model.

Your task: Systematically verify each high-priority threat using the provided tools. For each threat:
1. Get the threat details
2. Trace the data flow path
3. Check for effective sanitizers
4. Determine exploitability
5. Report findings

Available tools:
${toolDescriptions}

Respond with tool calls using this format:
TOOL_CALL: <tool_name>(<json_arguments>)

After analysis, provide final findings as JSON:
{
  "findings": [
    {
      "threatId": "...", "category": "...", "title": "...",
      "description": "...", "severity": "critical|high|medium|low",
      "line": 0, "cwe": "...", "exploitationPossible": true,
      "remediation": "...", "confidence": 0.0, "evidence": "..."
    }
  ]
}`,
      },
      {
        role: 'user',
        content: `Analyze this code's threat model. File has ${this.graph.nodeCount} nodes, ${this.graph.edgeCount} edges, ${this.threatModel.threats.length} identified threats.

Threat summary:
${threatSummary || 'No threats identified.'}

Start by getting the full threat model, then systematically verify the highest priority threats.`,
      },
    ];
  }

  private extractToolCalls(content: string): ThreatToolCall[] {
    const calls: ThreatToolCall[] = [];
    const regex = /TOOL_CALL:\s*(\w+)\(([\s\S]*?)\)(?=\s*(?:TOOL_CALL:|$))/g;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const toolName = match[1];
      const argsStr = match[2].trim();
      let args: Record<string, unknown> = {};
      try {
        args = JSON.parse(argsStr || '{}');
      } catch {
        const kvMatch = argsStr.match(/(\w+)\s*=\s*"([^"]*)"/);
        if (kvMatch) args[kvMatch[1]] = kvMatch[2];
      }
      calls.push({ tool: toolName, arguments: args });
    }

    return calls;
  }

  private executeTool(call: ThreatToolCall): ThreatToolResult {
    try {
      switch (call.tool) {
        case 'query_graph':
          return this.toolQueryGraph(call.arguments);
        case 'trace_dataflow':
          return this.toolTraceDataflow(call.arguments);
        case 'enumerate_attack_vectors':
          return this.toolEnumerateAttackVectors(call.arguments);
        case 'verify_exploitation':
          return this.toolVerifyExploitation(call.arguments);
        case 'check_sanitizer':
          return this.toolCheckSanitizer(call.arguments);
        case 'get_threat_model':
          return this.toolGetThreatModel(call.arguments);
        default:
          return { tool: call.tool, output: '', error: `Unknown tool: ${call.tool}` };
      }
    } catch (err) {
      return { tool: call.tool, output: '', error: String(err) };
    }
  }

  private toolQueryGraph(args: Record<string, unknown>): ThreatToolResult {
    const nodeType = args.node_type as string | undefined;
    const direction = args.direction as 'forward' | 'backward' | undefined;
    const fromNode = args.from_node as string | undefined;
    const depth = (args.depth as number) ?? 5;

    if (fromNode && direction) {
      const reachable = direction === 'forward'
        ? [...this.graphQuery.reachableFrom([fromNode])]
        : this.findReverseReachable(fromNode, depth);
      return {
        tool: 'query_graph',
        output: JSON.stringify({
          from: fromNode,
          direction,
          depth,
          reachableNodes: reachable.slice(0, 30),
          count: reachable.length,
        }),
      };
    }

    const entries = [...this.graph.nodes.entries()];
    const filtered = nodeType
      ? entries.filter(([_, n]) => n.type === nodeType).slice(0, 20)
          .map(([id, n]) => ({ id, type: n.type, code: n.code?.slice(0, 80), line: n.lineStart }))
      : entries.slice(0, 20)
          .map(([id, n]) => ({ id, type: n.type, code: n.code?.slice(0, 80), line: n.lineStart }));

    return {
      tool: 'query_graph',
      output: JSON.stringify({ nodes: filtered, totalNodes: this.graph.nodeCount, filter: nodeType ?? 'all' }),
    };
  }

  private toolTraceDataflow(args: Record<string, unknown>): ThreatToolResult {
    const source = args.source as string;
    const sink = args.sink as string | undefined;
    const maxHops = (args.max_hops as number) ?? 10;

    const matchingPaths = this.taintResult.paths.filter(p =>
      p.source.name.includes(source) || p.source.type.includes(source),
    );

    if (matchingPaths.length === 0) {
      return { tool: 'trace_dataflow', output: JSON.stringify({ paths: [], message: `No taint paths found from "${source}"` }) };
    }

    const paths = matchingPaths.slice(0, 5).map(p => ({
      source: { name: p.source.name, type: p.source.type, line: p.source.line },
      sink: { name: p.sink.name, type: p.sink.type, line: p.sink.line },
      confidence: p.confidence,
      sanitizers: p.sanitizers.map(s => s.name),
      flowsThrough: sink ? (p.sink.name.includes(sink) ? [p.source.name, p.sink.name] : []) : [p.source.name, p.sink.name],
    }));

    return { tool: 'trace_dataflow', output: JSON.stringify({ paths, pathCount: matchingPaths.length }) };
  }

  private toolEnumerateAttackVectors(args: Record<string, unknown>): ThreatToolResult {
    const category = args.category as string | undefined;
    const minPriority = (args.min_priority as number) ?? 0;

    let threats = this.threatModel.threats.filter(t => t.priority >= minPriority);
    if (category) {
      threats = threats.filter(t => t.category === category);
    }

    const vectors = threats.slice(0, 15).map(t => {
      const surface = this.threatModel.attackSurfaces.find(s => s.id === t.attackSurfaceId);
      return {
        threatId: t.id,
        category: t.category,
        title: t.title,
        priority: t.priority,
        entryPoint: surface?.entryPoint ?? 'unknown',
        dataFlowPaths: surface?.dataFlowPaths.length ?? 0,
        cwe: t.cwe,
      };
    });

    return { tool: 'enumerate_attack_vectors', output: JSON.stringify({ vectors, total: threats.length }) };
  }

  private toolVerifyExploitation(args: Record<string, unknown>): ThreatToolResult {
    const threatId = args.threat_id as string;
    const checkSanitizers = (args.check_sanitizers as boolean) ?? true;

    const threat = this.threatModel.threats.find(t => t.id === threatId);
    if (!threat) {
      return { tool: 'verify_exploitation', output: '', error: `Threat "${threatId}" not found` };
    }

    const surface = this.threatModel.attackSurfaces.find(s => s.id === threat.attackSurfaceId);

    const relevantPaths = this.taintResult.paths.filter(p => {
      const categories = getCategoriesForSourceSink(p.source.type, p.sink.type);
      return categories.includes(threat.category);
    });

    const pathsWithSanitizers = relevantPaths.filter(p => p.sanitizers.length > 0);
    const pathsWithoutSanitizers = relevantPaths.filter(p => p.sanitizers.length === 0);

    let sanitizerAnalysis = '';
    if (checkSanitizers && pathsWithSanitizers.length > 0) {
      sanitizerAnalysis = `\n${pathsWithSanitizers.length} paths have sanitizers: ${
        pathsWithSanitizers.flatMap(p => p.sanitizers.map(s => s.name)).filter((v, i, a) => a.indexOf(v) === i).join(', ')
      }`;
    }

    const exploitable = pathsWithoutSanitizers.length > 0 || relevantPaths.length === 0;
    const confidence = pathsWithoutSanitizers.length > 0
      ? Math.min(0.95, (pathsWithoutSanitizers.length / Math.max(relevantPaths.length, 1)) * 0.8 + 0.3)
      : 0.2;

    return {
      tool: 'verify_exploitation',
      output: JSON.stringify({
        threatId,
        title: threat.title,
        category: threat.category,
        exploitable,
        confidence: Math.round(confidence * 100) / 100,
        relevantPaths: relevantPaths.length,
        pathsWithoutSanitizers: pathsWithoutSanitizers.length,
        pathsWithSanitizers: pathsWithSanitizers.length,
        sanitizerAnalysis,
        entryPoint: surface?.entryPoint ?? 'unknown',
        recommendation: exploitable
          ? 'Exploitable path found without effective sanitization'
          : 'All paths have sanitizers — verify sanitizer effectiveness',
      }),
    };
  }

  private toolCheckSanitizer(args: Record<string, unknown>): ThreatToolResult {
    const sanitizerName = args.sanitizer_name as string;
    const vulnType = args.vulnerability_type as string;

    const knownSanitizers: Record<string, Record<string, { effective: boolean; notes: string }>> = {
      sql_injection: {
        'prepare': { effective: true, notes: 'Parameterized queries prevent SQL injection' },
        'parameterize': { effective: true, notes: 'Parameterized queries prevent SQL injection' },
        'escape_sql': { effective: true, notes: 'SQL escaping — verify completeness' },
        'escape_string': { effective: false, notes: 'Basic string escaping insufficient for SQL injection' },
        'mysql_real_escape_string': { effective: false, notes: 'Known bypasses exist; use parameterized queries' },
      },
      xss: {
        'htmlEncode': { effective: true, notes: 'HTML encoding prevents XSS in HTML context' },
        'encodeURIComponent': { effective: true, notes: 'Encoding prevents XSS in URL context' },
        'sanitize': { effective: true, notes: 'Generic sanitization — verify completeness' },
        'DOMPurify': { effective: true, notes: 'DOMPurify is effective for HTML sanitization' },
        'innerText': { effective: true, notes: 'innerText auto-escapes HTML' },
      },
      command_injection: {
        'exec': { effective: false, notes: 'exec with string concatenation is vulnerable' },
        'execFile': { effective: true, notes: 'execFile passes args as array — safe' },
        'spawn': { effective: true, notes: 'spawn with args array is safe' },
        'escape': { effective: false, notes: 'Shell escaping is error-prone and bypassable' },
      },
    };

    const categorySanitizers = knownSanitizers[vulnType];
    if (!categorySanitizers) {
      return {
        tool: 'check_sanitizer',
        output: JSON.stringify({
          sanitizer: sanitizerName,
          vulnerabilityType: vulnType,
          effective: null,
          notes: `No known effectiveness data for "${sanitizerName}" against "${vulnType}"`,
        }),
      };
    }

    const result = categorySanitizers[sanitizerName];
    return {
      tool: 'check_sanitizer',
      output: JSON.stringify({
        sanitizer: sanitizerName,
        vulnerabilityType: vulnType,
        effective: result?.effective ?? null,
        notes: result?.notes ?? 'Unknown sanitizer effectiveness',
      }),
    };
  }

  private toolGetThreatModel(args: Record<string, unknown>): ThreatToolResult {
    const threatId = args.threat_id as string | undefined;
    const includeSurfaces = (args.include_surfaces as boolean) ?? false;

    if (threatId) {
      const threat = this.threatModel.threats.find(t => t.id === threatId);
      if (!threat) {
        return { tool: 'get_threat_model', output: '', error: `Threat "${threatId}" not found` };
      }

      const surface = includeSurfaces
        ? this.threatModel.attackSurfaces.find(s => s.id === threat.attackSurfaceId)
        : undefined;

      return {
        tool: 'get_threat_model',
        output: JSON.stringify({
          threat: {
            id: threat.id,
            category: threat.category,
            title: threat.title,
            description: threat.description,
            priority: threat.priority,
            cwe: threat.cwe,
            owasp: threat.owasp,
            suggestedDetectionRules: threat.suggestedDetectionRules,
            attackSurface: surface ? {
              entryPoint: surface.entryPoint,
              riskScore: surface.riskScore,
            } : undefined,
          },
        }),
      };
    }

    return {
      tool: 'get_threat_model',
      output: JSON.stringify({
        id: this.threatModel.id,
        scope: this.threatModel.scope,
        totalThreats: this.threatModel.threats.length,
        strideCoverage: this.threatModel.strideCoverage,
        riskAssessment: this.threatModel.riskAssessment,
        boundaries: this.threatModel.trustBoundaries.length,
        surfaces: this.threatModel.attackSurfaces.length,
        threats: this.threatModel.threats.map(t => ({
          id: t.id,
          category: t.category,
          title: t.title,
          priority: t.priority,
        })),
      }),
    };
  }

  private parseFindings(content: string): { findings: ThreatAgentFinding[]; coveredThreats: string[] } {
    const findings: ThreatAgentFinding[] = [];
    const coveredThreats: string[] = [];

    try {
      const parsed = JSON.parse(content);
      const rawFindings = Array.isArray(parsed.findings) ? parsed.findings : Array.isArray(parsed) ? parsed : [];
      for (const f of rawFindings) {
        findings.push({
          threatId: String(f.threatId ?? ''),
          category: String(f.category ?? 'unknown'),
          title: String(f.title ?? ''),
          description: String(f.description ?? ''),
          severity: ['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'medium',
          line: f.line ? Number(f.line) : undefined,
          cwe: f.cwe ? String(f.cwe) : undefined,
          exploitationPossible: Boolean(f.exploitationPossible),
          remediation: String(f.remediation ?? ''),
          confidence: Math.min(1, Math.max(0, Number(f.confidence ?? 0.5))),
          evidence: String(f.evidence ?? ''),
        });
        if (f.threatId) coveredThreats.push(String(f.threatId));
      }
    } catch {
      // Non-JSON response — no findings extracted
    }

    return { findings, coveredThreats };
  }

  private findReverseReachable(nodeId: string, maxDepth: number): string[] {
    const visited = new Set<string>();
    const queue: Array<{ node: string; depth: number }> = [{ node: nodeId, depth: 0 }];
    visited.add(nodeId);

    while (queue.length > 0) {
      const item = queue.shift()!;
      if (item.depth >= maxDepth) continue;

      const inEdges = this.graphQuery.getInEdges(item.node);
      for (const edge of inEdges) {
        if (!visited.has(edge.source)) {
          visited.add(edge.source);
          queue.push({ node: edge.source, depth: item.depth + 1 });
        }
      }
    }

    return [...visited];
  }
}
