import { describe, test, expect, mock } from 'bun:test';
import { ThreatAgent } from '../../../src/threat/threat-agent.js';
import type { LLMRouter } from '../../../src/llm/router.js';
import type { ChatRequest, ChatResponse } from '../../../src/llm/types.js';
import type { ProgramGraph, PGNode, PGEdge } from '../../../src/engine/program-graph.js';
import type { TaintResult, TaintPath, TaintSource, TaintSink, Sanitizer } from '../../../src/engine/taint.js';
import type { ThreatModel, Threat, AttackSurface, TrustBoundary } from '../../../src/threat/types.js';

// ─── 测试用 fixture 工厂 ────────────────────────────────────────────────

function mkNode(id: string, type = 'function', code = 'x = 1'): PGNode {
  return {
    id,
    type,
    code,
    lineStart: 1,
    lineEnd: 1,
    properties: new Map(),
  };
}

function mkGraph(nodes: PGNode[], edges: PGEdge[] = []): ProgramGraph {
  const map = new Map<string, PGNode>();
  for (const n of nodes) map.set(n.id, n);
  return {
    nodes: map,
    edges,
    nodeCount: map.size,
    edgeCount: edges.length,
    edgeTypeCounts: { AST: 0, CFG: 0, CFG_TRUE: 0, CFG_FALSE: 0, DFG: 0, CALL: 0, FALLS_TO: 0 },
  };
}

function mkSource(name: string, type: TaintSource['type'] = 'user_input', line = 1): TaintSource {
  return { id: `s_${name}`, type, name, line, scope: 'main' };
}

function mkSink(name: string, type: TaintSink['type'] = 'sql', line = 10): TaintSink {
  return { id: `k_${name}`, type, name, line, scope: 'main' };
}

function mkSanitizer(name: string): Sanitizer {
  return { id: `san_${name}`, type: 'encoding', name, line: 5, scope: 'main' };
}

function mkPath(source: TaintSource, sink: TaintSink, sanitizers: Sanitizer[] = []): TaintPath {
  return {
    source,
    sink,
    path: [source.id, sink.id],
    confidence: 0.8,
    sanitizers,
  };
}

function mkTaint(paths: TaintPath[] = []): TaintResult {
  return {
    isTainted: paths.length > 0,
    sources: paths.map(p => p.source),
    sinks: paths.map(p => p.sink),
    paths,
    confidence: 0.8,
  };
}

function mkAttackSurface(id: string, threat: Threat): AttackSurface {
  return {
    id,
    name: `surface_${id}`,
    description: 'test surface',
    entryPoint: threat.attackSurfaceId === id ? 'ep_1' : 'ep_0',
    entryType: 'http_handler',
    reachableSinks: [],
    boundariesCrossed: [],
    dataFlowPaths: [],
    riskScore: 50,
    location: { file: 'test.py' },
  };
}

function mkThreat(id: string, category: Threat['category'], attackSurfaceId = 'as_1', priority = 50): Threat {
  return {
    id,
    category,
    title: `Threat ${id}`,
    description: `Description for ${id}`,
    attackSurfaceId,
    cwe: ['CWE-89'],
    suggestedDetectionRules: ['rule_1'],
    priority,
    scanned: false,
    findingIds: [],
  };
}

function mkThreatModel(threats: Threat[] = []): ThreatModel {
  const attackSurfaces: AttackSurface[] = [];
  const seen = new Set<string>();
  for (const t of threats) {
    if (!seen.has(t.attackSurfaceId)) {
      seen.add(t.attackSurfaceId);
      attackSurfaces.push(mkAttackSurface(t.attackSurfaceId, t));
    }
  }
  return {
    id: 'tm_1',
    scope: 'test.py',
    timestamp: Date.now(),
    method: 'auto_graph',
    trustBoundaries: [] as TrustBoundary[],
    attackSurfaces,
    threats,
    strideCoverage: {
      spoofing: false,
      tampering: threats.some(t => t.category === 'tampering'),
      repudiation: false,
      information_disclosure: threats.some(t => t.category === 'information_disclosure'),
      denial_of_service: false,
      elevation_of_privilege: false,
    },
    riskAssessment: { overall: 50, byCategory: {} as never, criticalPaths: 0 },
  };
}

// mock router:每次 chat() 调用返回队列中的下一条响应
function mkRouter(responses: string[]): LLMRouter {
  let i = 0;
  const chat = mock(async (_req: ChatRequest): Promise<ChatResponse> => {
    const content = responses[Math.min(i, responses.length - 1)];
    i++;
    return {
      id: `resp_${i}`,
      content,
      model: 'test-model',
      provider: 'openai',
      usage: { promptTokens: 10, completionTokens: 20, totalTokens: 30 },
      finishReason: 'stop',
      created: Date.now(),
    };
  });
  return { chat } as unknown as LLMRouter;
}

const sampleFindingsJson = JSON.stringify({
  findings: [
    {
      threatId: 'T-1',
      category: 'tampering',
      title: 'SQL injection in login',
      description: 'unsanitized input',
      severity: 'high',
      line: 42,
      cwe: 'CWE-89',
      exploitationPossible: true,
      remediation: 'use parameterized queries',
      confidence: 0.9,
      evidence: 'see line 42',
    },
  ],
});

// ─── happy path ─────────────────────────────────────────────────────────

describe('threat-agent: happy path - direct JSON findings', () => {
  test('analyze() parses final JSON findings and reports iterations/tokens', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([mkPath(mkSource('req.body', 'user_input'), mkSink('db.query', 'sql'))]);
    const threat = mkThreat('T-1', 'tampering');
    const model = mkThreatModel([threat]);
    const router = mkRouter([sampleFindingsJson]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].threatId).toBe('T-1');
    expect(result.findings[0].severity).toBe('high');
    expect(result.iterations).toBe(1);
    expect(result.totalTokens).toBe(30);
    expect(result.threatCoverage).toEqual(['T-1']);
    expect(typeof result.duration).toBe('number');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});

describe('threat-agent: happy path - tool call loop', () => {
  test('analyze() executes tool, feeds back result, then exits on second response', async () => {
    const graph = mkGraph([mkNode('n1'), mkNode('n2')]);
    const taint = mkTaint([mkPath(mkSource('req.body', 'user_input'), mkSink('db.query', 'sql'))]);
    const threat = mkThreat('T-1', 'tampering');
    const model = mkThreatModel([threat]);
    // 第一次: 触发工具调用(query_graph);第二次: 直接给出 findings
    const router = mkRouter([
      'TOOL_CALL: query_graph({"node_type":"function"})\n',
      sampleFindingsJson,
    ]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.iterations).toBe(2);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].threatId).toBe('T-1');
  });

  test('analyze() records threat_id from verify_exploitation into threatCoverage', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([mkPath(mkSource('req.body', 'user_input'), mkSink('db.query', 'sql'))]);
    const threat = mkThreat('T-99', 'tampering');
    const model = mkThreatModel([threat]);
    // 第一次: 调用 verify_exploitation;第二次: 返回 findings(不含该 threatId)
    const router = mkRouter([
      'TOOL_CALL: verify_exploitation({"threat_id":"T-99"})\n',
      JSON.stringify({ findings: [] }),
    ]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.threatCoverage).toContain('T-99');
    // T-99 没有出现在 findings 的 threatId 中,但作为已覆盖威胁
    expect(result.findings).toHaveLength(0);
    expect(result.iterations).toBe(2);
  });
});

// ─── 边界 ──────────────────────────────────────────────────────────────

describe('threat-agent: boundaries', () => {
  test('empty threat model + empty taint + single-node graph returns empty result', async () => {
    const graph = mkGraph([mkNode('only')]);
    const taint = mkTaint([]);
    const model = mkThreatModel([]);
    const router = mkRouter([JSON.stringify({ findings: [] })]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.findings).toEqual([]);
    expect(result.threatCoverage).toEqual([]);
    expect(result.iterations).toBe(1);
    expect(result.totalTokens).toBe(30);
  });

  test('maxIterations=1 forces final-response path and still returns shape', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([]);
    const model = mkThreatModel([]);
    // 第一次(也是唯一一次): 触发工具调用,迫使循环到 maxIter 边界
    // maxIter=1 时,第一次循环结束后 i=1 >= maxIter=1,会触发最终一次 chat
    const router = mkRouter([
      'TOOL_CALL: query_graph({})\n', // 仍然产生 tool calls
      sampleFindingsJson,             // maxIter 触发的最终响应
    ]);

    const agent = new ThreatAgent(router, graph, taint, model, { maxIterations: 1 });
    const result = await agent.analyze();

    // iterations 计入主循环的次数(1) + maxIter 触发的额外 chat 后
    // totalTokens 反映两次 chat 调用
    expect(result.iterations).toBe(1);
    expect(result.totalTokens).toBe(60); // 30 * 2 次 chat
    expect(result.findings).toHaveLength(1);
  });

  test('unknown severity in LLM response falls back to medium', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([]);
    const model = mkThreatModel([]);
    const badSeverity = JSON.stringify({
      findings: [{
        threatId: 'T-X',
        category: 'tampering',
        title: 'x',
        description: 'x',
        severity: 'catastrophic', // 不在白名单
        exploitationPossible: false,
        remediation: '',
        confidence: 0.5,
        evidence: '',
      }],
    });
    const router = mkRouter([badSeverity]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe('medium');
  });
});

// ─── 错误路径 ─────────────────────────────────────────────────────────

describe('threat-agent: error path', () => {
  test('non-JSON LLM response yields zero findings without throwing', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([]);
    const model = mkThreatModel([]);
    const router = mkRouter(['This is not JSON at all, just prose.']);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    expect(result.findings).toEqual([]);
    expect(result.threatCoverage).toEqual([]);
    expect(result.iterations).toBe(1);
  });

  test('unknown tool call is reported as error but agent continues to final response', async () => {
    const graph = mkGraph([mkNode('n1')]);
    const taint = mkTaint([]);
    const model = mkThreatModel([]);
    const router = mkRouter([
      'TOOL_CALL: nonexistent_tool({"foo":"bar"})\n',
      sampleFindingsJson,
    ]);

    const agent = new ThreatAgent(router, graph, taint, model);
    const result = await agent.analyze();

    // 工具错误不会中断循环;最终响应被解析
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].threatId).toBe('T-1');
    expect(result.iterations).toBe(2);
  });
});
