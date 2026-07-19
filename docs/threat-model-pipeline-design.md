# Threat-Modeling-Driven Vulnerability Detection Pipeline

## 1. Overview

security-vule 的核心差异化：**自动化威胁建模驱动的漏洞检测流水线**。

在分析 24+ 个竞品项目后，发现 **1/24 使用了自动化威胁建模** — Heimdall 的 Tyr 引擎 (LLM-driven, STRIDE-based, multi-pass refinement)。其余 23/24 均无结构化威胁建模。

**竞品威胁建模对比：**

| 竞品 | 威胁建模方式 | 自动化程度 |
|------|-------------|-----------|
| **Heimdall (Tyr)** | LLM 生成结构化威胁模型 (boundaries/surfaces/data_flows), STRIDE 方法论, refinement pass, 表面验证 | ⭐⭐⭐⭐⭐ 完全自动化 |
| defending-code-reference-harness | 手写 THREAT_MODEL.md | ⭐ 人工 |
| 其余 22 个 | 无 | — |

**security-vule 的差异化 (vs Heimdall Tyr)：**

| 维度 | Heimdall Tyr | security-vule |
|------|-------------|---------------|
| 威胁模型来源 | LLM 直接从代码索引生成 | **从程序图 (CPG/CFG/DFG/Taint) 自动生成** |
| STRIDE 分类 | LLM 提及 STRIDE 但无显式映射 | **显式 STRIDE↔CWE↔OWASP 映射表** |
| 信任边界 | LLM 推断 | **从 taint path 自动提取** |
| 检测定向 | Hunt agent 按表面调查 | **STRIDE 分类驱动定向检测插件** |
| 闭环校准 | 无 | **检测结果 → 威胁模型校准反馈** |
| 天体力学映射 | 无 | **轨道异常检测映射漏洞** |

security-vule 的独特价值：
1. **从程序图自动生成威胁模型** (非 LLM 推断，基于 CPG/CFG/DFG/Taint 的确定性分析)
2. **显式 STRIDE↔CWE↔OWASP 映射驱动定向检测**
3. **闭环反馈（检测结果 → 威胁模型校准）**
4. **天体力学轨道异常映射** (无竞品有此能力)

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Threat Modeling Pipeline                        │
│                                                                     │
│  Phase 0           Phase 1            Phase 2         Phase 3      │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐    ┌──────────┐   │
│  │  Program  │────▶│  Threat  │────▶│ Directed │───▶│ Results  │   │
│  │  Graph    │     │  Model   │     │ Detection │    │Calibrate │   │
│  │  Builder  │     │Generator │     │ Pipeline  │    │ + Feed   │   │
│  └──────────┘     └──────────┘     └──────────┘    └──────────┘   │
│       │                │                  │               │         │
│       ▼                ▼                  ▼               ▼         │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐    ┌──────────┐   │
│  │  Graph   │     │  STRIDE  │     │  Plugin   │    │Coverage  │   │
│  │  Query   │     │  Mapper  │     │ Pipeline  │    │ Report   │   │
│  │  Layer   │     │          │     │ (existing) │    │          │   │
│  └──────────┘     └──────────┘     └──────────┘    └──────────┘   │
│                                           ▲                         │
│  ┌────────────────────────────────────────┘                         │
│  │  LLM Tool Loop (Phase 2b)                                        │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐     │
│  │  │ query_  │  │ trace_   │  │ enumerate│  │ verify_      │     │
│  │  │ graph   │  │ dataflow │  │ _attack_ │  │ exploitation │     │
│  │  │         │  │          │  │ vectors  │  │              │     │
│  │  └─────────┘  └──────────┘  └──────────┘  └──────────────┘     │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Existing Infrastructure Map

| 组件 | 文件 | 现状 | 需要扩展 |
|------|------|------|----------|
| Program Graph | `src/engine/program-graph.ts` | 7 种边类型 (AST, CFG, CFG_TRUE, CFG_FALSE, DFG, CALL, FALLS_TO) | **+ 图查询算法 (BFS, DFS, reachability, path)** |
| Taint Analysis | `src/engine/taint.ts` | 7 source types, 7 sink types, 5 sanitizer types, taint propagation | **+ 跨文件传播, 作为 Trust Boundary 的输入** |
| Plugin System | `src/plugin/types.ts` | Probe → Detector → Generator 三层 | **+ ThreatModelPlugin 类型, ThreatModelContext** |
| Plugin Pipeline | `src/plugin/pipeline.ts` | probes → detectors → generators | **+ Phase 0 威胁模型生成阶段** |
| LLM Layer | `src/llm/router.ts` | 8 providers, failover/round-robin/latency/cost routing | **+ 用于威胁模型生成和工具循环** |
| LLM Agent | `src/detection/llm-agent.ts` | 单轮分析 + 修复建议 | **+ 多轮工具循环 (借鉴 Alibaba OCR)** |
| MCP Server | `src/mcp/server.ts` | 4 tools (scan_code, scan_file, list_rules, lookup_cwe) | **+ threat_model, attack_surface 工具** |
| CFG Builder | `src/engine/cfg.ts` | 控制流图 | 已有，直接使用 |
| DFG Builder | `src/engine/dfg.ts` | 数据流图 | 已有，直接使用 |
| Evolution | `src/evolution/` | GA + COSM-X 规则进化 | 未来可用于进化威胁模型权重 |

## 4. Phase 0: Threat Model Type System + Graph Query Layer

### 4.1 New Files

```
src/threat/
├── types.ts           # 核心类型定义 (TrustBoundary, AttackSurface, ThreatCategory, ThreatModel)
├── graph-query.ts     # 程序图查询算法 (BFS, DFS, reachability, path finding)
├── trust-boundary.ts  # 从 taint analysis 提取 trust boundary
├── stride-mapper.ts   # STRIDE 威胁分类映射
├── model-generator.ts # 自动威胁模型生成 (组合 trust boundary + STRIDE)
└── index.ts           # 公共导出
```

### 4.2 Core Types

```typescript
// src/threat/types.ts

/** STRIDE threat categories */
export type STRIDECategory =
  | 'spoofing'           // 身份欺骗
  | 'tampering'          // 数据篡改
  | 'repudiation'        // 否认
  | 'information_disclosure'  // 信息泄露
  | 'denial_of_service'  // 拒绝服务
  | 'elevation_of_privilege'; // 权限提升

/** Trust boundary between two security zones */
export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  /** Left side of boundary (higher trust) */
  inside: TrustZone;
  /** Right side of boundary (lower trust) */
  outside: TrustZone;
  /** Boundary type */
  type: 'input' | 'output' | 'data_store' | 'process' | 'network';
  /** Associated taint source/sink pairs */
  taintPaths: string[];  // TaintPath IDs
  /** Source location */
  location: {
    file: string;
    line?: number;
  };
  /** Confidence of boundary detection */
  confidence: number;
}

export interface TrustZone {
  id: string;
  name: string;
  type: 'trusted' | 'untrusted' | 'semi_trusted';
  /** PGNode IDs in this zone */
  nodes: string[];
  /** Scope (function name, module, etc.) */
  scope: string;
}

/** Attack surface: entry point + reachable dangerous operations */
export interface AttackSurface {
  id: string;
  name: string;
  description: string;
  /** Entry point node in program graph */
  entryPoint: string;  // PGNode ID
  /** Entry point type */
  entryType: 'http_handler' | 'cli_handler' | 'api_endpoint' | 'file_input' | 'db_query' | 'event_handler';
  /** Reachable dangerous operations from this entry point */
  reachableSinks: string[];  // PGNode IDs
  /** Trust boundaries crossed */
  boundariesCrossed: string[];  // TrustBoundary IDs
  /** Data flow paths */
  dataFlowPaths: DataFlowPath[];
  /** Risk score (computed from STRIDE + reachability) */
  riskScore: number;
  location: { file: string; line?: number };
}

export interface DataFlowPath {
  id: string;
  source: string;       // PGNode ID
  sink: string;         // PGNode ID
  intermediaries: string[];  // PGNode IDs
  sanitizers: string[];      // PGNode IDs
  crossBoundary: boolean;
  confidence: number;
}

/** STRIDE-classified threat */
export interface Threat {
  id: string;
  category: STRIDECategory;
  title: string;
  description: string;
  /** Attack surface this threat applies to */
  attackSurfaceId: string;
  /** Trust boundary being violated */
  trustBoundaryId?: string;
  /** CWE mapping */
  cwe?: string[];
  /** OWASP mapping */
  owasp?: string;
  /** Suggested detection rule IDs */
  suggestedDetectionRules: string[];
  /** Priority for scanning (higher = scan first) */
  priority: number;  // 0-100
  /** Whether this threat has been scanned */
  scanned: boolean;
  /** Scan results (filled in Phase 3) */
  findings?: string[];  // Detection IDs
}

/** Complete threat model for a codebase/file */
export interface ThreatModel {
  id: string;
  /** File or scope this model covers */
  scope: string;
  /** When generated */
  timestamp: number;
  /** How it was generated */
  method: 'auto_graph' | 'auto_llm' | 'manual' | 'hybrid';
  /** Trust boundaries identified */
  trustBoundaries: TrustBoundary[];
  /** Attack surfaces identified */
  attackSurfaces: AttackSurface[];
  /** STRIDE-classified threats */
  threats: Threat[];
  /** Coverage: which STRIDE categories have threats */
  strideCoverage: Record<STRIDECategory, boolean>;
  /** Overall risk assessment */
  riskAssessment: {
    overall: number;  // 0-100
    byCategory: Record<STRIDECategory, number>;
    criticalPaths: number;
  };
  /** Graph query cache */
  graphStats?: {
    nodeCount: number;
    edgeCount: number;
    boundaryCount: number;
    surfaceCount: number;
    threatCount: number;
  };
}

/** Detection scheduling instruction (Phase 1 → Phase 2) */
export interface DetectionSchedule {
  /** Threat to scan */
  threatId: string;
  /** Detection rules to apply */
  ruleIds: string[];
  /** Priority (higher = earlier) */
  priority: number;
  /** Context for detectors */
  context: {
    entryPoint?: string;
    trustBoundary?: string;
    dataFlowPaths: DataFlowPath[];
  };
}

/** Phase 3 calibration result */
export interface CalibrationResult {
  /** Threat model ID */
  threatModelId: string;
  /** Coverage report */
  coverage: {
    threatsScanned: number;
    threatsTotal: number;
    coveragePercent: number;
    unscannedCategories: STRIDECategory[];
  };
  /** Findings mapped to threats */
  threatFindings: Map<string, string[]>;  // threatId → detectionIds
  /** Recommended recalibration actions */
  recalibration: RecalibrationAction[];
}

export interface RecalibrationAction {
  type: 'add_threat' | 'increase_priority' | 'add_surface' | 'expand_boundary';
  description: string;
  affectedThreatId?: string;
  reason: string;
}
```

### 4.3 Graph Query Layer

```typescript
// src/threat/graph-query.ts

import type { ProgramGraph, PGNode, PGEdge, ProgramEdgeType } from '../engine/program-graph.js';

/** Graph query utilities for threat model generation */
export class GraphQuery {
  private graph: ProgramGraph;
  private adj: Map<string, Array<{ target: string; type: ProgramEdgeType }>>;
  private reverseAdj: Map<string, Array<{ source: string; type: ProgramEdgeType }>>;

  constructor(graph: ProgramGraph) { ... }

  /** BFS from a starting node, following specific edge types */
  bfs(start: string, edgeTypes?: ProgramEdgeType[]): Set<string>;

  /** DFS from a starting node */
  dfs(start: string, edgeTypes?: ProgramEdgeType[]): Set<string>;

  /** Find all nodes reachable from entry points */
  reachableFrom(entryPoints: string[], edgeTypes?: ProgramEdgeType[]): Set<string>;

  /** Find paths between two nodes */
  findPaths(source: string, target: string, maxLength?: number): string[][];

  /** Find all nodes of a given type */
  nodesByType(type: string): PGNode[];

  /** Find nodes matching a predicate */
  filterNodes(predicate: (node: PGNode) => boolean): PGNode[];

  /** Get edges crossing between two sets of nodes (trust boundary detection) */
  crossingEdges(zoneA: Set<string>, zoneB: Set<string>): PGEdge[];

  /** Find entry points (nodes with no incoming CALL edges but are function declarations) */
  findEntryPoints(): PGNode[];

  /** Find dangerous sinks (nodes that match sink patterns) */
  findSinks(): PGNode[];

  /** Compute shortest path between two nodes (weighted by edge type) */
  shortestPath(source: string, target: string): string[] | null;

  /** Get subgraph induced by a set of nodes */
  subgraph(nodeIds: Set<string>): { nodes: PGNode[]; edges: PGEdge[] };
}
```

### 4.4 STRIDE Mapper

Maps taint source→sink pairs to STRIDE categories:

| Source Type | Sink Type | STRIDE Category | CWE Examples |
|-------------|-----------|-----------------|--------------|
| user_input | sql | Tampering | CWE-89 |
| user_input | shell | Tampering + Elevation | CWE-78 |
| user_input | eval | Tampering | CWE-94 |
| user_input | file_write | Tampering | CWE-22, CWE-49 |
| user_input | network_send | Information Disclosure | CWE-201, CWE-352 |
| network | eval | Tampering + Spoofing | CWE-94 |
| cookie | sql | Tampering + Repudiation | CWE-89 |
| header | shell | Tampering + Spoofing | CWE-78 |
| file_io | eval | Tampering | CWE-94 |
| env | shell | Elevation of Privilege | CWE-78 |
| db | network_send | Information Disclosure | CWE-200 |
| * | * (any) | Denial of Service | CWE-400 |

## 5. Phase 1: Automated Threat Model Generation

### Flow

```
ProgramGraph + TaintResult + Source Code
        │
        ▼
┌───────────────────────────────────┐
│  Trust Boundary Extraction        │
│  - Identify security zones        │
│  - Find boundaries (source→sink)  │
│  - Score boundary severity        │
└─────────────────┬─────────────────┘
                  │
                  ▼
┌───────────────────────────────────┐
│  Attack Surface Enumeration       │
│  - Find entry points              │
│  - Compute reachability to sinks  │
│  - Identify data flow paths       │
└─────────────────┬─────────────────┘
                  │
                  ▼
┌───────────────────────────────────┐
│  STRIDE Threat Classification     │
│  - Map source→sink to STRIDE      │
│  - Assign CWE/OWASP               │
│  - Prioritize by risk             │
└─────────────────┬─────────────────┘
                  │
                  ▼
┌───────────────────────────────────┐
│  Threat Model Assembly            │
│  - Combine all components         │
│  - Compute coverage & risk        │
│  - Store in ProbeContext.sharedData│
└───────────────────────────────────┘
```

### Key Algorithm: Trust Boundary Extraction

```typescript
// src/threat/trust-boundary.ts

export function extractTrustBoundaries(
  graph: ProgramGraph,
  taintResult: TaintResult,
  filePath: string,
): TrustBoundary[] {
  const query = new GraphQuery(graph);
  const boundaries: TrustBoundary[] = [];

  for (const taintPath of taintResult.paths) {
    if (taintPath.confidence < 0.5) continue;

    const insideZone: TrustZone = {
      id: `zone_inside_${taintPath.sink.id}`,
      name: `${taintPath.sink.scope} (trusted)`,
      type: 'trusted',
      nodes: findNodesInScope(graph, taintPath.sink.scope),
      scope: taintPath.sink.scope,
    };

    const outsideZone: TrustZone = {
      id: `zone_outside_${taintPath.source.id}`,
      name: `${taintPath.source.type} input (untrusted)`,
      type: 'untrusted',
      nodes: findSourceNodes(graph, taintPath.source),
      scope: taintPath.source.scope,
    };

    const boundaryType = mapBoundaryType(taintPath.source.type, taintPath.sink.type);

    boundaries.push({
      id: `boundary_${taintPath.source.id}_${taintPath.sink.id}`,
      name: `${taintPath.source.type} → ${taintPath.sink.type}`,
      description: `Data from ${taintPath.source.type} (${taintPath.source.name}) flows to ${taintPath.sink.type} (${taintPath.sink.name})`,
      inside: insideZone,
      outside: outsideZone,
      type: boundaryType,
      taintPaths: [taintPath.source.id, ...taintPath.path, taintPath.sink.id],
      location: { file: filePath, line: taintPath.source.line },
      confidence: taintPath.confidence,
    });
  }

  return deduplicateBoundaries(boundaries);
}
```

## 6. Phase 2: Threat-Model-Driven Scanning Pipeline

### Integration with Existing PluginPipeline

The threat model becomes a **pre-pipeline phase** that injects context into `ProbeContext.sharedData`:

```typescript
// Enhanced pipeline flow:
//
//  [Phase 0] Threat Model Generation
//      ↓
//  [Phase 1] Detection Scheduling (threat → rules mapping)
//      ↓
//  [Phase 2] Plugin Pipeline (probes → detectors → generators)
//      ↓   (existing PluginPipeline.run() with sharedData containing threat model)
//  [Phase 3] Results Calibration + Feedback

export class ThreatModelPipeline {
  private registry: PluginRegistry;
  private pluginPipeline: PluginPipeline;
  private llmRouter: LLMRouter;

  async run(code: string, filePath: string, language?: string): Promise<ThreatModelPipelineResult> {
    // Phase 0: Build program graph and taint analysis
    const graph = buildProgramGraph(parse(code), buildCFG(code), code);
    const taintResult = analyzeTaint(code, filePath);

    // Phase 0b: Generate threat model
    const threatModel = this.generateThreatModel(graph, taintResult, code, filePath);

    // Phase 1: Schedule detections
    const schedule = this.scheduleDetections(threatModel);

    // Phase 2: Run plugin pipeline with threat model context
    const pipelineResult = await this.pluginPipeline.run(code, filePath, {
      language,
      probeIds: this.selectProbesForSchedule(schedule),
      sharedDataOverrides: { threatModel, schedule },
    });

    // Phase 3: Calibrate results
    const calibration = this.calibrate(threatModel, pipelineResult);

    return { threatModel, schedule, pipelineResult, calibration };
  }
}
```

### LLM Tool Loop (Phase 2b)

借鉴 Alibaba open-code-review 的 6-tool 设计，但用程序图查询替代简单文本搜索：

```typescript
// LLM Agent Tools for deep analysis
const THREAT_MODEL_TOOLS: AgentTool[] = [
  {
    name: 'query_graph',
    description: 'Query the program graph for nodes, edges, paths, and reachability',
    parameters: { query: string, edgeTypes?: ProgramEdgeType[] },
  },
  {
    name: 'trace_dataflow',
    description: 'Trace data flow from a source to all reachable nodes',
    parameters: { sourceNode: string, maxDepth?: number },
  },
  {
    name: 'enumerate_attack_vectors',
    description: 'Enumerate attack vectors for a given entry point',
    parameters: { entryPoint: string, threatCategory?: STRIDECategory },
  },
  {
    name: 'verify_exploitation',
    description: 'Verify if a detected vulnerability is exploitable via the identified path',
    parameters: { threatId: string, pathNodes: string[] },
  },
  {
    name: 'check_sanitizer',
    description: 'Check if a sanitizer effectively blocks a specific attack type',
    parameters: { sanitizerNode: string, attackType: string },
  },
  {
    name: 'get_threat_model',
    description: 'Get the current threat model summary',
    parameters: {},
  },
];
```

## 7. Phase 3: Results Calibration + Feedback

### Coverage Reporting

```typescript
interface ThreatModelCoverage {
  /** STRIDE categories covered */
  strideCoverage: Record<STRIDECategory, { total: number; scanned: number }>;
  /** Attack surfaces scanned */
  surfaceCoverage: { total: number; scanned: number };
  /** Trust boundaries validated */
  boundaryCoverage: { total: number; validated: number };
  /** Overall coverage percentage */
  overallPercent: number;
}
```

### Feedback Loop

Detection results feed back into the threat model:

1. **Confirmed findings** → Reduce threat priority (already detected)
2. **False positives** → Adjust confidence scores
3. **Unscanned threats** → Trigger additional detection passes
4. **New patterns found** → Add to threat model (recalibration)

## 8. Implementation Priority

| Phase | Priority | Estimated Effort | Deliverable |
|-------|----------|------------------|-------------|
| Phase 0: Types + Graph Query | **P0** | 1-2 weeks | `src/threat/types.ts`, `src/threat/graph-query.ts` |
| Phase 1: Threat Model Generator | **P0** | 1-2 weeks | `src/thrust/trust-boundary.ts`, `stride-mapper.ts`, `model-generator.ts` |
| Phase 2a: Pipeline Integration | **P1** | 2-3 weeks | `src/threat/threat-pipeline.ts` |
| Phase 2b: LLM Tool Loop | **P1** | 2-3 weeks | Enhanced `LLMAgent` with tool calling |
| Phase 3: Calibration | **P2** | 1-2 weeks | Coverage reports + feedback loop |
| MCP Integration | **P2** | 1 week | New MCP tools for threat model |

## 9. STRIDE → CWE → Detection Rule Mapping

```typescript
// src/threat/stride-mapper.ts

export const STRIDE_MAPPINGS: Record<STRIDECategory, {
  description: string;
  sourceSinkPairs: Array<{ source: TaintSource['type']; sink: TaintSink['type'] }>;
  cweIds: string[];
  owasp: string;
  detectionRulePrefixes: string[];
}> = {
  spoofing: {
    description: 'Identity spoofing — untrusted input impersonates authenticated user',
    sourceSinkPairs: [
      { source: 'cookie', sink: 'sql' },
      { source: 'header', sink: 'sql' },
      { source: 'network', sink: 'eval' },
    ],
    cweIds: ['CWE-287', 'CWE-384', 'CWE-613'],
    owasp: 'A07:2021',
    detectionRulePrefixes: ['AUTH'],
  },
  tampering: {
    description: 'Data tampering — untrusted input modifies protected data',
    sourceSinkPairs: [
      { source: 'user_input', sink: 'sql' },
      { source: 'user_input', sink: 'shell' },
      { source: 'user_input', sink: 'eval' },
      { source: 'user_input', sink: 'file_write' },
      { source: 'network', sink: 'sql' },
      { source: 'network', sink: 'shell' },
    ],
    cweIds: ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-22', 'CWE-49'],
    owasp: 'A03:2021',
    detectionRulePrefixes: ['INJ'],
  },
  repudiation: {
    description: 'Repudiation — actions cannot be traced back to user',
    sourceSinkPairs: [
      { source: 'cookie', sink: 'sql' },
      { source: 'header', sink: 'sql' },
    ],
    cweIds: ['CWE-778', 'CWE-295'],
    owasp: 'A09:2021',
    detectionRulePrefixes: ['AUTH'],
  },
  information_disclosure: {
    description: 'Information disclosure — sensitive data exposed to untrusted party',
    sourceSinkPairs: [
      { source: 'user_input', sink: 'network_send' },
      { source: 'db', sink: 'network_send' },
      { source: 'file_io', sink: 'network_send' },
      { source: 'env', sink: 'network_send' },
    ],
    cweIds: ['CWE-200', 'CWE-201', 'CWE-352', 'CWE-532'],
    owasp: 'A01:2021',
    detectionRulePrefixes: ['INJ', 'CRYPTO'],
  },
  denial_of_service: {
    description: 'Denial of service — resource exhaustion or crash',
    sourceSinkPairs: [
      { source: 'user_input', sink: 'eval' },
      { source: 'user_input', sink: 'file_write' },
      { source: 'network', sink: 'eval' },
    ],
    cweIds: ['CWE-400', 'CWE-770', 'CWE-789'],
    owasp: 'A05:2021',
    detectionRulePrefixes: ['INJ', 'MEM'],
  },
  elevation_of_privilege: {
    description: 'Elevation of privilege — untrusted user gains admin access',
    sourceSinkPairs: [
      { source: 'user_input', sink: 'shell' },
      { source: 'env', sink: 'shell' },
      { source: 'network', sink: 'shell' },
      { source: 'user_input', sink: 'eval' },
    ],
    cweIds: ['CWE-78', 'CWE-94', 'CWE-269', 'CWE-862'],
    owasp: 'A01:2021',
    detectionRulePrefixes: ['INJ', 'AUTH'],
  },
};
```

## 10. Competitive Advantage Summary

| 能力 | security-vule | 24 个竞品 |
|------|:---:|:---:|
| 自动威胁建模 | ✅ Phase 0 | ❌ 无 |
| STRIDE 分类 | ✅ 6 categories | ❌ 无 |
| 信任边界提取 | ✅ from taint analysis | ❌ 无 |
| 攻击面枚举 | ✅ from program graph reachability | ❌ 无 |
| 威胁→检测规则映射 | ✅ STRIDE → CWE → Rules | ❌ 无 |
| 闭环反馈 | ✅ findings → threat model | ❌ 无 |
| 覆盖率报告 | ✅ STRIDE coverage % | ❌ 无 |
| 程序图查询 | ✅ 7 edge types + BFS/DFS | 部分 (仅 graph-based: FUNDED_NISL) |
| 污点分析 | ✅ 7 source + 7 sink types | 部分 (少数有) |
| LLM 增强检测 | ✅ tool loop with graph queries | 部分 (Alibaba OCR 有) |
| 插件架构 | ✅ Probe/Detector/Generator | 部分 (garak 有) |
