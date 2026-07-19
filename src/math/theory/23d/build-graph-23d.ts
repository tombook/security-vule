/**
 * theory/23d/build-graph-23d.ts — 23 维图数据构建 (per-node 修复版)
 *
 * v3.0 重新设计后, 修复 #1 优先级:
 *  旧: buildGraphData23D 只写 `_project_avg`, UVRS 实测只有 3 个值
 *  新: per-node 数据从 CPG 节点实际提取, UVRS 反映真实位置风险
 *
 * 实现说明: 本文件实际重写 buildGraphData23D, 接受 cpg 节点参数后
 *          per-node 填充 (而非 severity 锚点). 原 cosm-x-theory-23d
 *          中的 buildGraphData23D 保留 (compat re-export), 标记 deprecated.
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §4.1
 */

import type { GraphData } from '../../cosm-x-theory-23d.js';

/**
 * v3.0 重导出兼容类型
 */
export type GraphData23D = GraphData;

/**
 * v3.0 扩展: CPG 节点输入
 *
 * 调用方传入 cpg 节点, buildGraphData23D 实际从节点提取
 *  - pagerank, betweenness (图论指标)
 *  - in_degree, out_degree
 *  - cyclomatic_complexity
 *  - architectural_smells (来自 6 维 anomaly)
 *  - node_count 真实节点数
 */
export interface CPGNodeInput {
  nodeId: string;            // "file:line"
  pagerank?: number;
  betweenness?: number;
  inDegree?: number;
  outDegree?: number;
  cyclomaticComplexity?: number;
}

/**
 * v3.0 扩展: 6 维非饱和子信号 (来自 theory/physics/saturation.ts)
 */
export interface SixDimRawSignals {
  anomalyScore: number;        // 0-10 异常度
  perturbationScore: number;   // 0-10 摄动度
  gravityScore: number;        // 0-10 引力度
  composite: number;           // 0-1 复合
  composite_100: number;       // 0-100 复合×100
}

/**
 * v3.0 修复版 buildGraphData23D (per-node)
 *
 * 与原版区别:
 *  - per-node 字段从 cpgNode 实际读取, 而非 _project_avg
 *  - 接受 cpgNodes 数组, 累计真实节点
 *  - architectural_smells 来自六维 anomaly_raw (非饱和)
 *  - 保留 _project_avg 作为项目级锚点 (向后兼容)
 */
export function buildGraphData23Dv3(
  cpgNodes: CPGNodeInput[],
  sixDim: SixDimRawSignals,
  finding: { severity: number; nodeId: string }
): GraphData {
  const nodeMap: Record<string, number> = {};
  const betweennessMap: Record<string, number> = {};
  const inDegreeMap: Record<string, number> = {};
  const outDegreeMap: Record<string, number> = {};
  const cyclomaticMap: Record<string, number> = {};
  const smellsMap: Record<string, number> = {};

  for (const n of cpgNodes) {
    nodeMap[n.nodeId] = n.pagerank ?? 0;
    betweennessMap[n.nodeId] = n.betweenness ?? 0;
    inDegreeMap[n.nodeId] = n.inDegree ?? 0;
    outDegreeMap[n.nodeId] = n.outDegree ?? 0;
    cyclomaticMap[n.nodeId] = n.cyclomaticComplexity ?? 0;
    smellsMap[n.nodeId] = sixDim.anomalyScore;
  }

  // _project_avg 仍然作为项目级锚点 (避免破坏已有 consumer)
  const avgPagerank = cpgNodes.length > 0
    ? cpgNodes.reduce((s, n) => s + (n.pagerank ?? 0), 0) / cpgNodes.length
    : 0;
  const avgBetweenness = cpgNodes.length > 0
    ? cpgNodes.reduce((s, n) => s + (n.betweenness ?? 0), 0) / cpgNodes.length
    : 0;

  return {
    pagerank: { ...nodeMap, _project_avg: avgPagerank },
    betweenness: { ...betweennessMap, _project_avg: avgBetweenness },
    in_degree: inDegreeMap,
    out_degree: outDegreeMap,
    cyclomatic_complexity: cyclomaticMap,
    architectural_smells: smellsMap,
    _v3_per_node_count: cpgNodes.length,
    _v3_severity_anchor: finding.severity,
    _v3_target_node: finding.nodeId,
  };
}

/**
 * v3.0 重导出原 buildGraphData23D (保留 compat, 标记 deprecated)
 *
 * @deprecated 实际新代码请用 buildGraphData23Dv3
 */
export { buildGraphData23D } from '../../cosm-x-theory-23d.js';
