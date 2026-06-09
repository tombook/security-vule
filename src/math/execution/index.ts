/**
 * execution — L1 原始数学层
 *
 * 矩阵/概率/统计 — 测量与观测 — CPG/pagerank.
 * 不依赖 L2/L3, 是最底层的纯数学实现.
 *
 * 模块 (v3.0):
 *  - cpg             CPG 构建 (CFG/DFG/call/source-sink)
 *  - graph-metrics   pagerank/betweenness/closeness
 *  - entropy         信息熵
 *  - anomaly         z-score/Mahalanobis/isolation forest
 *  - taint           污点分析 (source/sink/sanitizer/path tracking)
 *  - dataflow        数据流 (reaching defs + live vars + DU chains)
 *  - controlflow     控制流 (basic blocks + CFG + dominators + loops)
 *
 * @see docs/REDESIGN.md §2, §3
 * @see docs/math-underneath.md §8.4 (真实漏洞检测能力)
 */

export * from './cpg.js';
export * from './graph-metrics.js';
export * from './entropy.js';
export * from './anomaly.js';
export * from './taint.js';
export * from './dataflow.js';
export * from './controlflow.js';
