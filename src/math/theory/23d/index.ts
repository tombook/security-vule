/**
 * theory/23d — 23 维宇宙理论 (L2 抽象层)
 *
 * 模块组成:
 *  - definitions    23 维定义 + 风险阈值
 *  - calculator     CosmicTheoryEngine (单维/全维/UVRS)
 *  - uvrs           UVRSCalculator + 默认权重
 *  - build-graph-23d   per-node 图数据构建 (v3 修复)
 *
 * @see docs/REDESIGN.md §2
 */

export * from './definitions.js';
export * from './calculator.js';
export * from './uvrs.js';
export * from './build-graph-23d.js';
