/**
 * theory/physics/gravity.ts — 万有引力场
 *
 * 数学对象 → 物理叙事:
 *   - buildBHTree: Barnes-Hut 八叉树 (N 体加速)
 *   - computeNBodyGravity: N 体引力合力
 *
 * 在漏洞挖掘中: 调用链引力, 多汇点撕裂力.
 * L1 数学基底: execution/graph-metrics.ts (pagerank/betweenness)
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §2
 */

export {
  buildBHTree,
  computeNBodyGravity,
} from '../../cosm-x-galaxy.js';
