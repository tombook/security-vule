/**
 * theory/physics/nbody.ts — N 体问题 / 轨道映射
 *
 * 数学对象 → 物理叙事:
 *   - CosmXOrbitMapper 类: 将 CPG 节点映射到轨道模型
 *   - cosmXAnalyze: 综合分析 (返回 CosmXResult)
 *
 * 在漏洞挖掘中: N 节点相互作用的引力模型 → 风险传播.
 * L1 数学基底: execution/cpg.ts + graph-metrics.ts
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §2
 */

export {
  CosmXOrbitMapper,
  cosmXAnalyze,
  type CodeOrbitMapper,
  type CosmXResult,
} from '../../cosm-x-galaxy.js';
