/**
 * theory/physics/tidal.ts — 潮汐力 / 拉格朗日点
 *
 * 数学对象 → 物理叙事:
 *   - solveTDOA: 到达时间差 (TDOA) 定位
 *   - trilaterate: 三边测量
 *   - computeLagrangePoints: 五个拉格朗日点 (引力平衡)
 *   - identifyLagrangePointsInCFG: CFG 中的 sink 点 (L4/L5 平衡位置)
 *
 * 在漏洞挖掘中: sink/source 节点作为引力平衡点, 多 sink 撕裂.
 * L1 数学基底: execution/cpg.ts (CFG/DFG 提取)
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §2
 */

export {
  solveTDOA,
  trilaterate,
  computeLagrangePoints,
  identifyLagrangePointsInCFG,
  type Anchor,
  type LagrangePoint,
} from '../../cosm-x-galaxy.js';
