/**
 * theory/physics/orbital.ts — 轨道力学 (开普勒 / 轨道六根数)
 *
 * 数学对象 → 物理叙事:
 *   - solveKeplerEquation: 牛顿迭代解 M = E - e*sin(E)
 *   - elementsToPosition: 轨道六根数 → 笛卡尔位置
 *   - meanToTrueAnomaly: 平近点角 → 真近点角
 *   - solveLambertProblem: Lambert 问题 (双脉冲转移)
 *
 * 在漏洞挖掘中: 节点到 sink 的"轨道距离" / 节点特征 (近心/远心)
 *
 * 抽象层次: L2 宇宙理论层
 * 数学基底: L1 execution/ (solver/iteration from std lib)
 *
 * @see docs/REDESIGN.md §2
 */

export {
  solveKeplerEquation,
  elementsToPosition,
  meanToTrueAnomaly,
  solveLambertProblem,
  type OrbitalElements,
  type LambertSolution,
} from '../../cosm-x-galaxy.js';
