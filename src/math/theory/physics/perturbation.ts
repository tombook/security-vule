/**
 * theory/physics/perturbation.ts — 摄动理论 / 异常检测
 *
 * 数学对象 → 物理叙事:
 *   - detectZScoreAnomaly: z-score 异常
 *   - detectMahalanobisAnomaly: 马氏距离异常
 *   - detectPeriodicAnomaly: 周期异常
 *   - computeJ2Perturbation: J2 摄动
 *   - computeAtmosphericDragPerturbation: 大气阻力摄动
 *
 * 在漏洞挖掘中: 偏离正常模式的节点 (outlier), 复杂度漂移.
 * L1 数学基底: execution/anomaly.ts (z-score/Mahalanobis)
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §2
 */

export {
  detectZScoreAnomaly,
  detectMahalanobisAnomaly,
  detectPeriodicAnomaly,
  computeJ2Perturbation,
  computeAtmosphericDragPerturbation,
  type OrbitalAnomaly,
  type Perturbation,
} from '../../cosm-x-galaxy.js';
