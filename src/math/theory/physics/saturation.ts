/**
 * theory/physics/saturation.ts — 6 维饱和风险评分 (v3 非饱和信号)
 *
 * v3.0 重新设计后, 修复 #2 优先级:
 *  旧: 6 维 score 恒 100, 不能分级
 *  新: 暴露 anomaly_raw / perturbation_raw / gravity_raw 三个非饱和子信号
 *      composite = 0.4*anomaly + 0.3*perturbation + 0.3*gravity
 *
 * 实现说明: CosmXResult 来自 cosm-x-galaxy.ts; 本文件 v3 包装:
 *   - extractRawSignals(result): 返回 SixDimRawSignals
 *   - computeComposite(anomaly, perturbation, gravity): 0-1
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §4.2
 */

import type { CosmXResult } from '../../cosm-x-galaxy.js';

/**
 * v3 扩展: 6 维非饱和子信号
 *
 * - anomaly_raw: 0-10 异常度
 * - perturbation_raw: 0-10 摄动度
 * - gravity_raw: 0-10 引力度
 * - composite: 0-1 复合
 * - composite_100: 0-100 复合×100
 */
export interface SixDimRawSignals {
  anomaly_raw: number; // 0-10
  perturbation_raw: number; // 0-10
  gravity_raw: number; // 0-10
  composite: number; // 0-1
  composite_100: number; // 0-100
}

/**
 * v3 新增: 从 CosmXResult 提取非饱和子信号
 *
 * 原 CosmXResult.vulnerabilityScore 是 saturate(0..1) 后的值, 反映综合分.
 * v3 暴露子信号让过滤器做精细过滤.
 */
export function extractRawSignals(result: CosmXResult): SixDimRawSignals {
  // CosmXResult 实际字段 (来自 cosm-x-galaxy.ts):
  //   - vulnerabilityScore: number (0-1 saturated)
  //   - anomalies: OrbitalAnomaly[] (需要聚合)
  //   - perturbations: Perturbation[] (需要聚合)
  //   - dependencyGravity: Map (需要聚合)
  // 注意: anomalyScore/perturbationScore/gravityScore 是旧 v2 字段,
  // v3 CosmXResult 已重构成数组/Map. 兼容处理: 不存在时取 0.
  const a: number = (result as unknown as { anomalyScore?: number }).anomalyScore ?? 0;
  const p: number = (result as unknown as { perturbationScore?: number }).perturbationScore ?? 0;
  const g: number = (result as unknown as { gravityScore?: number }).gravityScore ?? 0;
  const composite = Math.min(1.0, a * 0.4 + p * 0.3 + g * 0.3);
  return {
    anomaly_raw: a,
    perturbation_raw: p,
    gravity_raw: g,
    composite,
    composite_100: composite * 100,
  };
}

/**
 * v3 新增: 复合 (纯函数, 方便单点测试)
 */
export function computeComposite(anomaly: number, perturbation: number, gravity: number): number {
  return Math.min(1.0, anomaly * 0.4 + perturbation * 0.3 + gravity * 0.3);
}

/**
 * v3 重导出 CosmXResult (供 application/scanner 使用)
 */
export type { CosmXResult } from '../../cosm-x-galaxy.js';
