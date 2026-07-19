/**
 * theory/23d/definitions.ts — 23 维宇宙理论定义
 *
 * v3.0 重新设计后, 23 维理论定义从此处导出.
 * 原 cosm-x-theory-23d.ts 中 1-462 行的核心数据 (TheoryDimension 枚举,
 * THEORY_DEFINITIONS, RISK_THRESHOLDS 等) 通过 re-export 暴露.
 *
 * 抽象层次: L2 宇宙理论层 (数学对物理的同构)
 *
 * @see docs/REDESIGN.md §2 目录组织
 * @see docs/math-underneath.md §3 23 维理论
 */

import { THEORY_DEFINITIONS } from '../../cosm-x-theory-23d.js';

export {
  TheoryDimension,
  RiskLevel,
  RISK_THRESHOLDS,
  THEORY_DEFINITIONS,
  type TheoryDefinition,
  type TheoryCalculationResult,
  type GraphData,
  type DimensionComponents,
} from '../../cosm-x-theory-23d.js';

/**
 * v3.0 辅助: 按 dim_id 查找定义
 */
export function getTheoryDefinitionById(dimId: number) {
  return THEORY_DEFINITIONS.find((d) => d.dim_id === dimId) ?? null;
}
