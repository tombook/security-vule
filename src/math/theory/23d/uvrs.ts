/**
 * theory/23d/uvrs.ts — UVRS 聚合器
 *
 * UVRSCalculator + 默认权重 + 维度默认值的 facade.
 * UVRS = Unified Vulnerability Risk Score, sigmoid 聚合 23 维信号.
 *
 * 抽象层次: L2 宇宙理论层
 *
 * @see docs/REDESIGN.md §2
 */

export {
  UVRSCalculator,
  UVRS_DEFAULT_WEIGHTS,
  UVRS_DIMENSION_DEFAULTS,
  type UVRS,
  type UVRSStatistics,
  type UVRSConfigExport,
} from '../../cosm-x-theory-23d.js';
