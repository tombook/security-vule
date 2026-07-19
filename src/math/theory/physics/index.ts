/**
 * theory/physics — 6 维物理叙事 (L2 抽象层)
 *
 * 模块组成:
 *  - orbital       轨道力学 (开普勒 / 六根数)
 *  - gravity       万有引力 (Barnes-Hut)
 *  - tidal         潮汐 / 拉格朗日点
 *  - perturbation  摄动 / 异常检测
 *  - nbody         N 体 / 轨道映射
 *  - saturation    6 维非饱和风险评分 (v3 修复)
 *
 * @see docs/REDESIGN.md §2
 */

export * from './orbital.js';
export * from './gravity.js';
export * from './tidal.js';
export * from './perturbation.js';
export * from './nbody.js';
export * from './saturation.js';
