/**
 * 兼容层: cosm-x-galaxy (旧 API)
 *
 * v3.0 重新设计后, 6 维物理位于 src/math/theory/physics/
 * 本文件 re-export 新位置, 保证向后兼容
 *
 * 迁移路径:
 *  旧: import { ... } from './cosm-x-galaxy.js'
 *  新: import { ... } from '../theory/physics/index.js'
 *
 * @see docs/REDESIGN.md
 */
export * from '../theory/physics/index.js';
