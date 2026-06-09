/**
 * 兼容层: cosm-x-theory-23d (旧 API)
 *
 * v3.0 重新设计后, 23 维理论位于 src/math/theory/23d/
 * 本文件 re-export 新位置, 保证向后兼容
 *
 * 迁移路径:
 *  旧: import { ... } from './cosm-x-theory-23d.js'
 *  新: import { ... } from '../theory/23d/index.js'
 *
 * @see docs/REDESIGN.md
 */
export * from '../theory/23d/index.js';
