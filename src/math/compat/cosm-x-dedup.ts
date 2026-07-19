/**
 * 兼容层: cosm-x-dedup (旧 API)
 *
 * v3.0 重新设计后, 去重 + 置信度过滤位于 src/math/application/dedup.ts
 * 本文件 re-export 新位置, 保证向后兼容
 *
 * 迁移路径:
 *  旧: import { ... } from './cosm-x-dedup.js'
 *  新: import { ... } from '../application/dedup.js'
 *
 * @see docs/REDESIGN.md
 */
export * from '../application/dedup.js';
