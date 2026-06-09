/**
 * 兼容层: cosm-x-cli (旧 API)
 *
 * v3.0 重新设计后, CLI 入口位于 src/math/pipeline/run-scan.ts
 * 本文件 re-export 新位置, 保证向后兼容
 *
 * 迁移路径:
 *  旧: import { ... } from './cosm-x-cli.js'
 *  新: import { ... } from '../pipeline/run-scan.js'
 *
 * @see docs/REDESIGN.md
 */
export * from '../pipeline/run-scan.js';
