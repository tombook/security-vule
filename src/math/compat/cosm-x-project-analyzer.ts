/**
 * 兼容层: cosm-x-project-analyzer (旧 API)
 *
 * v3.0 重新设计后, 项目扫描器位于 src/math/application/scanner.ts
 * 本文件 re-export 新位置, 保证向后兼容
 *
 * 迁移路径:
 *  旧: import { ... } from './cosm-x-project-analyzer.js'
 *  新: import { ... } from '../application/scanner.js'
 *
 * @see docs/REDESIGN.md
 */
export * from '../application/scanner.js';
