/**
 * 兼容层: src/math/cpg.ts (旧位置)
 *
 * v3.0 重新设计后, cpg 实际位于 src/math/execution/cpg.ts.
 * 本文件 re-export, 保证 tests/unit/math/cpg.test.ts 等旧 import 仍工作.
 *
 * 新代码请用: import { ... } from './execution/cpg.js'
 *
 * @see docs/REDESIGN.md
 */
export * from './execution/cpg.js';
