/**
 * tests/unit/math/controlflow.test.ts — 控制流分析单元测试
 *
 * 数学等价验证 (math-underneath.md §1):
 *   - basic block 划分的 leader 算法
 *   - CFG 边构建 (顺序/分支/循环)
 *   - 圈复杂度 V(G) = E - N + 2P
 *   - 循环深度计算
 */

import { describe, expect, test } from 'bun:test';
import {
  analyzeControlFlow,
  blockAtLine,
  buildBlocks,
  buildCFG,
  findNaturalLoops,
  immediateDominators,
} from '../../../src/math/execution/controlflow';

describe('controlflow > buildBlocks', () => {
  test('sequential code is one block', () => {
    const code = ['const a = 1;', 'const b = 2;', 'const c = 3;'];
    const blocks = buildBlocks(code);
    expect(blocks.length).toBe(1);
    expect(blocks[0].startLine).toBe(1);
    expect(blocks[0].endLine).toBe(3);
  });

  test('branches create multiple blocks', () => {
    const code = ['if (x) {', '  a();', '} else {', '  b();', '}'];
    const blocks = buildBlocks(code);
    expect(blocks.length).toBeGreaterThan(1);
  });
});

describe('controlflow > buildCFG', () => {
  test('creates fallthrough edges for sequential code', () => {
    const code = ['a();', 'b();', 'if (x) {', '  c();', '}', 'd();'];
    const cfg = buildCFG(code);
    expect(cfg.edgeCount).toBeGreaterThanOrEqual(2);
    expect(cfg.edges.some(e => e.kind === 'fallthrough')).toBe(true);
  });

  test('creates branch_true/branch_false for if', () => {
    const code = ['if (x) {', '  a();', '}', 'b();'];
    const cfg = buildCFG(code);
    const branchEdges = cfg.edges.filter(e => e.kind === 'branch_true' || e.kind === 'branch_false');
    expect(branchEdges.length).toBeGreaterThanOrEqual(2);
  });

  test('creates loop_back edge for for/while', () => {
    const code = ['for (let i = 0; i < 10; i++) {', '  a();', '}', 'b();'];
    const cfg = buildCFG(code);
    expect(cfg.edges.some(e => e.kind === 'loop_back')).toBe(true);
  });
});

describe('controlflow > analyzeControlFlow', () => {
  test('computes cyclomatic complexity V(G) = E - N + 2', () => {
    const code = ['if (a) {', '  x();', '}', 'if (b) {', '  y();', '}'];
    const cfa = analyzeControlFlow(code);
    expect(cfa.cyclomaticComplexity).toBeGreaterThan(1);
    // 验证 V(G) 公式
    const N = cfa.cfg.blockCount;
    const E = cfa.cfg.edgeCount;
    expect(cfa.cyclomaticComplexity).toBe(E - N + 2);
  });

  test('detects natural loop with depth', () => {
    const code = [
      'for (let i = 0; i < 10; i++) {',
      '  for (let j = 0; j < 5; j++) {',
      '    a();',
      '  }',
      '}',
    ];
    const cfa = analyzeControlFlow(code);
    expect(cfa.loops.length).toBeGreaterThanOrEqual(1);
    expect(cfa.maxLoopDepth).toBeGreaterThanOrEqual(1);
  });

  test('detects nested loops with higher depth', () => {
    const code = [
      'for (let i = 0; i < 10; i++) {',
      '  for (let j = 0; j < 5; j++) {',
      '    a();',
      '  }',
      '}',
    ];
    const cfa = analyzeControlFlow(code);
    // 至少一个内层 loop 应该有 depth > 0
    const nestedLoop = cfa.loops.find(l => l.depth > 0);
    expect(nestedLoop).toBeDefined();
  });

  test('returns immediate dominators map', () => {
    const code = ['a();', 'if (x) b();', 'c();'];
    const cfa = analyzeControlFlow(code);
    expect(cfa.immediateDominators instanceof Map).toBe(true);
  });

  test('blockAtLine returns loop context', () => {
    const code = [
      'for (let i = 0; i < 10; i++) {',
      '  a();',
      '}',
    ];
    const cfa = analyzeControlFlow(code);
    const r = blockAtLine(cfa, 2);
    expect(r.inLoop).toBe(true);
    expect(r.loopDepth).toBeGreaterThanOrEqual(1);
  });
});

describe('controlflow > findNaturalLoops', () => {
  test('finds loop with single back edge', () => {
    const code = [
      'for (let i = 0; i < 10; i++) {',
      '  a();',
      '}',
    ];
    const cfg = buildCFG(code);
    const idom = immediateDominators(cfg);
    const loops = findNaturalLoops(cfg, idom);
    expect(loops.length).toBeGreaterThanOrEqual(1);
    expect(loops[0].backEdges.length).toBeGreaterThan(0);
  });
});
