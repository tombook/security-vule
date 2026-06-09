/**
 * tests/unit/math/matching.test.ts — Fuzzy Match 单元测试
 *
 * 数学等价验证 (math-underneath §8.4):
 *   - 多因子加权综合 confidence
 *   - taint 路径有/无 → confidence 提升/降权
 *   - 循环内命中 → confidence 加重
 *   - 未初始化变量使用 → confidence 提升
 */

import { describe, expect, test } from 'bun:test';
import { fuzzyMatchLine, fuzzyMatchAll, type MatchResult } from '../../../src/math/application/matching';

describe('matching > fuzzyMatchLine', () => {
  test('returns match result with signals', () => {
    const code = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM users WHERE id=" + id;',
      'db.query(q);',
    ];
    const r: MatchResult = fuzzyMatchLine(code, 2, 0.95);
    expect(r.confidence).toBeGreaterThan(0);
    expect(r.confidence).toBeLessThanOrEqual(1);
    expect(r.signals).toBeDefined();
    expect(typeof r.signals.combinedFactor).toBe('number');
  });

  test('taint source → confidence boosted', () => {
    const withTaint = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM users WHERE id=" + id;',
    ];
    const withoutTaint = [
      'const x = 5;',
      'const q = "SELECT * FROM users WHERE id=" + x;',
    ];
    const a = fuzzyMatchLine(withTaint, 2, 0.5);
    const b = fuzzyMatchLine(withoutTaint, 2, 0.5);
    // taint 路径应该让 factor > 1, 所以 a.confidence > 0.5
    expect(a.confidence).toBeGreaterThanOrEqual(b.confidence);
  });

  test('out of range returns zero', () => {
    const code = ['const x = 1;'];
    const r = fuzzyMatchLine(code, 100, 0.5);
    expect(r.confidence).toBe(0);
    expect(r.shouldReport).toBe(false);
  });

  test('loop context boosts confidence', () => {
    const inLoop = [
      'for (let i = 0; i < 10; i++) {',
      '  const id = req.params.id;',
      '  db.query("SELECT * FROM t WHERE id=" + id);',
      '}',
    ];
    const notInLoop = [
      'const id = req.params.id;',
      'db.query("SELECT * FROM t WHERE id=" + id);',
    ];
    const a = fuzzyMatchLine(inLoop, 3, 0.5);
    const b = fuzzyMatchLine(notInLoop, 2, 0.5);
    expect(a.signals.inLoop).toBe(true);
    expect(b.signals.inLoop).toBe(false);
    expect(a.confidence).toBeGreaterThan(b.confidence);
  });

  test('uninitialized variable use is flagged', () => {
    const code = [
      'console.log(x);',           // line 1: use x without def
      'const x = 1;',
    ];
    const r = fuzzyMatchLine(code, 1, 0.5);
    expect(r.signals.hasUninitialized).toBe(true);
  });

  test('explanation is non-empty when factors activate', () => {
    const code = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM users WHERE id=" + id;',
    ];
    const r = fuzzyMatchLine(code, 2, 0.5);
    expect(r.explanation.length).toBeGreaterThan(0);
  });
});

describe('matching > fuzzyMatchAll', () => {
  test('processes all candidates', () => {
    const code = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM users WHERE id=" + id;',
      'db.query(q);',
    ];
    const cands = [
      { line: 2, vulnType: 'sql_injection', patternBase: 0.95 },
      { line: 3, vulnType: 'sql_injection', patternBase: 0.95 },
    ];
    const results = fuzzyMatchAll(cands, code);
    expect(results.length).toBe(2);
    expect(results[0].line).toBe(2);
    expect(results[1].line).toBe(3);
  });
});

describe('matching > factor composition', () => {
  test('confidence is bounded [0, 1]', () => {
    const code = [
      'for (let i = 0; i < 10; i++) {',
      '  const id = req.params.id;',
      '  for (let j = 0; j < 5; j++) {',
      '    console.log(uninit);',      // uninit + nested loop + token overlap
      '  }',
      '}',
    ];
    const r = fuzzyMatchLine(code, 4, 0.95);
    expect(r.confidence).toBeGreaterThanOrEqual(0);
    expect(r.confidence).toBeLessThanOrEqual(1);
  });

  test('low pattern base clamps confidence low', () => {
    const code = ['const x = 1;', 'console.log(x);'];
    const r = fuzzyMatchLine(code, 2, 0.05);  // 5% pattern base
    expect(r.confidence).toBeLessThan(0.5);
  });
});
