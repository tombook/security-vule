/**
 * tests/unit/math/taint.test.ts — 污点分析单元测试
 *
 * 数学等价验证 (math-underneath.md §1):
 *   - source/sink 分类与 confidence 排序
 *   - 路径搜索的行索引单调性
 *   - sanitizer 对 confidence 的削弱作用
 */

import { describe, expect, test } from 'bun:test';
import {
  analyzeTaint,
  classifyLine,
  extractVariable,
  findTaintPaths,
  sinkConfidence,
} from '../../../src/math/execution/taint';

describe('taint > classifyLine', () => {
  test('detects user_input source', () => {
    const r = classifyLine('const id = req.params.id;', 1);
    expect(r.sources.length).toBeGreaterThan(0);
    expect(r.sources[0].type).toBe('user_input');
    expect(r.sources[0].variable).toBe('id');
    expect(r.sources[0].confidence).toBeGreaterThan(0.5);
  });

  test('detects SQL sink (strict mode)', () => {
    const r = classifyLine('const q = "SELECT * FROM t WHERE id=" + id;', 1);
    expect(r.sinks.some(s => s.type === 'sql')).toBe(true);
  });

  test('detects eval sink', () => {
    const r = classifyLine('eval(req.query.code);', 1);
    expect(r.sinks.some(s => s.type === 'eval')).toBe(true);
  });

  test('detects sanitizer (param_check)', () => {
    const r = classifyLine('const q = "SELECT * FROM t WHERE id=?"; db.query(q, [id]);', 1);
    expect(r.sanitizers.length).toBeGreaterThan(0);
  });

  test('extractVariable captures lhs of assignment', () => {
    expect(extractVariable('const id = req.params.id;')).toBe('id');
    expect(extractVariable('let x = 5;')).toBe('x');
    expect(extractVariable('// comment')).toBeUndefined();
  });
});

describe('taint > findTaintPaths', () => {
  test('finds source→sink path across lines', () => {
    const code = [
      'const id = req.params.id;',                                    // line 1: source
      'const q = "SELECT * FROM t WHERE id = " + id;',                 // line 2: sql concat
      'db.query(q);',                                                  // line 3: sql sink
    ];
    const paths = findTaintPaths(code);
    expect(paths.length).toBeGreaterThan(0);
    // 应该有从 line 1 → line 3 的路径
    const p = paths.find(pp => pp.source.line === 1 && pp.sink.line === 3);
    expect(p).toBeDefined();
    expect(p!.confidence).toBeGreaterThan(0.4);
  });

  test('confidence decreases with sanitizers', () => {
    const codeWithSan = [
      'const id = req.params.id;',
      'if (validate(id)) {',                                          // sanitizer
        '  const q = "SELECT * FROM t WHERE id=" + id;',
        '  db.query(q);',
        '}',
    ];
    const codeNoSan = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM t WHERE id=" + id;',
      'db.query(q);',
    ];
    const pathsWith = findTaintPaths(codeWithSan);
    const pathsNo = findTaintPaths(codeNoSan);
    const confWith = pathsWith[0]?.confidence ?? 1;
    const confNo = pathsNo[0]?.confidence ?? 1;
    expect(confWith).toBeLessThanOrEqual(confNo);
  });

  test('no path when no source/sink', () => {
    const code = ['const x = 1;', 'const y = 2;'];
    expect(findTaintPaths(code).length).toBe(0);
  });

  test('paths sorted by confidence descending', () => {
    const code = [
      'const id = req.params.id;',
      'const a = "ls " + id;',
      'exec(a);',
      'const q = "SELECT * FROM t WHERE id=" + id;',
      'db.query(q);',
    ];
    const paths = findTaintPaths(code);
    for (let i = 1; i < paths.length; i++) {
      expect(paths[i - 1].confidence).toBeGreaterThanOrEqual(paths[i].confidence);
    }
  });
});

describe('taint > analyzeTaint', () => {
  test('returns maxConfidence and pathCount', () => {
    const code = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM t WHERE id=" + id;',
      'db.query(q);',
    ];
    const r = analyzeTaint(code);
    expect(r.pathCount).toBeGreaterThan(0);
    expect(r.maxConfidence).toBeGreaterThan(0);
    expect(r.maxConfidence).toBeLessThanOrEqual(1);
  });
});

describe('taint > sinkConfidence', () => {
  test('returns 0 when no source before sink', () => {
    const code = ['const q = "SELECT 1";', 'db.query(q);'];
    expect(sinkConfidence(code, 2)).toBe(0);
  });

  test('returns positive when source before sink', () => {
    const code = [
      'const id = req.params.id;',
      'const q = "SELECT * FROM t WHERE id = " + id;',
      'db.query(q);',
    ];
    const c = sinkConfidence(code, 3);
    expect(c).toBeGreaterThan(0);
    expect(c).toBeLessThanOrEqual(1);
  });
});
