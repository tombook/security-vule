/**
 * tests/unit/math/run-evaluate.test.ts — 真实 GT 评估器单元测试
 *
 * 数学等价验证 (math-underneath §1.4 验证闭环):
 *   - 精确匹配 → TP
 *   - fuzz ±3 行匹配 → TP
 *   - fuzz > 3 → FN
 *   - type family mapping (rce ↔ command_injection 等)
 *   - 同 (file, type) 多 predict → 1 TP + N FP
 *   - Precision/Recall/F1 公式正确
 *   - 空输入 → 0
 */

import { describe, test, expect } from 'bun:test';
import { evaluate, type GroundTruthFinding } from '../../../src/math/pipeline/run-evaluate.js';
import type { VulnerabilityReport } from '../../../src/math/application/patterns.js';

function makeReport(file: string, line: number, type: string, score = 50): VulnerabilityReport {
  return { file, line, type, severity: 'high', score, message: type, suggestion: '', source: '' };
}
function makeGT(file: string, line: number, type: string): GroundTruthFinding {
  return { file, line, type };
}

describe('run-evaluate > evaluate()', () => {
  test('精确匹配 → TP=1, FP=0, FN=0', () => {
    const r = evaluate(
      [makeReport('a.js', 5, 'sql_injection')],
      [makeGT('a.js', 5, 'sql_injection')]
    );
    expect(r.true_positives).toBe(1);
    expect(r.false_positives).toBe(0);
    expect(r.false_negatives).toBe(0);
  });

  test('fuzz ±3 → TP=1, fuzzHits=1', () => {
    const r = evaluate(
      [makeReport('a.js', 8, 'sql_injection')],
      [makeGT('a.js', 5, 'sql_injection')]
    );
    expect(r.true_positives).toBe(1);
    expect(r.fuzzHits).toBe(1);
  });

  test('fuzz ±5 → FN=1', () => {
    const r = evaluate(
      [makeReport('a.js', 10, 'sql_injection')],
      [makeGT('a.js', 5, 'sql_injection')]
    );
    expect(r.false_negatives).toBe(1);
  });

  test('family mapping: rce ↔ command_injection → TP', () => {
    const r = evaluate(
      [makeReport('a.js', 5, 'rce')],
      [makeGT('a.js', 5, 'command_injection')]
    );
    expect(r.true_positives).toBe(1);
  });

  test('family mapping: xss ↔ cross_site_scripting → TP', () => {
    const r = evaluate(
      [makeReport('a.js', 5, 'xss')],
      [makeGT('a.js', 5, 'cross_site_scripting')]
    );
    expect(r.true_positives).toBe(1);
  });

  test('family mapping: weak_crypto ↔ cryptographic_failures → TP', () => {
    const r = evaluate(
      [makeReport('a.js', 5, 'weak_crypto')],
      [makeGT('a.js', 5, 'cryptographic_failures')]
    );
    expect(r.true_positives).toBe(1);
  });

  test('多 predict 命中同 GT → 1 TP + N FP', () => {
    const r = evaluate(
      [
        makeReport('a.js', 5, 'sql_injection'),
        makeReport('a.js', 6, 'sql_injection'),
        makeReport('a.js', 7, 'sql_injection'),
      ],
      [makeGT('a.js', 5, 'sql_injection')]
    );
    expect(r.true_positives).toBe(1);
    expect(r.false_positives).toBe(2);
  });

  test('Precision/Recall/F1 公式正确 (TP=1, FP=1, FN=1 → P=R=F1=0.5)', () => {
    const r = evaluate(
      [
        makeReport('a.js', 5, 'sql_injection'),
        makeReport('a.js', 10, 'xss'),
      ],
      [
        makeGT('a.js', 5, 'sql_injection'),
        makeGT('b.js', 5, 'rce'),
      ]
    );
    expect(r.precision).toBeCloseTo(0.5, 2);
    expect(r.recall).toBeCloseTo(0.5, 2);
    expect(r.f1).toBeCloseTo(0.5, 2);
  });

  test('空输入 → 全部为 0', () => {
    const r = evaluate([], []);
    expect(r.true_positives).toBe(0);
    expect(r.false_positives).toBe(0);
    expect(r.false_negatives).toBe(0);
    expect(r.f1).toBe(0);
  });

  test('file basename 匹配 (绝对路径 vs basename)', () => {
    const r = evaluate(
      [makeReport('/path/to/a.js', 5, 'sql_injection')],
      [makeGT('a.js', 5, 'sql_injection')]
    );
    expect(r.true_positives).toBe(1);
  });
});
