/**
 * CosmX Project Analyzer v2.5 dedup & filter unit tests
 * 验证去重 + 置信度过滤 + 注释跳过逻辑
 */
import { describe, test, expect } from 'bun:test';
import {
  isInComment,
  deduplicateByFileType,
  deduplicateByFileLineType,
  filterByMinScore,
} from '../../../src/math/cosm-x-dedup.js';

function mkReport(over: Partial<{
  file: string;
  line: number;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  score: number;
  uvrs: { unified_score: number; risk_level: string; top_risk_dimensions: string[]; classification: string; confidence: number; dimension_scores: Record<string, number>; metadata: Record<string, unknown>; } | undefined;
}> = {}) {
  return {
    project: 'p',
    file: over.file ?? 'a.js',
    line: over.line ?? 1,
    type: over.type ?? 'sql_injection',
    severity: over.severity ?? 'high',
    description: 'd',
    code: 'x',
    score: over.score ?? 50,
    uvrs: over.uvrs,
  };
}

describe('isInComment', () => {
  test('// 行注释 (JS/TS/Java)', () => {
    expect(isInComment('// password = "secret123"', '.js')).toBe(true);
    expect(isInComment('  // password = "secret123"', '.ts')).toBe(true);
    expect(isInComment('* 这是块注释内一行', '.java')).toBe(true);
    expect(isInComment('/* block start', '.js')).toBe(true);
  });
  test('# 行注释 (Python/Ruby)', () => {
    expect(isInComment('# password = "secret123"', '.py')).toBe(true);
    expect(isInComment('  # token = "abc123"', '.rb')).toBe(true);
  });
  test('行内注释也算 (整行有 //)', () => {
    expect(isInComment('let x = 1; // password = "abc"', '.js')).toBe(true);
  });
  test('普通代码行', () => {
    expect(isInComment('let password = "secret123";', '.js')).toBe(false);
    expect(isInComment('const password = "secret123"', '.ts')).toBe(false);
    expect(isInComment('password = "secret123"', '.py')).toBe(false);
    expect(isInComment('api_key = "longapikey1234567890"', '.rb')).toBe(false);
  });
});

describe('deduplicateByFileType', () => {
  test('同 file + 同 type 多个 reports 合并为 1 (保留最高 score)', () => {
    const reports = [
      mkReport({ file: 'a.js', line: 1, type: 'sql_injection', score: 30 }),
      mkReport({ file: 'a.js', line: 5, type: 'sql_injection', score: 80 }),
      mkReport({ file: 'a.js', line: 10, type: 'sql_injection', score: 50 }),
    ];
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(1);
    expect(out[0]!.line).toBe(5);
    expect(out[0]!.score).toBe(80);
  });
  test('同 file + 不同 type 不去重', () => {
    const reports = [
      mkReport({ file: 'a.js', type: 'sql_injection', score: 50 }),
      mkReport({ file: 'a.js', type: 'xss', score: 60 }),
      mkReport({ file: 'a.js', type: 'hardcoded_secret', score: 70 }),
    ];
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(3);
  });
  test('不同 file + 同 type 不去重', () => {
    const reports = [
      mkReport({ file: 'a.js', type: 'sql_injection', score: 50 }),
      mkReport({ file: 'b.js', type: 'sql_injection', score: 60 }),
    ];
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(2);
  });
  test('UVRS unified_score 优先于 score 字段', () => {
    const reports = [
      mkReport({ file: 'a.js', line: 1, type: 'sqli', score: 90, uvrs: { unified_score: 20, risk_level: 'low', top_risk_dimensions: [], classification: 'noise', confidence: 0.1, dimension_scores: {}, metadata: {} } }),
      mkReport({ file: 'a.js', line: 2, type: 'sqli', score: 30, uvrs: { unified_score: 85, risk_level: 'critical', top_risk_dimensions: [], classification: 'confirmed', confidence: 0.9, dimension_scores: {}, metadata: {} } }),
    ];
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(1);
    expect(out[0]!.line).toBe(2);
  });
  test('同分用 severity 决断 (高 severity 胜出)', () => {
    const reports = [
      mkReport({ file: 'a.js', line: 1, type: 'sqli', severity: 'low', score: 50, uvrs: { unified_score: 50, risk_level: 'low', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
      mkReport({ file: 'a.js', line: 2, type: 'sqli', severity: 'critical', score: 50, uvrs: { unified_score: 50, risk_level: 'critical', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
    ];
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(1);
    expect(out[0]!.severity).toBe('critical');
  });
  test('空数组返回空', () => {
    expect(deduplicateByFileType([])).toEqual([]);
  });
  test('WebGoat 场景: 同一文件 100+ sql_injection findings → 1 个', () => {
    const reports: any[] = [];
    for (let i = 0; i < 200; i++) {
      reports.push(mkReport({ file: 'lesson.java', line: i, type: 'sql_injection', score: 50 }));
    }
    const out = deduplicateByFileType(reports);
    expect(out.length).toBe(1);
  });
});

describe('deduplicateByFileLineType', () => {
  test('同 file + 同 line + 同 type 合并', () => {
    const reports = [
      mkReport({ file: 'a.js', line: 5, type: 'sqli', score: 30 }),
      mkReport({ file: 'a.js', line: 5, type: 'sqli', score: 80 }),
    ];
    const out = deduplicateByFileLineType(reports);
    expect(out.length).toBe(1);
  });
  test('同 line 不同 type 保留', () => {
    const reports = [
      mkReport({ file: 'a.js', line: 5, type: 'sqli' }),
      mkReport({ file: 'a.js', line: 5, type: 'xss' }),
    ];
    const out = deduplicateByFileLineType(reports);
    expect(out.length).toBe(2);
  });
});

describe('filterByMinScore', () => {
  test('minScore=0 不过滤', () => {
    const reports = [mkReport({ score: 1 }), mkReport({ score: 99 })];
    expect(filterByMinScore(reports, 0).length).toBe(2);
  });
  test('UVRS informative 时优先于 score 字段 (UVRS < 0.1 fallback score)', () => {
    const reports = [
      // 6 维 score 高 (90) 但 UVRS 低 (0.2 → 20/100) → UVRS informative, 用 20 → < 50 → 过滤
      mkReport({ score: 90, uvrs: { unified_score: 0.2, risk_level: 'low', top_risk_dimensions: [], classification: 'noise', confidence: 0.1, dimension_scores: {}, metadata: {} } }),
      // 6 维 score 低 (30) 但 UVRS 高 (0.85 → 85/100) → 用 85 → 通过
      mkReport({ score: 30, uvrs: { unified_score: 0.85, risk_level: 'critical', top_risk_dimensions: [], classification: 'confirmed', confidence: 0.9, dimension_scores: {}, metadata: {} } }),
    ];
    const out = filterByMinScore(reports, 50);
    expect(out.length).toBe(1);  // 只有 UVRS=85 的通过
    expect(out[0]!.uvrs!.unified_score).toBe(0.85);
  });
  test('UVRS < 0.1 (broken) 时回退 6 维 score', () => {
    const reports = [
      // UVRS = 0.05 → ×100 = 5, < 10 (broken) → 用 score 80 → 通过
      mkReport({ score: 80, uvrs: { unified_score: 0.05, risk_level: 'low', top_risk_dimensions: [], classification: 'noise', confidence: 0.1, dimension_scores: {}, metadata: {} } }),
      // UVRS = 0.05 → ×100 = 5, < 10 (broken) → 用 score 20 → 过滤
      mkReport({ score: 20, uvrs: { unified_score: 0.05, risk_level: 'low', top_risk_dimensions: [], classification: 'noise', confidence: 0.1, dimension_scores: {}, metadata: {} } }),
    ];
    const out = filterByMinScore(reports, 50);
    expect(out.length).toBe(1);
    expect(out[0]!.score).toBe(80);
  });
  test('UVRS < 0.1 (10/100) 时回退 6 维 score, 否则用 UVRS', () => {
    const reports = [
      // UVRS = 0.01 → ×100 = 1, < 10 → 用 score 80 → 通过 min-score=50
      mkReport({ score: 80, uvrs: { unified_score: 0.01, risk_level: 'low', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
      // UVRS = 0.05 → ×100 = 5, < 10 → 用 score 20 → 过滤掉
      mkReport({ score: 20, uvrs: { unified_score: 0.05, risk_level: 'low', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
      // UVRS = 0.4 → ×100 = 40, >= 10 → 用 UVRS=40 → 过滤掉 (min-score=50)
      mkReport({ score: 100, uvrs: { unified_score: 0.4, risk_level: 'high', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
      // UVRS = 0.6 → ×100 = 60, >= 10 → 用 UVRS=60 → 通过
      mkReport({ score: 100, uvrs: { unified_score: 0.6, risk_level: 'critical', top_risk_dimensions: [], classification: '', confidence: 0, dimension_scores: {}, metadata: {} } }),
    ];
    const out = filterByMinScore(reports, 50);
    expect(out.length).toBe(2);  // 80 (UVRS broken → score 80) + 60 (UVRS)
  });
  test('阈值过滤掉所有低于阈值的', () => {
    const reports = [
      mkReport({ score: 30 }),
      mkReport({ score: 40 }),
      mkReport({ score: 60 }),
      mkReport({ score: 80 }),
    ];
    const out = filterByMinScore(reports, 50);
    expect(out.length).toBe(2);
  });
  test('高阈值过滤所有', () => {
    const reports = [mkReport({ score: 30 }), mkReport({ score: 40 })];
    expect(filterByMinScore(reports, 100).length).toBe(0);
  });
});

describe('组合效果: 真实场景压测', () => {
  test('WebGoat 类场景: 2018 findings → 强烈压缩', () => {
    // 模拟 50 个 lesson 文件, 每个文件 5 种漏洞类型, 每种 8 行
    const reports: any[] = [];
    const types = ['sql_injection', 'xss', 'hardcoded_secret', 'broken_access_control', 'command_injection'];
    for (let f = 0; f < 50; f++) {
      for (const t of types) {
        for (let l = 0; l < 8; l++) {
          reports.push(mkReport({ file: `lesson${f}.java`, line: l * 10, type: t, score: 30 + (l * 5) }));
        }
      }
    }
    expect(reports.length).toBe(2000);
    const deduped = deduplicateByFileType(reports);
    expect(deduped.length).toBe(250);  // 50 files × 5 types
    const filtered = filterByMinScore(deduped, 50);
    expect(filtered.length).toBeLessThanOrEqual(250);
  });
});
