import { describe, it, expect } from 'bun:test';
import { evaluate, computeMetrics, formatReport, SYNTHETIC_DATASET, type BenchmarkSample, type DetectionOutput } from '../../../src/benchmark/index.js';

describe('Benchmark Evaluator', () => {
  it('computes metrics correctly for perfect detection', () => {
    const result = computeMetrics(10, 0, 0, 10);
    expect(result.precision).toBe(1);
    expect(result.recall).toBe(1);
    expect(result.f1).toBe(1);
    expect(result.accuracy).toBe(1);
  });

  it('computes metrics for mixed results', () => {
    const result = computeMetrics(8, 2, 3, 7);
    expect(result.precision).toBeCloseTo(8 / 10);
    expect(result.recall).toBeCloseTo(8 / 11);
    expect(result.f1).toBeGreaterThan(0);
  });

  it('handles zero division gracefully', () => {
    const result = computeMetrics(0, 0, 0, 0);
    expect(result.precision).toBe(0);
    expect(result.recall).toBe(0);
    expect(result.f1).toBe(0);
  });

  it('evaluates against synthetic dataset', () => {
    const samples: BenchmarkSample[] = [
      { id: 't1', code: 'db.query(sql + input)', language: 'javascript', isVulnerable: true, cwe: ['CWE-89'] },
      { id: 't2', code: 'function safe() { return 1; }', language: 'javascript', isVulnerable: false },
    ];

    const detections: DetectionOutput[] = [
      { sampleId: 't1', detected: true, confidence: 0.9, ruleIds: ['INJ-001'] },
      { sampleId: 't2', detected: false, confidence: 0, ruleIds: [] },
    ];

    const result = evaluate(samples, detections, { minConfidence: 0.5 });
    expect(result.tp).toBe(1);
    expect(result.tn).toBe(1);
    expect(result.precision).toBe(1);
    expect(result.recall).toBe(1);
    expect(result.totalSamples).toBe(2);
  });

  it('evaluates with false positives', () => {
    const samples: BenchmarkSample[] = [
      { id: 't1', code: 'safe code', language: 'javascript', isVulnerable: false },
    ];

    const detections: DetectionOutput[] = [
      { sampleId: 't1', detected: true, confidence: 0.8, ruleIds: ['INJ-001'] },
    ];

    const result = evaluate(samples, detections);
    expect(result.fp).toBe(1);
    expect(result.precision).toBe(0);
  });

  it('formats report correctly', () => {
    const result = evaluate(
      [{ id: 't1', code: 'test', language: 'javascript', isVulnerable: true }],
      [{ sampleId: 't1', detected: true, confidence: 0.9, ruleIds: ['INJ-001'] }],
    );

    const report = formatReport(result);
    expect(report).toContain('Precision');
    expect(report).toContain('Recall');
    expect(report).toContain('F1');
  });

  it('synthetic dataset has expected structure', () => {
    expect(SYNTHETIC_DATASET.length).toBeGreaterThanOrEqual(15);

    const vuln = SYNTHETIC_DATASET.filter(s => s.isVulnerable);
    const safe = SYNTHETIC_DATASET.filter(s => !s.isVulnerable);
    expect(vuln.length).toBeGreaterThan(safe.length);

    const withCwe = SYNTHETIC_DATASET.filter(s => s.cwe && s.cwe.length > 0);
    expect(withCwe.length).toBeGreaterThan(0);
  });
});
