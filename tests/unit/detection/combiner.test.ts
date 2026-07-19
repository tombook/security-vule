import { describe, test, expect } from 'bun:test';
import {
  combinePatternStatistical,
  addMLResults,
  recalculateScores,
  aggregateScores,
  rankDetections,
  filterBySeverity,
  mergeDetections,
  finalizeDetection,
  getTopByMethod,
  DEFAULT_WEIGHTS,
  type DetectionResult,
  type CombinedDetection,
} from '../../../src/detection/combiner.js';

function makePatternResult(overrides: Partial<DetectionResult> = {}): DetectionResult {
  return {
    ruleId: 'P-1',
    name: 'Pattern 1',
    severity: 'high',
    confidence: 0.8,
    location: 'file.py:10',
    message: 'test',
    ...overrides,
  };
}

describe('combiner: combinePatternStatistical', () => {
  test('combines pattern and statistical results', () => {
    const pattern: DetectionResult[] = [makePatternResult()];
    const stat: DetectionResult[] = [makePatternResult({ ruleId: 'S-1' })];
    const result = combinePatternStatistical(pattern, stat);
    expect(result.length).toBe(2);
  });

  test('merges results with same ruleId', () => {
    const pattern: DetectionResult[] = [makePatternResult({ ruleId: 'P-1', confidence: 0.7 })];
    const stat: DetectionResult[] = [makePatternResult({ ruleId: 'P-1', confidence: 0.9 })];
    const result = combinePatternStatistical(pattern, stat);
    expect(result.length).toBe(1);
    expect(result[0].methods).toContain('pattern');
    expect(result[0].methods).toContain('statistical');
  });

  test('handles empty inputs', () => {
    expect(combinePatternStatistical([], []).length).toBe(0);
  });
});

describe('combiner: addMLResults', () => {
  test('adds ML results to existing combined detections', () => {
    const combined: CombinedDetection[] = [{
      ruleId: 'P-1',
      name: 'Test',
      severity: 'high',
      scores: { pattern: 0.8, statistical: 0, ml: 0 },
      combinedScore: 0.24,
      confidence: 0.8,
      methods: ['pattern'],
    }];
    const result = addMLResults(combined, [{ ruleId: 'P-1', confidence: 0.9 }]);
    expect(result.length).toBe(1);
    expect(result[0].scores.ml).toBe(0.9);
    expect(result[0].methods).toContain('ml');
  });

  test('creates new entry for new ML rule', () => {
    const result = addMLResults([], [{ ruleId: 'ML-1', confidence: 0.85 }]);
    expect(result.length).toBe(1);
    expect(result[0].name).toBe('ML-detected');
  });
});

describe('combiner: recalculateScores', () => {
  test('recalculates with default weights', () => {
    const detections: CombinedDetection[] = [{
      ruleId: 'T-1', name: 'T', severity: 'high',
      scores: { pattern: 0.5, statistical: 0.5, ml: 0.5 },
      combinedScore: 0, confidence: 0,
      methods: ['pattern', 'statistical', 'ml'],
    }];
    const result = recalculateScores(detections);
    expect(result[0].combinedScore).toBeGreaterThan(0);
  });

  test('uses custom weights', () => {
    const detections: CombinedDetection[] = [{
      ruleId: 'T-1', name: 'T', severity: 'high',
      scores: { pattern: 1.0, statistical: 0, ml: 0 },
      combinedScore: 0, confidence: 0,
      methods: ['pattern'],
    }];
    const result = recalculateScores(detections, { pattern: 1.0, statistical: 0, ml: 0 });
    expect(result[0].combinedScore).toBe(1.0);
  });
});

describe('combiner: aggregateScores', () => {
  test('returns VulnerabilityScore with all fields', () => {
    const detections: CombinedDetection[] = [{
      ruleId: 'T-1', name: 'T', severity: 'critical',
      scores: { pattern: 0.9, statistical: 0, ml: 0 },
      combinedScore: 0.27, confidence: 0.9,
      methods: ['pattern'],
    }];
    const result = aggregateScores(detections);
    expect(result.overall).toBeGreaterThan(0);
    expect(result.pattern).toBe(0.9);
    expect(result.severityBreakdown.critical).toBe(1);
  });

  test('empty detections return zero', () => {
    const result = aggregateScores([]);
    expect(result.overall).toBe(0);
    expect(result.confidence).toBe(0);
  });
});

describe('combiner: rankDetections', () => {
  test('sorts by combinedScore descending', () => {
    const detections: CombinedDetection[] = [
      { ruleId: 'A', name: 'A', severity: 'low', scores: { pattern: 0.1, statistical: 0, ml: 0 }, combinedScore: 0.1, confidence: 0.1, methods: ['pattern'] },
      { ruleId: 'B', name: 'B', severity: 'high', scores: { pattern: 0.9, statistical: 0, ml: 0 }, combinedScore: 0.9, confidence: 0.9, methods: ['pattern'] },
    ];
    const ranked = rankDetections(detections);
    expect(ranked[0].ruleId).toBe('B');
    expect(ranked[1].ruleId).toBe('A');
  });

  test('respects limit parameter', () => {
    const detections: CombinedDetection[] = [
      { ruleId: 'A', name: 'A', severity: 'low', scores: { pattern: 0.1, statistical: 0, ml: 0 }, combinedScore: 0.1, confidence: 0.1, methods: ['pattern'] },
      { ruleId: 'B', name: 'B', severity: 'high', scores: { pattern: 0.9, statistical: 0, ml: 0 }, combinedScore: 0.9, confidence: 0.9, methods: ['pattern'] },
    ];
    expect(rankDetections(detections, 1).length).toBe(1);
  });
});

describe('combiner: filterBySeverity', () => {
  test('filters by minimum severity', () => {
    const detections: CombinedDetection[] = [
      { ruleId: 'A', name: 'A', severity: 'low', scores: { pattern: 0.5, statistical: 0, ml: 0 }, combinedScore: 0.5, confidence: 0.5, methods: ['pattern'] },
      { ruleId: 'B', name: 'B', severity: 'critical', scores: { pattern: 0.9, statistical: 0, ml: 0 }, combinedScore: 0.9, confidence: 0.9, methods: ['pattern'] },
    ];
    const filtered = filterBySeverity(detections, 'high');
    expect(filtered.length).toBe(1);
    expect(filtered[0].severity).toBe('critical');
  });

  test('keeps all when filtering by info', () => {
    const detections: CombinedDetection[] = [
      { ruleId: 'A', name: 'A', severity: 'info', scores: { pattern: 0.1, statistical: 0, ml: 0 }, combinedScore: 0.1, confidence: 0.1, methods: ['pattern'] },
    ];
    expect(filterBySeverity(detections, 'info').length).toBe(1);
  });
});

describe('combiner: mergeDetections', () => {
  test('merges results from multiple sources', () => {
    const map = new Map<string, DetectionResult[]>();
    map.set('pattern', [makePatternResult({ ruleId: 'P-1' })]);
    map.set('statistical', [makePatternResult({ ruleId: 'S-1' })]);
    const result = mergeDetections(map);
    expect(result.length).toBe(2);
  });
});

describe('combiner: finalizeDetection', () => {
  test('recalculates combinedScore and confidence', () => {
    const d: CombinedDetection = {
      ruleId: 'T-1', name: 'T', severity: 'high',
      scores: { pattern: 0.5, statistical: 0.5, ml: 0.5 },
      combinedScore: 0, confidence: 0,
      methods: ['pattern', 'statistical', 'ml'],
    };
    const result = finalizeDetection(d);
    expect(result.combinedScore).toBeGreaterThan(0);
    expect(result.confidence).toBeGreaterThan(0);
  });
});

describe('combiner: getTopByMethod', () => {
  test('returns top N by method', () => {
    const detections: CombinedDetection[] = [
      { ruleId: 'A', name: 'A', severity: 'low', scores: { pattern: 0.1, statistical: 0, ml: 0 }, combinedScore: 0.1, confidence: 0.1, methods: ['pattern'] },
      { ruleId: 'B', name: 'B', severity: 'high', scores: { pattern: 0.9, statistical: 0, ml: 0 }, combinedScore: 0.9, confidence: 0.9, methods: ['pattern'] },
    ];
    const top = getTopByMethod(detections, 'pattern', 1);
    expect(top.length).toBe(1);
    expect(top[0].ruleId).toBe('B');
  });
});

describe('combiner: DEFAULT_WEIGHTS', () => {
  test('weights sum to 1.0', () => {
    const total = DEFAULT_WEIGHTS.pattern + DEFAULT_WEIGHTS.statistical + DEFAULT_WEIGHTS.ml;
    expect(Math.abs(total - 1.0)).toBeLessThan(0.001);
  });
});
