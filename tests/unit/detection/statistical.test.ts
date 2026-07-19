import { describe, test, expect } from 'bun:test';
import {
  oneClassSVMscore,
  dbscan,
  detectStatisticalAnomaly,
  detectComplexityAnomalies,
  computeAnomalyScore,
  type CodeComplexityFeatures,
} from '../../../src/detection/statistical.js';

describe('statistical: oneClassSVMscore', () => {
  test('returns array of scores', () => {
    const data = [[1, 2], [3, 4], [5, 6]];
    const scores = oneClassSVMscore(data, 0.1);
    expect(scores).toBeArray();
    expect(scores.length).toBe(3);
  });

  test('scores are in [0, 1] after normalization', () => {
    const data = [[1, 1], [2, 2], [100, 100]];
    const scores = oneClassSVMscore(data, 0.1);
    for (const s of scores) {
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThanOrEqual(1);
    }
  });

  test('outliers get higher scores', () => {
    const data = [[0, 0], [0.1, 0.1], [10, 10]];
    const scores = oneClassSVMscore(data, 0.1);
    expect(scores[2]).toBeGreaterThan(scores[0]);
  });

  test('single point data', () => {
    const data = [[5, 5]];
    const scores = oneClassSVMscore(data, 0.1);
    expect(scores.length).toBe(1);
  });
});

describe('statistical: dbscan', () => {
  test('returns labels, outliers, clusters', () => {
    const data = [[0, 0], [0.1, 0.1], [10, 10]];
    const result = dbscan(data, 0.5, 2);
    expect(result.labels).toBeArray();
    expect(result.outliers).toBeArray();
    expect(result.clusters).toBeArray();
  });

  test('dense cluster forms one cluster', () => {
    const data = [[0, 0], [0.1, 0.1], [0.2, 0.2], [0.15, 0.15]];
    const result = dbscan(data, 0.5, 3);
    expect(result.labels.length).toBe(4);
  });

  test('isolated points are outliers', () => {
    const data = [[0, 0], [100, 100]];
    const result = dbscan(data, 0.5, 2);
    expect(result.outliers.length).toBeGreaterThan(0);
  });
});

describe('statistical: detectStatisticalAnomaly', () => {
  test('returns array of anomaly results', () => {
    const features = [[1, 2, 3], [4, 5, 6], [100, 100, 100]];
    const result = detectStatisticalAnomaly(features, 2.0);
    expect(result).toBeArray();
  });

  test('detects z-score outliers', () => {
    const features = [[1, 1], [1, 1], [1, 1], [100, 100]];
    const result = detectStatisticalAnomaly(features, 2.0);
    expect(result.length).toBeGreaterThan(0);
  });

  test('empty data returns empty array', () => {
    const result = detectStatisticalAnomaly([], 2.0);
    expect(result.length).toBe(0);
  });
});

describe('statistical: detectComplexityAnomalies', () => {
  test('returns array of anomaly results', () => {
    const features: CodeComplexityFeatures[] = [
      { cyclomatic: 1, cognitive: 1, halstead: 10, linesOfCode: 20, parameterCount: 2, nestingDepth: 1 },
    ];
    const result = detectComplexityAnomalies(features);
    expect(result).toBeArray();
  });

  test('detects high cyclomatic complexity', () => {
    const features: CodeComplexityFeatures[] = [
      { cyclomatic: 1, cognitive: 1, halstead: 10, linesOfCode: 20, parameterCount: 2, nestingDepth: 1 },
      { cyclomatic: 50, cognitive: 50, halstead: 500, linesOfCode: 500, parameterCount: 10, nestingDepth: 8 },
    ];
    const result = detectComplexityAnomalies(features);
    expect(result.length).toBeGreaterThan(0);
  });

  test('empty input returns empty', () => {
    const result = detectComplexityAnomalies([]);
    expect(result.length).toBe(0);
  });
});

describe('statistical: computeAnomalyScore', () => {
  test('returns object with combined score', () => {
    const features = [[1, 2, 3]];
    const result = computeAnomalyScore(features);
    expect(result).toBeDefined();
    expect(typeof result.combined).toBe('number');
  });

  test('uses custom weights', () => {
    const features = [[1, 2, 3]];
    const result = computeAnomalyScore(features, [0.5, 0.3, 0.2]);
    expect(result).toBeDefined();
  });

  test('empty features returns 0', () => {
    const result = computeAnomalyScore([]);
    expect(result.combined).toBe(0);
  });
});
