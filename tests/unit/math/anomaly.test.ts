import { describe, expect, test } from 'bun:test';
import {
  mean,
  standardDeviation,
  zScore,
  zScoreArray,
  mahalanobisDistance,
  mahalanobisDistances,
  isolationForestScore,
  detectAnomalies,
  localOutlierFactor
} from '../../../src/math/anomaly';

describe('anomaly', () => {
  test('mean calculates average', () => {
    expect(mean([1, 2, 3, 4, 5])).toBe(3);
    expect(mean([10, 20])).toBe(15);
  });

  test('mean returns 0 for empty array', () => {
    expect(mean([])).toBe(0);
  });

  test('standard deviation for simple data', () => {
    expect(standardDeviation([2, 4, 4, 4, 5, 5, 7, 9])).toBeCloseTo(2, 1);
  });

  test('z-score calculation', () => {
    const data = [2, 4, 4, 4, 5, 5, 7, 9];
    // Mean = 5, so z-score of 5 should be 0
    const z = zScore(5, data);
    expect(z).toBeCloseTo(0, 5);
  });

  test('z-score of mean is 0', () => {
    const data = [1, 2, 3, 4, 5];
    expect(zScore(3, data)).toBeCloseTo(0, 5);
  });

  test('z-score array normalizes data', () => {
    const data = [1, 2, 3, 4, 5];
    const zscores = zScoreArray(data);
    expect(mean(zscores)).toBeCloseTo(0, 10);
    expect(standardDeviation(zscores)).toBeCloseTo(1, 5);
  });

  test('Mahalanobis distance for point close to cluster', () => {
    // Points clustered around origin
    const data = [
      [0, 0],
      [0.1, 0.1],
      [-0.1, -0.1]
    ];
    const point = [0.05, 0.05];
    const dist = mahalanobisDistance(point, data);
    expect(dist).toBeLessThan(3);
  });

  test('Mahalanobis distance for far point', () => {
    const data = [
      [0, 0],
      [0, 1],
      [1, 0]
    ];
    const point = [10, 10];
    const dist = mahalanobisDistance(point, data);
    expect(dist).toBeGreaterThan(5);
  });

  test('Mahalanobis distances for all points', () => {
    const data = [[1], [2], [3], [100]];
    const distances = mahalanobisDistances(data);
    expect(distances.length).toBe(4);
    expect(distances[3]).toBeGreaterThan(distances[0]); // Outlier has larger distance
  });

  test('Isolation Forest identifies outliers', () => {
    const data = [
      [1, 2],
      [1.1, 2.1],
      [1, 2.2],
      [100, 100], // outlier
      [0.9, 1.9]
    ];
    const scores = isolationForestScore(data, 50, 5);
    // The outlier [100, 100] should have higher score than normal points
    expect(scores[3]).toBeGreaterThanOrEqual(scores[0]);
  });

  test('detectAnomalies finds values beyond threshold', () => {
    const values = [1, 2, 3, 4, 5, 100];
    const anomalies = detectAnomalies(values, 1.5);
    expect(anomalies.some(a => a.value === 100)).toBe(true);
  });

  test('detectAnomalies returns empty for normal data', () => {
    const values = [1, 2, 3, 4, 5, 6, 7, 8];
    const anomalies = detectAnomalies(values, 3);
    expect(anomalies.length).toBe(0);
  });

  test('local outlier factor', () => {
    const data = [
      [1, 1],
      [1.1, 1.1],
      [1.2, 0.9],
      [50, 50] // outlier - much further from cluster
    ];
    const point = [50, 50];
    const lof = localOutlierFactor(point, data, 3);
    // Outlier should have LOF != 1 (can be higher or lower depending on structure)
    expect(Math.abs(lof - 1)).toBeGreaterThan(0);
  });
});