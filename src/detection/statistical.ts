/**
 * Statistical Anomaly Detection
 * Z-score, Mahalanobis distance, Isolation Forest, One-Class SVM, DBSCAN, LOF
 */
import { mean, standardDeviation, zScore, zScoreArray, covarianceMatrix, mahalanobisDistance, mahalanobisDistances, isolationForestScore, localOutlierFactor } from '../math/anomaly.js';

// Code complexity features for anomaly detection
export interface CodeComplexityFeatures {
  cyclomatic: number;
  cognitive: number;
  halstead: number;
  linesOfCode: number;
  parameterCount: number;
  nestingDepth: number;
}

// Anomaly detection result
export interface AnomalyResult {
  score: number;
  isAnomaly: boolean;
  method: string;
  features?: number[];
  details?: string;
}

// One-Class SVM (simplified)
export function oneClassSVMscore(data: number[][], nu: number = 0.1): number[] {
  const n = data.length;
  const dim = data[0].length;
  const scores = new Array(n).fill(0);
  
  // Compute RBF kernel distance to center
  const center = new Array(dim).fill(0);
  for (const point of data) {
    for (let i = 0; i < dim; i++) center[i] += point[i];
  }
  for (let i = 0; i < dim; i++) center[i] /= n;
  
  // Calculate distances
  for (let i = 0; i < n; i++) {
    let dist = 0;
    for (let j = 0; j < dim; j++) {
      dist += (data[i][j] - center[j]) ** 2;
    }
    scores[i] = Math.sqrt(dist);
  }
  
  // Normalize scores
  const maxDist = Math.max(...scores);
  if (maxDist > 0) {
    for (let i = 0; i < n; i++) scores[i] /= maxDist;
  }
  
  return scores;
}

// DBSCAN clustering (simplified)
export interface DBSCANResult {
  labels: number[];
  outliers: number[];
  clusters: number[][];
}
export function dbscan(data: number[][], eps: number = 0.5, minPts: number = 5): DBSCANResult {
  const n = data.length;
  const labels = new Array(n).fill(-1);
  let clusterId = 0;
  
  function distance(p1: number[], p2: number[]): number {
    return Math.sqrt(p1.reduce((s, v, i) => s + (v - p2[i]) ** 2, 0));
  }
  
  function regionQuery(idx: number): number[] {
    const result: number[] = [];
    for (let i = 0; i < n; i++) {
      if (distance(data[idx], data[i]) <= eps) result.push(i);
    }
    return result;
  }
  
  function expandCluster(idx: number, neighbors: number[]): void {
    labels[idx] = clusterId;
    const queue = [...neighbors];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (labels[curr] === -1) {
        labels[curr] = clusterId;
        const currNeighbors = regionQuery(curr);
        if (currNeighbors.length >= minPts) queue.push(...currNeighbors);
      }
    }
  }
  
  for (let i = 0; i < n; i++) {
    if (labels[i] !== -1) continue;
    const neighbors = regionQuery(i);
    if (neighbors.length >= minPts) {
      expandCluster(i, neighbors);
      clusterId++;
    }
  }
  
  const outliers = labels.map((l, i) => l === -1 ? i : -1).filter(i => i !== -1);
  const clusters: number[][] = [];
  for (let c = 0; c < clusterId; c++) {
    clusters.push(labels.map((l, i) => l === c ? i : -1).filter(i => i !== -1));
  }
  
  return { labels, outliers, clusters };
}

// Combined statistical anomaly detection
export function detectStatisticalAnomaly(features: number[][], threshold: number = 2): AnomalyResult[] {
  const results: AnomalyResult[] = [];
  const n = features.length;
  
  if (n === 0) return results;
  
  // Z-score method
  const zscores = zScoreArray(features.map((_, i) => i));
  for (let i = 0; i < n; i++) {
    const z = Math.abs(zscores[i]);
    results.push({
      score: z,
      isAnomaly: z > threshold,
      method: 'zscore'
    });
  }
  
  // Mahalanobis distance method
  const mahaDists = mahalanobisDistances(features);
  const mahaMean = mean(mahaDists);
  const mahaStd = standardDeviation(mahaDists);
  for (let i = 0; i < n; i++) {
    const z = mahaStd > 0 ? Math.abs(mahaDists[i] - mahaMean) / mahaStd : 0;
    results[i].score = (results[i].score + z) / 2;
    results[i].isAnomaly = results[i].isAnomaly || z > threshold;
    results[i].method += '+mahalanobis';
  }
  
  return results;
}

// Isolation Forest on code complexity
export function detectComplexityAnomalies(features: CodeComplexityFeatures[]): AnomalyResult[] {
  const featureVectors = features.map(f => [
    f.cyclomatic, f.cognitive, f.halstead, f.linesOfCode, f.parameterCount, f.nestingDepth
  ]);
  
  const scores = isolationForestScore(featureVectors);
  return scores.map((score, i) => ({
    score,
    isAnomaly: score > 0.6,
    method: 'isolation_forest',
    features: featureVectors[i],
    details: score > 0.6 ? 'Unusual code complexity detected' : 'Normal complexity'
  }));
}

// Combined anomaly score
export function computeAnomalyScore(features: number[][], weights: number[] = [0.3, 0.3, 0.4]): {
  combined: number;
  zscore: number;
  mahalanobis: number;
  isolation: number;
} {
  if (features.length === 0) return { combined: 0, zscore: 0, mahalanobis: 0, isolation: 0 };
  
  const zscores = zScoreArray(features.map((_, i) => i));
  const mahaDists = mahalanobisDistances(features);
  const isoScores = isolationForestScore(features);
  
  const zMean = mean(zscores);
  const mMean = mean(mahaDists);
  const iMean = mean(isoScores);
  
  const combined = weights[0] * zMean + weights[1] * mMean + weights[2] * iMean;
  
  return {
    combined,
    zscore: zMean,
    mahalanobis: mMean,
    isolation: iMean
  };
}