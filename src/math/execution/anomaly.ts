/**
 * Anomaly Detection Module
 * Z-score, Mahalanobis distance, Isolation Forest
 */

/**
 * Calculate mean of an array
 */
export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

/**
 * Calculate standard deviation
 */
export function standardDeviation(values: number[], ddof: number = 0): number {
  if (values.length === 0) return 0;
  const m = mean(values);
  const squaredDiffs = values.map(v => (v - m) ** 2);
  const variance = squaredDiffs.reduce((sum, v) => sum + v, 0) / (values.length - ddof);
  return Math.sqrt(variance);
}

/**
 * Calculate z-score for a value
 */
export function zScore(value: number, data: number[]): number {
  const m = mean(data);
  const sd = standardDeviation(data);
  if (sd === 0) return 0;
  return (value - m) / sd;
}

/**
 * Calculate z-scores for all values in an array
 */
export function zScoreArray(data: number[]): number[] {
  const m = mean(data);
  const sd = standardDeviation(data);

  if (sd === 0) return data.map(() => 0);

  return data.map(v => (v - m) / sd);
}

/**
 * Calculate covariance matrix for 2D data
 */
export function covarianceMatrix(data: number[][]): number[][] {
  const n = data.length;
  const dims = data[0].length;

  // Calculate means for each dimension
  const means = new Array(dims).fill(0);
  for (const row of data) {
    for (let i = 0; i < dims; i++) {
      means[i] += row[i];
    }
  }
  for (let i = 0; i < dims; i++) {
    means[i] /= n;
  }

  // Calculate covariance matrix
  const cov = Array.from({ length: dims }, () => new Array(dims).fill(0));

  for (let i = 0; i < dims; i++) {
    for (let j = 0; j < dims; j++) {
      let sum = 0;
      for (let k = 0; k < n; k++) {
        sum += (data[k][i] - means[i]) * (data[k][j] - means[j]);
      }
      cov[i][j] = sum / (n - 1);
    }
  }

  return cov;
}

/**
 * Calculate determinant of a matrix
 */
export function determinant(matrix: number[][]): number {
  const n = matrix.length;
  if (n === 1) return matrix[0][0];
  if (n === 2) {
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  }

  let det = 0;
  for (let j = 0; j < n; j++) {
    const subMatrix = matrix.slice(1).map(row => row.filter((_, col) => col !== j));
    det += ((j % 2 === 0) ? 1 : -1) * matrix[0][j] * determinant(subMatrix);
  }
  return det;
}

/**
 * Invert a matrix
 */
export function invertMatrix(matrix: number[][]): number[][] | null {
  const n = matrix.length;
  const aug = matrix.map((row, i) => [...row, ...Array(n).fill(0).map((_, j) => i === j ? 1 : 0)]);

  // Gaussian elimination
  for (let i = 0; i < n; i++) {
    let maxRow = i;
    for (let k = i + 1; k < n; k++) {
      if (Math.abs(aug[k][i]) > Math.abs(aug[maxRow][i])) {
        maxRow = k;
      }
    }

    [aug[i], aug[maxRow]] = [aug[maxRow], aug[i]];

    if (Math.abs(aug[i][i]) < 1e-10) return null;

    const pivot = aug[i][i];
    for (let j = 0; j < 2 * n; j++) aug[i][j] /= pivot;

    for (let k = 0; k < n; k++) {
      if (k !== i) {
        const factor = aug[k][i];
        for (let j = 0; j < 2 * n; j++) {
          aug[k][j] -= factor * aug[i][j];
        }
      }
    }
  }

  return aug.map(row => row.slice(n));
}

/**
 * Calculate Mahalanobis distance for a single point
 */
export function mahalanobisDistance(point: number[], data: number[][]): number {
  const n = data.length;
  const dims = point.length;

  if (n <= dims) {
    // Not enough samples, fall back to Euclidean distance
    const m = data.reduce((acc, row) => {
      return row.map((v, i) => acc[i] + v);
    }, new Array(dims).fill(0)).map(v => v / n);

    return Math.sqrt(point.reduce((sum, v, i) => sum + (v - m[i]) ** 2, 0));
  }

  // Calculate mean vector
  const meanVec = new Array(dims).fill(0);
  for (const row of data) {
    for (let i = 0; i < dims; i++) {
      meanVec[i] += row[i];
    }
  }
  for (let i = 0; i < dims; i++) {
    meanVec[i] /= n;
  }

  // Calculate covariance matrix
  const cov = covarianceMatrix(data);

  const det = determinant(cov);
  if (Math.abs(det) < 1e-10) {
    // Singularity, fall back to Euclidean
    return Math.sqrt(point.reduce((sum, v, i) => sum + (v - meanVec[i]) ** 2, 0));
  }

  const invCov = invertMatrix(cov);
  if (!invCov) {
    return Math.sqrt(point.reduce((sum, v, i) => sum + (v - meanVec[i]) ** 2, 0));
  }

  // Calculate (x - mean)^T * Cov^-1 * (x - mean)
  const diff = point.map((v, i) => v - meanVec[i]);

  let sum = 0;
  for (let i = 0; i < dims; i++) {
    for (let j = 0; j < dims; j++) {
      sum += diff[i] * invCov[i][j] * diff[j];
    }
  }

  return Math.sqrt(Math.max(0, sum));
}

/**
 * Calculate Mahalanobis distances for all points
 */
export function mahalanobisDistances(data: number[][]): number[] {
  return data.map(point => mahalanobisDistance(point, data));
}

// Isolation Forest

interface ITreeNode {
  size?: number;
  splitAttribute?: number;
  splitValue?: number;
  left?: ITreeNode;
  right?: ITreeNode;
  isLeaf?: boolean;
}

function randomSplit(data: number[][], features: number, rng: () => number): { attr: number; val: number } {
  const attr = Math.floor(rng() * features);
  const values = data.map(row => row[attr]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const val = min + rng() * (max - min);
  return { attr, val };
}

function buildTree(data: number[][], depth: number, limit: number, rng: () => number): ITreeNode {
  if (data.length <= limit || depth >= 10) {
    return { size: data.length, isLeaf: true };
  }

  const features = data[0].length;
  const { attr, val } = randomSplit(data, features, rng);

  const leftData = data.filter(row => row[attr] < val);
  const rightData = data.filter(row => row[attr] >= val);

  if (leftData.length === 0 || rightData.length === 0) {
    return { size: data.length, isLeaf: true };
  }

  return {
    splitAttribute: attr,
    splitValue: val,
    left: buildTree(leftData, depth + 1, limit, rng),
    right: buildTree(rightData, depth + 1, limit, rng)
  };
}

function pathLength(point: number[], node: ITreeNode, currentDepth: number): number {
  if (node.isLeaf) {
    return currentDepth + (node.size ? Math.log(node.size) : 0);
  }

  const val = point[node.splitAttribute!];
  if (val < node.splitValue!) {
    return pathLength(point, node.left!, currentDepth + 1);
  } else {
    return pathLength(point, node.right!, currentDepth + 1);
  }
}

/**
 * Isolation Forest scoring
 * Returns anomaly scores (higher = more anomalous)
 */
export function isolationForestScore(
  data: number[][],
  numTrees: number = 100,
  sampleSize: number = 256,
  seed?: number
): number[] {
  const n = data.length;
  const rng = seed !== undefined
    ? (() => { let s = seed; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; }; })()
    : Math.random;

  // Sample size cannot exceed data size
  const s = Math.min(sampleSize, n);

  // Build trees
  const trees: ITreeNode[] = [];
  for (let i = 0; i < numTrees; i++) {
    const indices = new Set<number>();
    while (indices.size < s) {
      indices.add(Math.floor(rng() * n));
    }
    const sampleData = Array.from(indices).map(idx => data[idx]);
    trees.push(buildTree(sampleData, 0, s, rng));
  }

  // Calculate anomaly scores
  const c = 2 * (Math.log(s - 1) + 0.5772156649) - (2 * (s - 1) / s);

  return data.map(point => {
    const avgPathLength = trees.reduce((sum, tree) => {
      return sum + pathLength(point, tree, 0);
    }, 0) / numTrees;

    return Math.pow(2, -avgPathLength / c);
  });
}

/**
 * Simple anomaly detection using threshold
 */
export function detectAnomalies(
  values: number[],
  threshold: number = 2
): Array<{ index: number; value: number; score: number }> {
  const zscores = zScoreArray(values);

  return values
    .map((value, index) => ({ index, value, score: Math.abs(zscores[index]) }))
    .filter(item => item.score > threshold)
    .sort((a, b) => b.score - a.score);
}

/**
 * Local Outlier Factor (simplified)
 */
export function localOutlierFactor(
  point: number[],
  data: number[][],
  k: number = 5
): number {
  if (data.length <= k) return 1;

  // Calculate distances to all points
  const distances = data.map((p, i) => ({
    idx: i,
    dist: Math.sqrt(p.reduce((sum, v, j) => sum + (v - point[j]) ** 2, 0))
  }));

  // Sort by distance
  distances.sort((a, b) => a.dist - b.dist);

  // Get k nearest neighbors
  const neighbors = distances.slice(1, k + 1); // Exclude self (assumed to be in data)

  // Calculate reachability density
  let sum = 0;
  for (const neighbor of neighbors) {
    const neighborDistances = data.map(p =>
      Math.sqrt(p.reduce((s, v, j) => s + (v - data[neighbor.idx][j]) ** 2, 0))
    ).sort((a, b) => a - b)[k];

    sum += Math.max(neighbor.dist, neighborDistances);
  }

  const lrd = k / sum;

  // Calculate LOF
  let neighborLrdSum = 0;
  for (const neighbor of neighbors) {
    const neighborNeighbors = distances
      .filter(d => d.idx !== neighbor.idx)
      .slice(1, k + 1);

    let nSum = 0;
    for (const nn of neighborNeighbors) {
      const nnDistances = data.map(p =>
        Math.sqrt(p.reduce((s, v, j) => s + (v - data[nn.idx][j]) ** 2, 0))
      ).sort((a, b) => a - b)[k];
      nSum += Math.max(nn.dist, nnDistances);
    }

    neighborLrdSum += (k / nSum);
  }

  return lrd / (neighborLrdSum / k);
}