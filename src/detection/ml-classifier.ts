export type FeatureVector = number[];
export type Embedding = number[];

function hashString(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function seededRandom(seed: number, index: number): number {
  let s = (seed + index * 0x6b2f9a1d) | 0;
  s = Math.imul(s ^ (s >>> 16), 0x45d9f3b);
  s = Math.imul(s ^ (s >>> 13), 0x45d9f3b);
  s = s ^ (s >>> 16);
  return (s >>> 0) / 4294967296;
}

export function graphEmbedding(adjacency: Map<string, string[]>, dimensions: number = 64): Map<string, Embedding> {
  const embeddings = new Map<string, Embedding>();
  const nodes = Array.from(adjacency.keys());

  // Phase 1: Deterministic initialization from node identity hash
  for (const node of nodes) {
    const seed = hashString(node);
    const embedding = new Array(dimensions);
    for (let d = 0; d < dimensions; d++) {
      embedding[d] = seededRandom(seed, d) * 2 - 1;
    }
    embeddings.set(node, embedding);
  }

  // Phase 2: Neighborhood aggregation (2 iterations of mean-aggregation GCN-style)
  for (let iteration = 0; iteration < 2; iteration++) {
    const updated = new Map<string, Embedding>();
    for (const node of nodes) {
      const current = embeddings.get(node)!;
      const neighbors = adjacency.get(node) || [];
      const aggregated = [...current];

      if (neighbors.length > 0) {
        let neighborCount = 0;
        for (const neighbor of neighbors) {
          const ne = embeddings.get(neighbor);
          if (ne) {
            for (let d = 0; d < dimensions; d++) {
              aggregated[d] += ne[d];
            }
            neighborCount++;
          }
        }
        if (neighborCount > 0) {
          const selfWeight = 0.5;
          const neighborWeight = 0.5 / neighborCount;
          for (let d = 0; d < dimensions; d++) {
            aggregated[d] = selfWeight * current[d] + neighborWeight * (aggregated[d] - current[d]);
          }
        }
      }
      updated.set(node, aggregated);
    }
    for (const [k, v] of updated) embeddings.set(k, v);
  }

  // Phase 3: L2 normalize
  for (const [node, embedding] of embeddings) {
    const norm = Math.sqrt(embedding.reduce((s, v) => s + v * v, 0));
    if (norm > 0) {
      for (let d = 0; d < dimensions; d++) embedding[d] /= norm;
    }
  }

  return embeddings;
}

export function tokenEmbedding(tokens: string[], vocab: Map<string, Embedding>): Embedding[] {
  const results: Embedding[] = [];
  const dim = vocab.values().next().value?.length || 64;

  for (const token of tokens) {
    const embed = vocab.get(token);
    if (embed) {
      results.push([...embed]);
    } else {
      const seed = hashString(token);
      const unknown = new Array(dim);
      for (let d = 0; d < dim; d++) {
        unknown[d] = seededRandom(seed, d) * 2 - 1;
      }
      const norm = Math.sqrt(unknown.reduce((s, v) => s + v * v, 0));
      if (norm > 0) for (let d = 0; d < dim; d++) unknown[d] /= norm;
      results.push(unknown);
    }
  }
  return results;
}

export function sentenceEmbedding(tokens: string[], vocab: Map<string, Embedding>): Embedding {
  const tokenEmbeds = tokenEmbedding(tokens, vocab);
  if (tokenEmbeds.length === 0) return [];
  const dims = tokenEmbeds[0].length;
  const sentence = new Array(dims).fill(0);
  for (const embed of tokenEmbeds) {
    for (let d = 0; d < dims; d++) sentence[d] += embed[d];
  }
  for (let d = 0; d < dims; d++) sentence[d] /= tokenEmbeds.length;
  return sentence;
}

export interface RandomForestConfig {
  numTrees: number;
  maxDepth: number;
  featureSampleRatio: number;
  seed?: number;
}

interface DecisionStump {
  featureIdx: number;
  threshold: number;
  leftLabel: number;
  rightLabel: number;
  weight: number;
}

export function randomForestPredict(features: FeatureVector[], labels: number[], config: RandomForestConfig): (x: FeatureVector) => number {
  const numFeatures = features[0]?.length || 0;
  const numSamples = features.length;
  if (numSamples === 0 || numFeatures === 0) return () => 0;

  const baseSeed = config.seed ?? hashString('rf');
  const trees: DecisionStump[] = [];

  for (let t = 0; t < config.numTrees; t++) {
    // Bootstrap sample with replacement (deterministic)
    const sampleIndices: number[] = [];
    for (let s = 0; s < numSamples; s++) {
      const idx = Math.floor(seededRandom(baseSeed + t, s * 7) * numSamples);
      sampleIndices.push(Math.min(idx, numSamples - 1));
    }

    // Select feature subset (sqrt(n) features)
    const numCandidateFeatures = Math.max(1, Math.floor(numFeatures * config.featureSampleRatio));
    const featureIdx = Math.floor(seededRandom(baseSeed + t * 13, 0) * numCandidateFeatures) % numFeatures;

    const sampleFeatures = sampleIndices.map(i => features[i][featureIdx]);
    const sampleLabels = sampleIndices.map(i => labels[i]);

    // Find best threshold via median split
    const sorted = sampleFeatures.map((f, i) => ({ f, l: sampleLabels[i] })).sort((a, b) => a.f - b.f);
    const mid = Math.floor(sorted.length / 2);
    const threshold = sorted.length > 1 ? (sorted[mid - 1].f + sorted[mid].f) / 2 : sorted[0]?.f ?? 0;

    const leftLabels = sorted.filter(x => x.f < threshold).map(x => x.l);
    const rightLabels = sorted.filter(x => x.f >= threshold).map(x => x.l);

    trees.push({
      featureIdx,
      threshold,
      leftLabel: leftLabels.length > 0 ? mean(leftLabels) : mean(sampleLabels),
      rightLabel: rightLabels.length > 0 ? mean(rightLabels) : mean(sampleLabels),
      weight: 1,
    });
  }

  return (x: FeatureVector): number => {
    let sum = 0;
    for (const tree of trees) {
      const val = x[tree.featureIdx] < tree.threshold ? tree.leftLabel : tree.rightLabel;
      sum += val * tree.weight;
    }
    return sum / trees.length;
  };
}

function mean(values: number[]): number {
  return values.length > 0 ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

export interface XGBoostConfig {
  numIterations: number;
  learningRate: number;
  maxDepth: number;
}

export function xgboostPredict(features: FeatureVector[], labels: number[], config: XGBoostConfig): (x: FeatureVector) => number {
  const numSamples = features.length;
  if (numSamples === 0) return () => 0;

  const predictions = new Array(numSamples).fill(mean(labels));

  for (let iter = 0; iter < config.numIterations; iter++) {
    const gradients = labels.map((l, i) => l - predictions[i]);

    // Fit a simple stump to the gradients
    const residuals = [...gradients];
    const numFeatures = features[0]?.length || 0;

    let bestFeature = 0;
    let bestThreshold = 0;
    let bestLoss = Infinity;

    for (let f = 0; f < Math.min(numFeatures, 20); f++) {
      const vals = features.map(feat => feat[f]);
      const sorted = vals.map((v, i) => ({ v, g: residuals[i] })).sort((a, b) => a.v - b.v);
      const mid = Math.floor(sorted.length / 2);
      if (mid === 0) continue;
      const thresh = (sorted[mid - 1].v + sorted[mid].v) / 2;

      const left = sorted.filter(x => x.v < thresh);
      const right = sorted.filter(x => x.v >= thresh);
      if (left.length === 0 || right.length === 0) continue;

      const leftMean = mean(left.map(x => x.g));
      const rightMean = mean(right.map(x => x.g));
      const loss = left.reduce((s, x) => s + (x.g - leftMean) ** 2, 0) + right.reduce((s, x) => s + (x.g - rightMean) ** 2, 0);

      if (loss < bestLoss) {
        bestLoss = loss;
        bestFeature = f;
        bestThreshold = thresh;
      }
    }

    // Compute leaf values for the best split
    const leftIndices = features.map((feat, i) => feat[bestFeature] < bestThreshold ? i : -1).filter(i => i >= 0);
    const rightIndices = features.map((feat, i) => feat[bestFeature] >= bestThreshold ? i : -1).filter(i => i >= 0);

    const leftValue = leftIndices.length > 0 ? mean(leftIndices.map(i => residuals[i])) : 0;
    const rightValue = rightIndices.length > 0 ? mean(rightIndices.map(i => residuals[i])) : 0;

    for (let i = 0; i < numSamples; i++) {
      const update = features[i][bestFeature] < bestThreshold ? leftValue : rightValue;
      predictions[i] += config.learningRate * update;
    }
  }

  return (x: FeatureVector): number => {
    let pred = mean(labels);
    const numFeatures = x.length;

    for (let iter = 0; iter < config.numIterations; iter++) {
      let bestFeature = 0;
      let bestThreshold = 0;
      let bestLoss = Infinity;

      for (let f = 0; f < Math.min(numFeatures, 20); f++) {
        const vals = features.map(feat => feat[f]);
        const sorted = vals.map((v, i) => ({ v })).sort((a, b) => a.v - b.v);
        const mid = Math.floor(sorted.length / 2);
        if (mid === 0) continue;
        const thresh = (sorted[mid - 1].v + sorted[mid].v) / 2;

        const leftCount = sorted.filter(s => s.v < thresh).length;
        const rightCount = sorted.filter(s => s.v >= thresh).length;
        if (leftCount === 0 || rightCount === 0) continue;

        const loss = leftCount * rightCount;
        if (loss < bestLoss) { bestLoss = loss; bestFeature = f; bestThreshold = thresh; }
      }

      const gradients = labels.map((l, i) => l - predictions[i]);
      const leftIndices = features.map((feat, i) => feat[bestFeature] < bestThreshold ? i : -1).filter(i => i >= 0);
      const rightIndices = features.map((feat, i) => feat[bestFeature] >= bestThreshold ? i : -1).filter(i => i >= 0);
      const leftValue = leftIndices.length > 0 ? mean(leftIndices.map(i => gradients[i])) : 0;
      const rightValue = rightIndices.length > 0 ? mean(rightIndices.map(i => gradients[i])) : 0;

      const update = x[bestFeature] < bestThreshold ? leftValue : rightValue;
      pred += config.learningRate * update;
    }
    return pred;
  };
}

export interface EnsembleConfig {
  rfConfig: RandomForestConfig;
  xgbConfig: XGBoostConfig;
  weights: { rf: number; xgb: number };
}

export function createEnsembleClassifier(
  features: FeatureVector[],
  labels: number[],
  config: EnsembleConfig
): {
  predict: (x: FeatureVector) => number;
  probabilities: (x: FeatureVector) => { vulnerable: number; safe: number };
} {
  const rfPredict = randomForestPredict(features, labels, config.rfConfig);
  const xgbPredict = xgboostPredict(features, labels, config.xgbConfig);
  const totalWeight = config.weights.rf + config.weights.xgb;
  const rfWeight = config.weights.rf / totalWeight;
  const xgbWeight = config.weights.xgb / totalWeight;

  return {
    predict: (x: FeatureVector): number => {
      return rfWeight * rfPredict(x) + xgbWeight * xgbPredict(x);
    },
    probabilities: (x: FeatureVector): { vulnerable: number; safe: number } => {
      const pred = rfWeight * rfPredict(x) + xgbWeight * xgbPredict(x);
      const vulnProb = Math.min(1, Math.max(0, pred));
      return { vulnerable: vulnProb, safe: 1 - vulnProb };
    }
  };
}

export function combinedEmbedding(
  graphEmbed: Embedding,
  tokenEmbed: Embedding,
  weights: { graph: number; token: number } = { graph: 0.5, token: 0.5 }
): Embedding {
  const len = Math.max(graphEmbed.length, tokenEmbed.length);
  const combined = new Array(len).fill(0);
  for (let i = 0; i < len; i++) {
    const g = i < graphEmbed.length ? graphEmbed[i] : 0;
    const t = i < tokenEmbed.length ? tokenEmbed[i] : 0;
    combined[i] = g * weights.graph + t * weights.token;
  }
  return combined;
}

export interface MLClassification {
  vulnerable: boolean;
  confidence: number;
  probabilities: { vulnerable: number; safe: number };
  method: string;
  features: FeatureVector;
}

// Aliases for backward compatibility with detector.ts
export const computeGraphEmbedding = graphEmbedding;
export const computeTokenEmbedding = tokenEmbedding;
