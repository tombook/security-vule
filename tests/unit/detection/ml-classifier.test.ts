import { describe, test, expect } from 'bun:test';
import {
  graphEmbedding,
  tokenEmbedding,
  sentenceEmbedding,
  randomForestPredict,
  xgboostPredict,
  createEnsembleClassifier,
  combinedEmbedding,
  computeGraphEmbedding,
  computeTokenEmbedding,
  type FeatureVector,
} from '../../../src/detection/ml-classifier.js';

// 注:MLClassification 接口为死代码(全文未消费),不纳入测试。

describe('ml-classifier: graphEmbedding', () => {
  test('为每个节点返回指定维度的向量', () => {
    const adj = new Map<string, string[]>([
      ['a', ['b']],
      ['b', ['a']],
    ]);
    const embeddings = graphEmbedding(adj, 8);
    expect(embeddings.size).toBe(2);
    expect(embeddings.get('a')?.length).toBe(8);
    expect(embeddings.get('b')?.length).toBe(8);
  });

  test('空图返回空 Map', () => {
    const adj = new Map<string, string[]>();
    const embeddings = graphEmbedding(adj, 16);
    expect(embeddings.size).toBe(0);
  });

  test('computeGraphEmbedding 别名与原函数一致', () => {
    const adj = new Map<string, string[]>([['x', ['y']]]);
    const direct = graphEmbedding(adj, 4);
    const aliased = computeGraphEmbedding(adj, 4);
    expect(aliased.get('x')).toEqual(direct.get('x'));
  });
});

describe('ml-classifier: tokenEmbedding / sentenceEmbedding', () => {
  test('已知 token 拷贝 vocab 向量,未知 token 用种子回退', () => {
    const vocab = new Map<string, number[]>();
    vocab.set('safe', [0.1, 0.2, 0.3]);
    vocab.set('unsafe', [0.9, 0.8, 0.7]);

    const known = tokenEmbedding(['safe'], vocab);
    expect(known.length).toBe(1);
    expect(known[0]).toEqual([0.1, 0.2, 0.3]);

    const unknown = tokenEmbedding(['mystery'], vocab);
    expect(unknown.length).toBe(1);
    expect(unknown[0].length).toBe(3);
    expect(unknown[0]).not.toEqual([0, 0, 0]);
  });

  test('computeTokenEmbedding 别名与 tokenEmbedding 等价', () => {
    const vocab = new Map<string, number[]>([['k', [1, 1]]]);
    const direct = tokenEmbedding(['k'], vocab);
    const aliased = computeTokenEmbedding(['k'], vocab);
    expect(aliased).toEqual(direct);
  });

  test('sentenceEmbedding 对 token 向量取平均,空 tokens 返回空数组', () => {
    const vocab = new Map<string, number[]>();
    vocab.set('a', [1, 0, 0]);
    vocab.set('b', [0, 1, 0]);

    const vec = sentenceEmbedding(['a', 'b'], vocab);
    expect(vec.length).toBe(3);
    expect(vec[0]).toBeCloseTo(0.5, 5);
    expect(vec[1]).toBeCloseTo(0.5, 5);
    expect(vec[2]).toBeCloseTo(0, 5);

    const empty = sentenceEmbedding([], vocab);
    expect(empty).toEqual([]);
  });
});

describe('ml-classifier: combinedEmbedding', () => {
  test('默认 0.5/0.5 加权平均,维度取较大者', () => {
    const g = [2, 0];
    const t = [0, 4];
    const c = combinedEmbedding(g, t);
    expect(c).toEqual([1, 2]);
  });

  test('自定义权重覆盖默认值', () => {
    const g = [1, 1];
    const t = [0, 0];
    const c = combinedEmbedding(g, t, { graph: 0.8, token: 0.2 });
    expect(c[0]).toBeCloseTo(0.8, 5);
    expect(c[1]).toBeCloseTo(0.8, 5);
  });

  test('长度不一时用 0 补齐短侧', () => {
    const g = [1, 2];
    const t = [3];
    const c = combinedEmbedding(g, t);
    expect(c.length).toBe(2);
    expect(c[0]).toBeCloseTo(0.5 * 1 + 0.5 * 3, 5);
    expect(c[1]).toBeCloseTo(0.5 * 2 + 0.5 * 0, 5);
  });
});

describe('ml-classifier: randomForestPredict', () => {
  test('训练后返回可调用的预测函数', () => {
    const features: FeatureVector[] = [
      [0.1], [0.2], [0.8], [0.9],
    ];
    const labels = [0, 0, 1, 1];
    const predict = randomForestPredict(features, labels, {
      numTrees: 5,
      maxDepth: 2,
      featureSampleRatio: 1,
      seed: 42,
    });
    const out = predict([0.15]);
    expect(typeof out).toBe('number');
    expect(Number.isFinite(out)).toBe(true);
  });

  test('相同种子产生相同的预测结果(确定性)', () => {
    const features: FeatureVector[] = [[0], [1], [2], [3]];
    const labels = [0, 0, 1, 1];
    const cfg = { numTrees: 4, maxDepth: 2, featureSampleRatio: 1, seed: 7 };
    const p1 = randomForestPredict(features, labels, cfg);
    const p2 = randomForestPredict(features, labels, cfg);
    expect(p1([1.5])).toBeCloseTo(p2([1.5]), 10);
  });
});

describe('ml-classifier: xgboostPredict', () => {
  test('训练后预测函数返回有限数值', () => {
    const features: FeatureVector[] = [
      [1, 0], [2, 0], [8, 1], [9, 1],
    ];
    const labels = [0, 0, 1, 1];
    const predict = xgboostPredict(features, labels, {
      numIterations: 3,
      learningRate: 0.1,
      maxDepth: 2,
    });
    const out = predict([5, 0]);
    expect(typeof out).toBe('number');
    expect(Number.isFinite(out)).toBe(true);
  });

  test('迭代数为 0 时预测值为标签均值', () => {
    const features: FeatureVector[] = [[0], [2]];
    const labels = [0, 1];
    const predict = xgboostPredict(features, labels, {
      numIterations: 0,
      learningRate: 0.1,
      maxDepth: 1,
    });
    expect(predict([1])).toBeCloseTo(0.5, 5);
  });
});

describe('ml-classifier: createEnsembleClassifier', () => {
  test('probabilities 输出归一化到 [0,1] 且 vulnerable+safe=1', () => {
    const features: FeatureVector[] = [
      [0.1, 0.0], [0.2, 0.1], [0.9, 0.8], [1.0, 0.9],
    ];
    const labels = [0, 0, 1, 1];
    const clf = createEnsembleClassifier(features, labels, {
      rfConfig: { numTrees: 3, maxDepth: 2, featureSampleRatio: 1, seed: 1 },
      xgbConfig: { numIterations: 2, learningRate: 0.1, maxDepth: 2 },
      weights: { rf: 1, xgb: 1 },
    });
    const prob = clf.probabilities([0.5, 0.5]);
    expect(prob.vulnerable).toBeGreaterThanOrEqual(0);
    expect(prob.vulnerable).toBeLessThanOrEqual(1);
    expect(prob.safe).toBeGreaterThanOrEqual(0);
    expect(prob.safe).toBeLessThanOrEqual(1);
    expect(prob.vulnerable + prob.safe).toBeCloseTo(1, 6);
  });

  test('predict 产出与 probabilities.vulnerable 一致(同一输入)', () => {
    const features: FeatureVector[] = [[0], [1], [2], [3]];
    const labels = [0, 0, 1, 1];
    const clf = createEnsembleClassifier(features, labels, {
      rfConfig: { numTrees: 2, maxDepth: 1, featureSampleRatio: 1, seed: 3 },
      xgbConfig: { numIterations: 1, learningRate: 0.05, maxDepth: 1 },
      weights: { rf: 1, xgb: 2 },
    });
    const x: FeatureVector = [1.5];
    const pred = clf.predict(x);
    const prob = clf.probabilities(x);
    expect(prob.vulnerable).toBeCloseTo(pred, 6);
  });
});

describe('ml-classifier: 边界条件', () => {
  test('randomForestPredict 对空 features 返回常数 0 预测', () => {
    const predict = randomForestPredict([], [], {
      numTrees: 3, maxDepth: 1, featureSampleRatio: 1, seed: 0,
    });
    expect(predict([1, 2, 3])).toBe(0);
  });

  test('xgboostPredict 对空 features 返回常数 0 预测', () => {
    const predict = xgboostPredict([], [], {
      numIterations: 2, learningRate: 0.1, maxDepth: 1,
    });
    expect(predict([1, 2])).toBe(0);
  });

  test('graphEmbedding 单节点自嵌入范数约等于 1(L2 归一化)', () => {
    const adj = new Map<string, string[]>([['only', []]]);
    const embeddings = graphEmbedding(adj, 32);
    const v = embeddings.get('only')!;
    const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
    expect(norm).toBeCloseTo(1, 5);
  });
});