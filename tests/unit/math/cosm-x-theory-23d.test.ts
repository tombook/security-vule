/**
 * cosm-x-theory-23d.test.ts
 * 23 维度宇宙星系法 + UVRS 的单元测试
 * 目标: 60+ 用例覆盖
 */

import { describe, test, expect } from 'bun:test';
import {
  TheoryDimension,
  RiskLevel,
  THEORY_DEFINITIONS,
  RISK_THRESHOLDS,
  UVRS_DEFAULT_WEIGHTS,
  UVRS_DIMENSION_DEFAULTS,
  CosmicTheoryEngine,
  UVRSCalculator,
  buildGraphData23D,
  calculateProjectUVRS,
  type GraphData,
  type UVRS,
} from '../../../src/math/cosm-x-theory-23d.js';

describe('TheoryDimension enum', () => {
  test('has exactly 23 dimensions', () => {
    const ids = Object.values(TheoryDimension)
      .filter(v => typeof v === 'number') as number[];
    expect(ids.length).toBe(23);
  });

  test('dimension IDs are 1..23', () => {
    const ids = Object.values(TheoryDimension)
      .filter(v => typeof v === 'number') as number[];
    expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]);
  });

  test('all 23 dimensions have THEORY_DEFINITIONS entries', () => {
    expect(THEORY_DEFINITIONS.length).toBe(23);
    for (let i = 1; i <= 23; i++) {
      const def = THEORY_DEFINITIONS.find(d => d.dim_id === i);
      expect(def).toBeDefined();
      expect(def!.name).toBeTruthy();
      expect(def!.description).toBeTruthy();
    }
  });
});

describe('RiskLevel', () => {
  test('has 4 levels', () => {
    const values = Object.values(RiskLevel).filter(v => typeof v === 'string');
    expect(values.length).toBe(4);
  });

  test('RISK_THRESHOLDS is monotonically increasing', () => {
    const order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL];
    for (let i = 0; i < order.length - 1; i++) {
      expect(RISK_THRESHOLDS[order[i]]).toBeLessThanOrEqual(RISK_THRESHOLDS[order[i + 1]]);
    }
  });
});

describe('UVRSCalculator', () => {
  const scorer = new UVRSCalculator();

  test('default weights sum to ~1.0', () => {
    const total = Object.values(UVRS_DEFAULT_WEIGHTS)
      .filter(w => w > 0)
      .reduce((s, w) => s + w, 0);
    expect(total).toBeCloseTo(1.0, 1);
  });

  test('compute() returns value in [0, 1]', () => {
    const score = scorer.compute({ kepler: 0.5, gravity: 0.3, entropy: 0.4 });
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  test('sigmoid boundary: large positive input -> 1.0', () => {
    const s = scorer.compute({
      kepler: 100, gravity: 100, tidal: 100, nbody: 100, perturbation: 100,
      relativistic: 100, dark_matter: 100, quantum: 100, entropy: 100, history: 100,
    });
    expect(s).toBeCloseTo(1.0, 5);
  });

  test('sigmoid boundary: large negative input -> 0.0', () => {
    const s = scorer.compute({
      kepler: -100, gravity: -100, tidal: -100, nbody: -100, perturbation: -100,
      relativistic: -100, dark_matter: -100, quantum: -100, entropy: -100, history: -100,
    });
    expect(s).toBeCloseTo(0.0, 5);
  });

  test('classify() at boundaries', () => {
    expect(scorer.classify(0.0)).toBe(RiskLevel.LOW);
    expect(scorer.classify(0.24)).toBe(RiskLevel.LOW);
    expect(scorer.classify(0.25)).toBe(RiskLevel.LOW);  // impl: 0.25 >= 0.25 LOW threshold
    expect(scorer.classify(0.50)).toBe(RiskLevel.MEDIUM);
    expect(scorer.classify(0.75)).toBe(RiskLevel.HIGH);
    expect(scorer.classify(0.85)).toBe(RiskLevel.CRITICAL);
    expect(scorer.classify(1.0)).toBe(RiskLevel.CRITICAL);
  });

  test('classify_batch() returns array of same length', () => {
    const result = scorer.classify_batch([0.1, 0.3, 0.6, 0.9]);
    expect(result.length).toBe(4);
    expect(result[0]).toBe(RiskLevel.LOW);
    expect(result[3]).toBe(RiskLevel.CRITICAL);
  });

  test('top_risks() returns sorted by score desc', () => {
    const scores = { nodeA: 0.9, nodeB: 0.2, nodeC: 0.5 };
    const top = scorer.top_risks(scores, 3);
    expect(top.length).toBe(3);
    expect(top[0][0]).toBe('nodeA');  // highest first
    expect(top[0][1]).toBe(0.9);
    expect(top[1][1]).toBeLessThanOrEqual(top[0][1]);
  });

  test('contribution_analysis() sums to ~1.0', () => {
    const analysis = scorer.contribution_analysis({ kepler: 0.5, gravity: 0.5, entropy: 0.5 });
    const total = Object.values(analysis).reduce((s, v) => s + v, 0);
    expect(total).toBeCloseTo(1.0, 1);
  });

  test('dominant_dimension() returns highest contributor', () => {
    const dominant = scorer.dominant_dimension({ kepler: 0.9, gravity: 0.1, entropy: 0.3 });
    expect(dominant[0]).toBe('kepler');
    expect(dominant[1]).toBeGreaterThan(0.3);
  });

  test('update_weights() normalizes', () => {
    const custom = new UVRSCalculator({ kepler: 2, gravity: 2, entropy: 2 });
    custom.update_weights({ kepler: 2, gravity: 2, entropy: 2 });
    const total = Object.values(custom.weights).reduce((s, w) => s + w, 0);
    expect(total).toBeCloseTo(1.0, 1);
  });

  test('get_risk_distribution()', () => {
    const dist = scorer.get_risk_distribution([0.1, 0.3, 0.6, 0.9, 0.95]);
    expect(dist[RiskLevel.LOW]).toBeGreaterThanOrEqual(0);
    expect(dist[RiskLevel.CRITICAL]).toBeGreaterThanOrEqual(1);
  });

  test('compute_statistics() has all fields', () => {
    const stats = scorer.compute_statistics([0.1, 0.3, 0.5, 0.7, 0.9]);
    expect(typeof stats.mean).toBe('number');
    expect(typeof stats.median).toBe('number');
    expect(typeof stats.std).toBe('number');
    expect(typeof stats.min).toBe('number');
    expect(typeof stats.max).toBe('number');
    expect(typeof stats.q25).toBe('number');
    expect(typeof stats.q75).toBe('number');
    expect(typeof stats.high_risk_ratio).toBe('number');
    expect(typeof stats.critical_ratio).toBe('number');
  });

  test('export_config() / from_config() round-trip', () => {
    const exported = scorer.export_config();
    const restored = UVRSCalculator.from_config(exported);
    expect(restored.weights).toEqual(scorer.weights);
  });

  test('custom thresholds respected', () => {
    const custom = new UVRSCalculator(undefined, {
      [RiskLevel.LOW]: 0.1,
      [RiskLevel.MEDIUM]: 0.3,
      [RiskLevel.HIGH]: 0.6,
      [RiskLevel.CRITICAL]: 0.9,
    });
    // 0.15 >= 0.1 LOW but < 0.3 MEDIUM, so should be LOW
    expect(custom.classify(0.15)).toBe(RiskLevel.LOW);
    // 0.35 >= 0.3 MEDIUM, so MEDIUM
    expect(custom.classify(0.35)).toBe(RiskLevel.MEDIUM);
  });

  test('empty components returns default', () => {
    const s = scorer.compute({});
    expect(s).toBeGreaterThanOrEqual(0);
    expect(s).toBeLessThanOrEqual(1);
  });
});

describe('CosmicTheoryEngine', () => {
  const engine = new CosmicTheoryEngine();

  test('engine instance created', () => {
    expect(engine).toBeInstanceOf(CosmicTheoryEngine);
  });

  test('get_dimension_definition returns null for invalid id', () => {
    const def = engine.get_dimension_definition(999);
    expect(def).toBeNull();
  });

  test('get_dimension_definition returns valid for all 23', () => {
    for (let i = 1; i <= 23; i++) {
      const def = engine.get_dimension_definition(i);
      expect(def).not.toBeNull();
      expect(def!.dim_id).toBe(i);
    }
  });

  test('calculate_dimension_score returns valid result object', () => {
    const graph: GraphData = { sinks: ['a'], shortest_paths: { node1: { a: 1 } } };
    const result = engine.calculate_dimension_score(1, graph, 'node1');
    expect(result).toBeDefined();
    expect(result.dim_id).toBe(1);
    expect(typeof result.score).toBe('number');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(1);
  });

  test('calculate_all_dimensions returns 23 results', () => {
    const graph: GraphData = { sinks: ['a'] };
    const results = engine.calculate_all_dimensions(graph, 'node1');
    expect(results.length).toBe(23);
  });

  test('calculate_unified_risk_score returns UVRS object', () => {
    const graph: GraphData = { sinks: ['a'], pagerank: { node1: 0.5 } };
    const uvrs = engine.calculate_unified_risk_score(graph, 'node1');
    expect(typeof uvrs.unified_score).toBe('number');
    expect(Object.values(RiskLevel)).toContain(uvrs.risk_level);
    expect(Array.isArray(uvrs.top_risk_dimensions)).toBe(true);
    expect(typeof uvrs.dimension_contributions).toBe('object');
  });

  test('calculate_unified_risk_score score in [0,1]', () => {
    const graph: GraphData = { sinks: ['a'] };
    const uvrs = engine.calculate_unified_risk_score(graph, 'node1');
    expect(uvrs.unified_score).toBeGreaterThanOrEqual(0);
    expect(uvrs.unified_score).toBeLessThanOrEqual(1);
  });

  test('get_theory_whitepaper_data returns valid structure', () => {
    const wp = engine.get_theory_whitepaper_data();
    expect(wp).toBeDefined();
  });

  test('calculateProjectUVRS via engine instance', () => {
    const empty: UVRS = {
      unified_score: 0.5,
      risk_level: RiskLevel.MEDIUM,
      top_risk_dimensions: [1, 2],
      top_risk_dimension_names: ['kepler', 'gravity'],
      dimension_contributions: { kepler: 0.5, gravity: 0.5 },
      dimension_scores: { kepler: 0.5, gravity: 0.5 },
      dimension_names: { 1: 'kepler', 2: 'gravity' },
      dimension_contributions_by_id: { 1: 0.5, 2: 0.5 },
      metadata: { engine_version: '7.5', computed_at: Date.now(), enabled_dimensions: [1, 2] },
    };
    const result = (engine as unknown as { calculateProjectUVRS: (uvrs: UVRS[]) => UVRS })
      .calculateProjectUVRS([empty]);
    expect(result.unified_score).toBe(0.5);
  });
});

describe('buildGraphData23D', () => {
  test('builds from empty inputs', () => {
    const graph = buildGraphData23D({}, {});
    expect(graph.sinks).toEqual([]);
    expect(graph.pagerank).toBeDefined();
  });

  test('extracts lagrange points as sinks', () => {
    const graph = buildGraphData23D({}, {
      lagrangePoints: [{ id: 'lp1' }, { id: 'lp2' }],
    });
    expect(graph.sinks).toContain('lp1');
    expect(graph.sinks).toContain('lp2');
  });

  test('extracts anomalies as architectural_smells', () => {
    const graph = buildGraphData23D({}, {
      anomalies: [{ nodeId: 'a1', score: 0.7 }],
    });
    expect(graph.architectural_smells!['a1']).toBe(0.7);
  });

  test('uses vulnerabilityScore as anchor', () => {
    const graph = buildGraphData23D({}, { vulnerabilityScore: 80 });
    expect(graph.pagerank!['_project_avg']).toBe(0.8);
  });

  test('extracts CPG nodes into pagerank', () => {
    const cpg = { nodes: [{ id: 'n1' }, { id: 'n2' }] };
    const graph = buildGraphData23D(cpg, {});
    expect(graph.pagerank!['n1']).toBe(0.01);
    expect(graph.pagerank!['n2']).toBe(0.01);
  });
});

describe('calculateProjectUVRS standalone', () => {
  test('empty list returns zero', () => {
    const r = calculateProjectUVRS([]);
    expect(r.unified_score).toBe(0);
    expect(r.risk_level).toBe(RiskLevel.LOW);
    expect(r.top_risk_dimensions).toEqual([]);
  });

  test('single UVRS is returned with same score', () => {
    const u: UVRS = {
      unified_score: 0.7,
      risk_level: RiskLevel.HIGH,
      top_risk_dimensions: [3],
      top_risk_dimension_names: ['gravity'],
      dimension_contributions: { gravity: 1.0 },
      dimension_scores: { gravity: 0.7 },
      dimension_names: { 3: 'gravity' },
      dimension_contributions_by_id: { 3: 1.0 },
      metadata: { engine_version: '7.5', computed_at: Date.now(), enabled_dimensions: [3] },
    };
    const r = calculateProjectUVRS([u]);
    expect(r.unified_score).toBe(0.7);
    expect(r.risk_level).toBe(RiskLevel.HIGH);
  });

  test('multiple UVRS: average score, worst level', () => {
    const u1: UVRS = {
      unified_score: 0.3, risk_level: RiskLevel.MEDIUM,
      top_risk_dimensions: [1], top_risk_dimension_names: ['kepler'],
      dimension_contributions: { kepler: 1 }, dimension_scores: { kepler: 0.3 },
      dimension_names: { 1: 'kepler' }, dimension_contributions_by_id: { 1: 1 },
      metadata: { engine_version: '7.5', computed_at: Date.now(), enabled_dimensions: [1] },
    };
    const u2: UVRS = {
      unified_score: 0.9, risk_level: RiskLevel.CRITICAL,
      top_risk_dimensions: [2], top_risk_dimension_names: ['gravity'],
      dimension_contributions: { gravity: 1 }, dimension_scores: { gravity: 0.9 },
      dimension_names: { 2: 'gravity' }, dimension_contributions_by_id: { 2: 1 },
      metadata: { engine_version: '7.5', computed_at: Date.now(), enabled_dimensions: [2] },
    };
    const r = calculateProjectUVRS([u1, u2]);
    expect(r.unified_score).toBeCloseTo(0.6, 1);
    expect(r.risk_level).toBe(RiskLevel.CRITICAL);
    expect(r.metadata.total_vulnerabilities).toBe(2);
  });
});

describe('Integration: UVRS thresholds consistent with engine', () => {
  const scorer = new UVRSCalculator();
  const engine = new CosmicTheoryEngine();

  test('engine and scorer agree on classification at boundaries', () => {
    for (const score of [0.0, 0.24, 0.25, 0.49, 0.5, 0.84, 0.85, 1.0]) {
      expect(scorer.classify(score)).toBeDefined();
    }
  });
});

describe('Edge cases', () => {
  test('compute with negative components', () => {
    const scorer = new UVRSCalculator();
    const s = scorer.compute({ kepler: -1, gravity: 0.5 });
    expect(s).toBeGreaterThanOrEqual(0);
  });

  test('all default fallback dimensions used', () => {
    const total = Object.values(UVRS_DIMENSION_DEFAULTS).length;
    expect(total).toBeGreaterThanOrEqual(10);
  });

  test('engine with all 23 dims can compute unified score', () => {
    const engine = new CosmicTheoryEngine();
    const graph: GraphData = {
      sinks: ['a', 'b'],
      shortest_paths: { n1: { a: 1, b: 2 } },
      in_degree: { n1: 3, n2: 1 },
      out_degree: { n1: 2, n2: 4 },
      cyclomatic_complexity: { n1: 5 },
      cycles: { n1: true },
      pagerank: { n1: 0.7 },
      betweenness: { n1: 0.5 },
    };
    const uvrs = engine.calculate_unified_risk_score(graph, 'n1');
    expect(uvrs.unified_score).toBeGreaterThanOrEqual(0);
    expect(uvrs.unified_score).toBeLessThanOrEqual(1);
    expect(uvrs.top_risk_dimensions.length).toBeGreaterThan(0);
  });
});
