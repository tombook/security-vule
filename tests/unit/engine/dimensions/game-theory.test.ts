import { describe, expect, test } from 'bun:test';
import { GameTheoryDimension } from '../../../../src/engine/dimensions/game-theory.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('GameTheoryDimension', () => {
  test('weight is 0.02', () => expect(new GameTheoryDimension().weight).toBe(0.02));
  test('zero payoff = 0.5 (neutral)', () => {
    expect(new GameTheoryDimension().compute(n(), {} as CPG)).toBe(0.5);
  });
  test('strong attacker = high risk', () => {
    const v = new GameTheoryDimension().compute(n({ exploit_value: 100, attack_cost: 1, defense_strength: 0, defense_cost: 1 }), {} as CPG);
    expect(v).toBeGreaterThan(0.9);
  });
  test('strong defender = low risk', () => {
    const v = new GameTheoryDimension().compute(n({ exploit_value: 1, attack_cost: 1, defense_strength: 100, defense_cost: 1 }), {} as CPG);
    expect(v).toBeLessThan(0.1);
  });
  test('output clamped to [0,1]', () => {
    expect(new GameTheoryDimension().compute(n({ exploit_value: 999, defense_strength: 0 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});