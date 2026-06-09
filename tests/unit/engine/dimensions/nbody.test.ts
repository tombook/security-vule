import { describe, expect, test } from 'bun:test';
import { NBodyDimension } from '../../../../src/engine/dimensions/nbody.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function node(id: string): CPGNode {
  return { id, type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} };
}

describe('NBodyDimension', () => {
  test('weight is 0.10', () => {
    expect(new NBodyDimension().weight).toBe(0.10);
  });
  test('without consensus context, returns 0', () => {
    const dim = new NBodyDimension();
    expect(dim.compute(node('x'), {} as CPG)).toBe(0);
  });
  test('with consensusMap, returns agreement score', () => {
    const dim = new NBodyDimension();
    dim.setConsensusContext({ x: 0.85 });
    expect(dim.compute(node('x'), {} as CPG)).toBe(0.85);
  });
  test('clamps to [0,1]', () => {
    const dim = new NBodyDimension();
    dim.setConsensusContext({ y: 1.5 });
    expect(dim.compute(node('y'), {} as CPG)).toBeLessThanOrEqual(1);
    dim.setConsensusContext({ z: -0.5 });
    expect(dim.compute(node('z'), {} as CPG)).toBeGreaterThanOrEqual(0);
  });
  test('different node IDs are independent', () => {
    const dim = new NBodyDimension();
    dim.setConsensusContext({ x: 0.9, y: 0.1 });
    expect(dim.compute(node('x'), {} as CPG)).toBe(0.9);
    expect(dim.compute(node('y'), {} as CPG)).toBe(0.1);
    expect(dim.compute(node('z'), {} as CPG)).toBe(0);
  });
});