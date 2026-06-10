import { describe, expect, test } from 'bun:test';
import { PhaseTransitionDimension } from '../../../../src/engine/dimensions/phase-transition.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('PhaseTransitionDimension', () => {
  test('weight is 0.02', () => expect(new PhaseTransitionDimension().weight).toBe(0.02));
  test('isolated node with low coupling = high risk (no defense)', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    const v = new PhaseTransitionDimension().compute(cpg.getNode('x')!, cpg);
    // exp(0) = 1
    expect(v).toBeCloseTo(1);
  });
  test('high audit pressure = low risk', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { coupling: 0, audit_pressure: 10 } }]]),
      [], 'php'
    );
    const v = new PhaseTransitionDimension().compute(cpg.getNode('x')!, cpg);
    // exp(-10/10) = exp(-1) ≈ 0.368
    expect(v).toBeLessThan(0.5);
  });
  test('neighbors multiply coupling', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { coupling: 2 } }],
        ['y', { id: 'y', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
        ['z', { id: 'z', type: 'stmt', file: 'a', line: 3, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'x', target: 'y', kind: 'data' },
        { source: 'z', target: 'x', kind: 'data' },
      ], 'php'
    );
    const v = new PhaseTransitionDimension().compute(cpg.getNode('x')!, cpg);
    // x: outDegree=1, inDegree=1, total neighbors=2, J=2, h=0: exp(-4/10) ≈ 0.67
    expect(v).toBeGreaterThan(0.6);
    expect(v).toBeLessThan(0.75);
  });
});