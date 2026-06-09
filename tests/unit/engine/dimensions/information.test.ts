import { describe, expect, test } from 'bun:test';
import { InformationDimension } from '../../../../src/engine/dimensions/information.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('InformationDimension', () => {
  test('weight is 0.04', () => expect(new InformationDimension().weight).toBe(0.04));
  test('undefined entropy = 0', () => {
    expect(new InformationDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('optimal entropy (4.5) = 0 risk', () => {
    expect(new InformationDimension().compute(n({ token_entropy: 4.5 }), {} as CPG)).toBe(0);
  });
  test('extreme entropy (7.5) = 1 risk', () => {
    expect(new InformationDimension().compute(n({ token_entropy: 7.5 }), {} as CPG)).toBe(1);
  });
  test('low entropy (1.5) = 1 risk (auto-generated)', () => {
    expect(new InformationDimension().compute(n({ token_entropy: 1.5 }), {} as CPG)).toBe(1);
  });
});