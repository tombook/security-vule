import { describe, expect, test } from 'bun:test';
import { RenormalizationDimension } from '../../../../src/engine/dimensions/renormalization.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('RenormalizationDimension', () => {
  test('weight is 0.02', () => expect(new RenormalizationDimension().weight).toBe(0.02));
  test('zero = 0', () => {
    expect(new RenormalizationDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('high aggregate = 1', () => {
    expect(new RenormalizationDimension().compute(n({ instruction_complexity: 10, block_complexity: 10, function_complexity: 10, module_complexity: 10 }), {} as CPG)).toBe(1);
  });
  test('output clamped to [0,1]', () => {
    expect(new RenormalizationDimension().compute(n({ instruction_complexity: 999, block_complexity: 999, function_complexity: 999, module_complexity: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});