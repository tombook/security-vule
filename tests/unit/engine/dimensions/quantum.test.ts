import { describe, expect, test } from 'bun:test';
import { QuantumDimension } from '../../../../src/engine/dimensions/quantum.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('QuantumDimension', () => {
  test('weight is 0.07', () => expect(new QuantumDimension().weight).toBe(0.07));
  test('no concurrency = 0', () => {
    expect(new QuantumDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('5 concurrency features = 1', () => {
    expect(new QuantumDimension().compute(n({ shared_state: 3, async_await: 2 }), {} as CPG)).toBe(1);
  });
  test('threads alone contributes', () => {
    expect(new QuantumDimension().compute(n({ threads: 5 }), {} as CPG)).toBe(1);
  });
  test('output clamped to [0,1]', () => {
    expect(new QuantumDimension().compute(n({ shared_state: 99, async_await: 99, threads: 99 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});