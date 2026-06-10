import { describe, expect, test } from 'bun:test';
import { SymbolicExecDimension } from '../../../../src/engine/dimensions/symbolic-exec.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features };
}

describe('SymbolicExecDimension', () => {
  test('weight is 0.03', () => expect(new SymbolicExecDimension().weight).toBe(0.03));
  test('no info = 0', () => {
    expect(new SymbolicExecDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('many paths + violations = high risk', () => {
    expect(new SymbolicExecDimension().compute(n({ path_count: 1024, solver_violations: 3 }), {} as CPG)).toBeGreaterThan(0.5);
  });
  test('path_count alone contributes (log scale)', () => {
    expect(new SymbolicExecDimension().compute(n({ path_count: 1024 }), {} as CPG)).toBe(1);
  });
  test('output clamped to [0,1]', () => {
    expect(new SymbolicExecDimension().compute(n({ path_count: 999999, solver_violations: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});