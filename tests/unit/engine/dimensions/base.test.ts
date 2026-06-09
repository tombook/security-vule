import { describe, expect, test } from 'bun:test';
import { BaseDimension } from '../../../../src/engine/dimensions/base.js';
import type { CPG, CPGNode } from '../../../../src/engine/cpg/types.js';

class TestDim extends BaseDimension {
  readonly name = 'test';
  readonly weight = 0.5;
  compute(node: CPGNode, _cpg: CPG): number {
    return (node.features['risk'] || 0) * 0.5;
  }
}

describe('BaseDimension', () => {
  test('name and weight are exposed', () => {
    const d = new TestDim();
    expect(d.name).toBe('test');
    expect(d.weight).toBe(0.5);
  });
  test('compute returns numeric contribution', () => {
    const d = new TestDim();
    const node: CPGNode = { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { risk: 1 } };
    expect(d.compute(node, {} as any)).toBe(0.5);
  });
  test('cannot instantiate BaseDimension directly (abstract)', () => {
    expect(() => {
      new (class extends BaseDimension {
        readonly name = 'x';
        readonly weight = 0;
        compute(): number { return 0; }
      })();
    }).not.toThrow();
  });
});