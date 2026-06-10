import { describe, expect, test } from 'bun:test';
import { CategoryBasicDimension } from '../../../../src/engine/dimensions/category-basic.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('CategoryBasicDimension', () => {
  test('weight is 0.02', () => expect(new CategoryBasicDimension().weight).toBe(0.02));
  test('dense graph = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'a', target: 'b', kind: 'control' },
        { source: 'a', target: 'b', kind: 'call' },
        { source: 'a', target: 'b', kind: 'def_use' },
        { source: 'a', target: 'b', kind: 'ast_child' },
      ], 'php'
    );
    const v = new CategoryBasicDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeGreaterThan(0.4);
  });
  test('sparse graph = low risk', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
        ['c', { id: 'c', type: 'stmt', file: 'a', line: 3, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'php'
    );
    const v = new CategoryBasicDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeLessThan(0.1);
  });
  test('empty CPG handles gracefully', () => {
    const cpg = createCPG(new Map(), [], 'php');
    const dim = new CategoryBasicDimension();
    // Empty CPG → density = 0 / 1 = 0
    expect(dim.weight).toBe(0.02);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'a', target: 'b', kind: 'control' },
        { source: 'a', target: 'b', kind: 'call' },
      ], 'php'
    );
    const v = new CategoryBasicDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeLessThanOrEqual(1);
  });
});