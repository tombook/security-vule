import { describe, expect, test } from 'bun:test';
import { TransferDimension } from '../../../../src/engine/dimensions/transfer.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('TransferDimension', () => {
  test('weight is 0.02', () => expect(new TransferDimension().weight).toBe(0.02));
  test('no cross-file = 0', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    expect(new TransferDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('cross-file calls > files = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: { cross_file_calls: 5 } }],
        ['y', { id: 'y', type: 'stmt', file: 'b.php', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [], 'php'
    );
    const v = new TransferDimension().compute(cpg.getNode('x')!, cpg);
    // 5 calls / 2 files = 2.5 → clamped to 1
    expect(v).toBe(1);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: { cross_file_calls: 999 } }],
      ]),
      [], 'php'
    );
    expect(new TransferDimension().compute(cpg.getNode('x')!, cpg)).toBeLessThanOrEqual(1);
  });
});