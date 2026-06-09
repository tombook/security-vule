import { describe, expect, test } from 'bun:test';
import type { CPGNode, CPGEdge, CPG } from '../../../../src/engine/cpg/types.js';

describe('CPG types', () => {
  test('CPGNode is constructible with required fields', () => {
    const node: CPGNode = {
      id: 'n1',
      type: 'stmt',
      file: 'a.php',
      line: 1,
      col: 0,
      code: 'mysql_query($q);',
      language: 'php',
      features: { complexity: 2 },
    };
    expect(node.id).toBe('n1');
    expect(node.features.complexity).toBe(2);
  });

  test('CPGEdge supports 5 kinds', () => {
    const kinds: Array<CPGEdge['kind']> = ['data', 'control', 'call', 'def_use', 'ast_child'];
    expect(kinds).toHaveLength(5);
  });
});