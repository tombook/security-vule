/**
 * Property-based tests for CPG (Code Property Graph) roundtrip integrity.
 *
 * Uses fast-check to generate arbitrary inputs and verify invariants.
 */
import { describe, expect, test } from 'bun:test';
import fc from 'fast-check';
import { CPGBuilder, createCPG } from '../../src/engine/cpg/builder.js';
import type { CPG, CPGNode, CPGEdge, CPGNodeType } from '../../src/engine/cpg/types.js';
import { isSinkFunction } from '../../src/engine/cpg/sinks.js';

const validNodeType: fc.Arbitrary<CPGNodeType> = fc.constantFrom('stmt', 'expr', 'func', 'var');
const validLang = fc.constantFrom('php', 'python', 'javascript', 'typescript') as fc.Arbitrary<
  'php' | 'python' | 'javascript' | 'typescript'
>;

describe('CPG property: node preservation', () => {
  test('createCPG preserves node count and IDs', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            id: fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !s.includes('|')),
            type: validNodeType,
            code: fc.string({ maxLength: 100 }),
            complexity: fc.integer({ min: 0, max: 100 }),
          }),
          { minLength: 0, maxLength: 50 }
        ),
        validLang,
        (nodeSpecs, lang) => {
          const nodes = new Map<string, CPGNode>();
          nodeSpecs.forEach((spec, i) => {
            const id = spec.id || `n${i}`;
            nodes.set(id, {
              id,
              type: spec.type,
              file: 'test',
              line: i + 1,
              col: 0,
              code: spec.code,
              language: lang,
              features: { complexity: spec.complexity },
            });
          });
          const cpg = createCPG(nodes, [], lang);
          expect(cpg.nodes.size).toBe(nodeSpecs.length);
          for (const [id] of nodes) {
            expect(cpg.nodes.get(id)).toBeDefined();
            expect(cpg.nodes.get(id)?.id).toBe(id);
          }
        }
      ),
      { numRuns: 100 }
    );
  });

  test('edges are preserved', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(
          fc.tuple(
            fc.string({ minLength: 1, maxLength: 5 }),
            fc.string({ minLength: 1, maxLength: 5 })
          ),
          { minLength: 0, maxLength: 20, selector: (p) => p[0] + '>' + p[1] }
        ),
        (edgePairs) => {
          const nodes = new Map<string, CPGNode>();
          const edges: CPGEdge[] = [];
          for (const [src, tgt] of edgePairs) {
            if (!nodes.has(src)) nodes.set(src, makeNode(src, 'stmt'));
            if (!nodes.has(tgt)) nodes.set(tgt, makeNode(tgt, 'stmt'));
            edges.push({ source: src, target: tgt, kind: 'data' });
          }
          const cpg = createCPG(nodes, edges, 'php');
          expect(cpg.edges.length).toBe(edges.length);
          for (let i = 0; i < edges.length; i++) {
            expect(cpg.edges[i].source).toBe(edges[i].source);
            expect(cpg.edges[i].target).toBe(edges[i].target);
          }
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe('CPG property: degree invariants', () => {
  test('inDegree + outDegree <= total edges', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            id: fc.string({ minLength: 1, maxLength: 10 }).filter((s) => /^[a-z]+$/.test(s)),
          }),
          { minLength: 1, maxLength: 10, selector: (n) => n.id }
        ),
        fc.array(fc.tuple(fc.integer({ min: 0, max: 9 }), fc.integer({ min: 0, max: 9 })), {
          maxLength: 20,
        }),
        (nodeSpecs, edgeIdx) => {
          const nodes = new Map<string, CPGNode>();
          nodeSpecs.forEach((s, i) => nodes.set(s.id, makeNode(s.id, 'stmt')));
          const edges: CPGEdge[] = [];
          for (const [src, tgt] of edgeIdx) {
            if (src < nodeSpecs.length && tgt < nodeSpecs.length && src !== tgt) {
              edges.push({ source: nodeSpecs[src].id, target: nodeSpecs[tgt].id, kind: 'data' });
            }
          }
          const cpg = createCPG(nodes, edges, 'php');
          let totalDegree = 0;
          for (const id of cpg.nodes.keys()) {
            totalDegree += cpg.inDegree(id) + cpg.outDegree(id);
          }
          // Each edge contributes 1 to inDegree and 1 to outDegree
          expect(totalDegree).toBe(2 * edges.length);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe('CPG property: shortest path invariants', () => {
  test('shortestPath(self, self) returns [self]', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 10 }).filter((s) => /^[a-z]+$/.test(s)),
        (id) => {
          const nodes = new Map<string, CPGNode>();
          nodes.set(id, makeNode(id, 'stmt'));
          const cpg = createCPG(nodes, [], 'php');
          const path = cpg.shortestPath(id, id);
          expect(path).toEqual([id]);
        }
      ),
      { numRuns: 50 }
    );
  });

  test('shortestPath path length is at least 1 for distinct nodes', () => {
    fc.assert(
      fc.property(
        fc
          .tuple(
            fc.string({ minLength: 1, maxLength: 5 }).filter((s) => /^[a-z]+$/.test(s)),
            fc.string({ minLength: 1, maxLength: 5 }).filter((s) => /^[a-z]+$/.test(s))
          )
          .filter(([a, b]) => a !== b),
        ([src, tgt]) => {
          const nodes = new Map<string, CPGNode>();
          nodes.set(src, makeNode(src, 'stmt'));
          nodes.set(tgt, makeNode(tgt, 'stmt'));
          // Linear chain
          nodes.set('mid', makeNode('mid', 'stmt'));
          const edges: CPGEdge[] = [
            { source: src, target: 'mid', kind: 'data' },
            { source: 'mid', target: tgt, kind: 'data' },
          ];
          const cpg = createCPG(nodes, edges, 'php');
          const path = cpg.shortestPath(src, tgt);
          expect(path).not.toBeNull();
          expect(path!.length).toBe(3);
          expect(path![0]).toBe(src);
          expect(path![path!.length - 1]).toBe(tgt);
        }
      ),
      { numRuns: 50 }
    );
  });

  test('shortestPath returns null for disconnected nodes', () => {
    fc.assert(
      fc.property(
        fc
          .tuple(
            fc.string({ minLength: 1, maxLength: 5 }).filter((s) => /^[a-z]+$/.test(s)),
            fc.string({ minLength: 1, maxLength: 5 }).filter((s) => /^[a-z]+$/.test(s))
          )
          .filter(([a, b]) => a !== b),
        ([src, tgt]) => {
          const nodes = new Map<string, CPGNode>();
          nodes.set(src, makeNode(src, 'stmt'));
          nodes.set(tgt, makeNode(tgt, 'stmt'));
          const cpg = createCPG(nodes, [], 'php');
          const path = cpg.shortestPath(src, tgt);
          expect(path).toBeNull();
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe('CPG property: sink function detection', () => {
  test('isSinkFunction handles arbitrary strings without crashing', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 50 }), validLang, (name, lang) => {
        // Should not throw
        const result = isSinkFunction(name, lang);
        expect(typeof result).toBe('boolean');
      }),
      { numRuns: 100 }
    );
  });

  test('isSinkFunction: known dangerous functions are detected', () => {
    const dangerous = ['mysql_query', 'shell_exec', 'eval', 'os.system'];
    const langs = ['php', 'python', 'typescript', 'javascript'] as const;
    for (const lang of langs) {
      for (const fn of dangerous) {
        // At least one lang should match each function
        const anyMatch = langs.some((l) => isSinkFunction(fn, l));
        expect(anyMatch).toBe(true);
      }
    }
  });
});

describe('CPG property: downDegree <= total nodes', () => {
  test('downstreamNodes result is subset of all node IDs', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(
          fc.string({ minLength: 1, maxLength: 5 }).filter((s) => /^[a-z]+$/.test(s)),
          { minLength: 1, maxLength: 15, selector: (s) => s }
        ),
        fc.array(fc.tuple(fc.integer({ min: 0, max: 14 }), fc.integer({ min: 0, max: 14 })), {
          maxLength: 30,
        }),
        (ids, edgeIdx) => {
          const nodes = new Map<string, CPGNode>();
          ids.forEach((id) => nodes.set(id, makeNode(id, 'stmt')));
          const edges: CPGEdge[] = [];
          for (const [s, t] of edgeIdx) {
            if (s < ids.length && t < ids.length) {
              edges.push({ source: ids[s], target: ids[t], kind: 'data' });
            }
          }
          const cpg = createCPG(nodes, edges, 'php');
          for (const id of ids) {
            // Get downstream via the public API
            const out: string[] = [];
            const visited = new Set<string>([id]);
            const stack = [id];
            while (stack.length) {
              const cur = stack.pop()!;
              for (const e of cpg.outEdges(cur)) {
                if (!visited.has(e.target)) {
                  visited.add(e.target);
                  out.push(e.target);
                  stack.push(e.target);
                }
              }
            }
            for (const d of out) {
              expect(cpg.nodes.has(d)).toBe(true);
            }
          }
        }
      ),
      { numRuns: 30 }
    );
  });
});

function makeNode(id: string, type: CPGNodeType): CPGNode {
  return {
    id,
    type,
    file: 'test',
    line: 1,
    col: 0,
    code: '',
    language: 'php',
    features: {},
  };
}
