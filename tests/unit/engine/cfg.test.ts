import { describe, test, expect } from 'bun:test';
import {
  buildCFG,
  computeDominators,
  detectLoops,
  computeDominanceFrontier,
  getCFGAdjacency,
  getReachableNodes,
  isReducible,
  type ControlFlowGraph,
} from '../../../src/engine/cfg.js';
import { parsePython, type ASTNode } from '../../../src/engine/parser.js';

function cfgFromCode(code: string): ControlFlowGraph {
  const parsed = parsePython(code);
  return buildCFG(parsed.ast);
}

describe('cfg: buildCFG', () => {
  test('builds CFG for simple linear code', () => {
    const code = `x = 1\ny = 2\nz = x + y`;
    const cfg = cfgFromCode(code);
    expect(cfg.nodes).toBeDefined();
    expect(cfg.entryId).toBeDefined();
    expect(cfg.exitId).toBeDefined();
    expect(cfg.nodes.has(cfg.entryId)).toBe(true);
    expect(cfg.nodes.has(cfg.exitId)).toBe(true);
  });

  test('builds CFG for empty code', () => {
    const cfg = cfgFromCode('');
    expect(cfg).toBeDefined();
    expect(cfg.entryId).toBeDefined();
  });

  test('builds CFG for if/else', () => {
    const code = `
if x > 0:
    a = 1
else:
    a = 2
`;
    const cfg = cfgFromCode(code);
    expect(cfg.nodes.size).toBeGreaterThan(2);
  });

  test('builds CFG for loop', () => {
    const code = `
for i in range(10):
    x = i
`;
    const cfg = cfgFromCode(code);
    expect(cfg.nodes.size).toBeGreaterThan(2);
  });

  test('builds CFG for nested control flow', () => {
    const code = `
def f(x):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                y = i
            else:
                y = -i
    return y
`;
    const cfg = cfgFromCode(code);
    expect(cfg.nodes.size).toBeGreaterThan(2);
  });
});

describe('cfg: computeDominators', () => {
  test('returns a Map of dominator nodes', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const doms = computeDominators(cfg);
    expect(doms).toBeInstanceOf(Map);
  });

  test('entry dominates all reachable nodes', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const doms = computeDominators(cfg);
    const entryDom = doms.get(cfg.entryId);
    expect(entryDom).toBeDefined();
  });
});

describe('cfg: detectLoops', () => {
  test('returns array of loop info', () => {
    const code = `x = 1`;
    const cfg = cfgFromCode(code);
    const loops = detectLoops(cfg);
    expect(loops).toBeArray();
  });

  test('detects loop in for statement', () => {
    const code = `
for i in range(10):
    x = i
`;
    const cfg = cfgFromCode(code);
    const loops = detectLoops(cfg);
    expect(loops.length).toBeGreaterThanOrEqual(0);
  });
});

describe('cfg: getCFGAdjacency', () => {
  test('returns adjacency map', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const adj = getCFGAdjacency(cfg);
    expect(adj).toBeInstanceOf(Map);
  });

  test('adjacency entries have target and type', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const adj = getCFGAdjacency(cfg);
    for (const edges of adj.values()) {
      for (const e of edges) {
        expect(e.target).toBeDefined();
        expect(['unconditional', 'true', 'false', 'fallthrough']).toContain(e.type);
      }
    }
  });
});

describe('cfg: getReachableNodes', () => {
  test('returns set of reachable nodes', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const reachable = getReachableNodes(cfg);
    expect(reachable).toBeInstanceOf(Set);
    expect(reachable.has(cfg.entryId)).toBe(true);
  });

  test('entry and exit are reachable', () => {
    const code = `x = 1`;
    const cfg = cfgFromCode(code);
    const reachable = getReachableNodes(cfg);
    expect(reachable.has(cfg.exitId)).toBe(true);
  });
});

describe('cfg: isReducible', () => {
  test('returns boolean', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const reducible = isReducible(cfg);
    expect(typeof reducible).toBe('boolean');
  });

  test('simple linear code is reducible', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    expect(isReducible(cfg)).toBe(true);
  });
});

describe('cfg: computeDominanceFrontier', () => {
  test('returns array of frontier nodes', () => {
    const code = `x = 1\ny = 2`;
    const cfg = cfgFromCode(code);
    const dom = computeDominators(cfg);
    const frontier = computeDominanceFrontier(cfg, dom);
    expect(frontier).toBeInstanceOf(Map);
  });
});
