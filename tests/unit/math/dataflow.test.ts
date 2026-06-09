/**
 * tests/unit/math/dataflow.test.ts — 数据流分析单元测试
 *
 * 数学等价验证 (math-underneath.md §1):
 *   - reaching definitions 的前向传播 + kill 规则
 *   - live variables 的后向传播
 *   - DU chain 的配对
 *   - 死代码检测
 */

import { describe, expect, test } from 'bun:test';
import {
  analyzeDataFlow,
  buildDefUseChains,
  extractDefs,
  extractUses,
  findDefiningLine,
  findUninitializedUses,
  liveVariables,
  reachingDefinitions,
  varsUsedAt,
} from '../../../src/math/execution/dataflow';

describe('dataflow > extractDefs / extractUses', () => {
  test('extractDefs captures assignments', () => {
    const defs = extractDefs('const x = 5;', 1);
    expect(defs).toHaveLength(1);
    expect(defs[0].variable).toBe('x');
    expect(defs[0].line).toBe(1);
  });

  test('extractDefs skips function declarations', () => {
    const defs = extractDefs('function foo() { return 1; }', 1);
    expect(defs).toHaveLength(0);
  });

  test('extractUses finds reads in expressions', () => {
    const uses = extractUses('const y = x + 1;', 1);
    const reads = uses.filter(u => u.kind === 'read');
    expect(reads.some(r => r.variable === 'x')).toBe(true);
  });
});

describe('dataflow > reachingDefinitions', () => {
  test('propagates defs forward', () => {
    const code = ['const x = 1;', 'const y = x + 1;', 'const z = y + 1;'];
    const reach = reachingDefinitions(code);
    // line 3 之前, x@1, y@2 都能到达
    const at3 = [...(reach.get(3) ?? [])];
    expect(at3.some(d => d.variable === 'x' && d.line === 1)).toBe(true);
    expect(at3.some(d => d.variable === 'y' && d.line === 2)).toBe(true);
  });

  test('kills old defs when new def appears', () => {
    const code = ['const x = 1;', 'const x = 2;', 'const y = x;'];
    const reach = reachingDefinitions(code);
    // line 3 之前, x@1 应该被 x@2 杀掉
    const at3 = [...(reach.get(3) ?? [])];
    const xDefs = at3.filter(d => d.variable === 'x');
    // 至少保证只有一个 x def 到达 (line 2), 或者 line 2 之前的 line 1 已经被 killed
    expect(xDefs.every(d => d.line === 2)).toBe(true);
  });
});

describe('dataflow > liveVariables', () => {
  test('propagates liveness backward', () => {
    const code = ['const x = 1;', 'const y = 2;', 'console.log(x, y);'];
    const live = liveVariables(code);
    // line 3 之前 x, y 活跃 (line 3 读 x, y)
    const at3 = [...(live.get(3) ?? [])];
    expect(at3).toContain('x');
    expect(at3).toContain('y');
  });
});

describe('dataflow > buildDefUseChains', () => {
  test('matches defs to subsequent uses', () => {
    const code = ['const x = 1;', 'const y = x;'];
    const chains = buildDefUseChains(code);
    const xChain = chains.find(c => c.def.variable === 'x');
    expect(xChain).toBeDefined();
    expect(xChain!.uses.length).toBeGreaterThan(0);
    expect(xChain!.uses.some(u => u.line === 2)).toBe(true);
  });
});

describe('dataflow > findUninitializedUses', () => {
  test('flags use before def', () => {
    const code = ['console.log(x);', 'const x = 1;'];
    const reach = reachingDefinitions(code);
    const allUses = code.flatMap((l, i) => extractUses(l, i + 1));
    const uninit = findUninitializedUses(code, reach, allUses);
    expect(uninit.some(u => u.variable === 'x' && u.line === 1)).toBe(true);
  });
});

describe('dataflow > analyzeDataFlow', () => {
  test('returns complete result', () => {
    const code = [
      'const x = req.params.id;',     // line 1
      'if (x) {',                     // line 2
      '  const q = x;',               // line 3
      '  db.query(q);',               // line 4
      '}',                             // line 5
    ];
    const r = analyzeDataFlow(code);
    expect(r.reachingDefs.size).toBe(5);
    expect(r.liveVars.size).toBe(5);
    expect(r.defUseChains.length).toBeGreaterThan(0);
    expect(Array.isArray(r.variableStats)).toBe(true);
  });
});

describe('dataflow > helpers', () => {
  test('findDefiningLine returns most recent def', () => {
    const code = ['const x = 1;', 'const y = 2;', 'console.log(x);'];
    expect(findDefiningLine(code, 3, 'x')).toBe(1);
    expect(findDefiningLine(code, 3, 'undefined_var')).toBe(0);
  });

  test('varsUsedAt returns identifiers read at line', () => {
    const code = ['const x = 1;', 'console.log(x + y);'];
    expect(varsUsedAt(code, 2)).toContain('x');
  });
});
