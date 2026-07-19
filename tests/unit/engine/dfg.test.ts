import { describe, test, expect } from 'bun:test';
import {
  buildDFG,
  reachingDefinitions,
  liveVariableAnalysis,
  forwardAnalysis,
  backwardAnalysis,
  aliasAnalysis,
  type DataFlowResult,
} from '../../../src/engine/dfg.js';
import { CPGBuilder, type CodePropertyGraph } from '../../../src/math/cpg.js';

// 构造一个含函数及其语句/表达式的 CPG (dfg 模块以 node.name 或
// properties.functionName 来定位函数体). 直接复用 CPGBuilder 真实路径.
function buildFooCPG(): CodePropertyGraph {
  const b = new CPGBuilder();
  b.setLanguage('python')
    .addFile('file1', '/tmp/foo.py')
    .addFunction('fn1', 'foo', 1)
    .addStatement('s1', 'let x = 1', 2)
    .addStatement('s2', 'let y = x', 3)
    .addExpression('e1', 'y', 3)
    .addASTEdge('fn1', 's1')
    .addASTEdge('fn1', 's2')
    .addCFGEdge('s1', 's2');
  // 给语句/表达式打 functionName 标签, 模拟真实构造出的 CPG
  for (const id of ['s1', 's2', 'e1']) {
    const n = b.nodes.get(id)!;
    b.nodes.set(id, { ...n, properties: new Map([['functionName', 'foo']]) });
  }
  return b.build();
}

function buildLinearCPG(): CodePropertyGraph {
  // a -> b -> c -> d  线性 CFG
  const b = new CPGBuilder();
  b.setLanguage('python')
    .addFunction('a', 'main', 1)
    .addStatement('b', 'x = 1', 2)
    .addStatement('c', 'y = 2', 3)
    .addStatement('d', 'z = 3', 4)
    .addCFGEdge('b', 'c')
    .addCFGEdge('c', 'd');
  return b.build();
}

describe('dfg: reachingDefinitions', () => {
  test('detects let/const/var assignments inside a function', () => {
    const cpg = buildFooCPG();
    const rd = reachingDefinitions(cpg, 'foo');
    // 'x' 在 s1 定义, 'y' 在 s2 定义
    expect(rd.has('x')).toBe(true);
    expect(rd.get('x')).toEqual(['s1']);
    expect(rd.has('y')).toBe(true);
    expect(rd.get('y')).toEqual(['s2']);
  });

  test('returns empty Map for function with no matching nodes', () => {
    const cpg = buildFooCPG();
    const rd = reachingDefinitions(cpg, 'nonexistentFn');
    expect(rd.size).toBe(0);
  });
});

describe('dfg: liveVariableAnalysis', () => {
  test('captures variables used in Expression nodes', () => {
    const cpg = buildFooCPG();
    const live = liveVariableAnalysis(cpg, 'foo');
    // 表达式 e1 的 code='y' 应让 'y' 出现在 live set 中
    expect(live.has('e1')).toBe(true);
    expect(live.get('e1')!.has('y')).toBe(true);
  });

  test('returns empty Map when no Expression nodes match the function', () => {
    const cpg = buildLinearCPG(); // 只有 Statement, 没有 Expression
    const live = liveVariableAnalysis(cpg, 'main');
    expect(live.size).toBe(0);
  });
});

describe('dfg: buildDFG', () => {
  test('builds DataFlowResult with nodes, edges, reachingDefs, liveVars', () => {
    const cpg = buildFooCPG();
    const dfg: DataFlowResult = buildDFG(cpg, 'foo');

    expect(dfg).toBeDefined();
    expect(dfg.nodes).toBeInstanceOf(Array);
    expect(dfg.edges).toBeInstanceOf(Array);
    expect(dfg.reachingDefs).toBeInstanceOf(Map);
    expect(dfg.liveVars).toBeInstanceOf(Map);

    // Statement 节点映射为 definition, Expression 映射为 use
    const defs = dfg.nodes.filter(n => n.type === 'definition');
    const uses = dfg.nodes.filter(n => n.type === 'use');
    expect(defs.length).toBe(2);
    expect(uses.length).toBe(1);

    // 节点字段完整
    for (const n of dfg.nodes) {
      expect(typeof n.id).toBe('string');
      expect(n.scope).toBe('foo');
      expect(typeof n.line).toBe('number');
    }

    // CFG 边会变成 def-use 边
    expect(dfg.edges.length).toBeGreaterThanOrEqual(1);
    const du = dfg.edges.find(e => e.type === 'def-use');
    expect(du).toBeDefined();
    expect(du!.from).toBe('s1');
    expect(du!.to).toBe('s2');
  });

  test('returns empty nodes/defs/live for unknown function (edges still come from CPG)', () => {
    const cpg = buildFooCPG();
    const dfg = buildDFG(cpg, 'ghost');
    // 没有任何节点匹配 ghost, 因此没有 definition/use 节点
    expect(dfg.nodes.length).toBe(0);
    expect(dfg.reachingDefs.size).toBe(0);
    expect(dfg.liveVars.size).toBe(0);
    // 边是直接从 cpg.edges 投影而来, 与函数名无关
    expect(dfg.edges.length).toBeGreaterThanOrEqual(1);
  });
});

describe('dfg: forwardAnalysis / backwardAnalysis', () => {
  test('forwardAnalysis walks downstream CFG nodes BFS', () => {
    const cpg = buildLinearCPG();
    const reached = forwardAnalysis(cpg, 'b');
    // b -> c -> d 全部可达
    expect(reached.has('b')).toBe(true);
    expect(reached.has('c')).toBe(true);
    expect(reached.has('d')).toBe(true);
    expect(reached.has('a')).toBe(false);
  });

  test('backwardAnalysis walks upstream CFG nodes BFS', () => {
    const cpg = buildLinearCPG();
    const reached = backwardAnalysis(cpg, 'd');
    // 从 d 逆向经 c 到 b
    expect(reached.has('d')).toBe(true);
    expect(reached.has('c')).toBe(true);
    expect(reached.has('b')).toBe(true);
    expect(reached.has('a')).toBe(false);
  });

  test('forward from non-existent node returns singleton set', () => {
    const cpg = buildLinearCPG();
    const reached = forwardAnalysis(cpg, 'missing');
    expect([...reached]).toEqual(['missing']);
  });
});

describe('dfg: aliasAnalysis', () => {
  test('returns true for identical variable names', () => {
    const cpg = buildLinearCPG();
    expect(aliasAnalysis(cpg, 'x', 'x')).toBe(true);
  });

  test('returns true when both names appear in the same CPG node code', () => {
    // 节点 'b' 的 code='x = 1' 同时含 'x' 和 'z'? 这里 'b' 含 'x',
    // 那么 aliasAnalysis(b, 'x', 'z') 应当为 false (不同节点),
    // 但若同节点含两者, 则为 true. 改用含两者的 code 验证该路径.
    const b = new CPGBuilder();
    b.setLanguage('python')
      .addStatement('mixed', 'const x = y;', 1);
    const cpg = b.build();
    expect(aliasAnalysis(cpg, 'x', 'y')).toBe(true);
  });

  test('returns false for disjoint variable names', () => {
    const cpg = buildLinearCPG();
    expect(aliasAnalysis(cpg, 'alpha', 'beta')).toBe(false);
  });
});
