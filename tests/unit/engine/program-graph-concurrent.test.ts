import { describe, it, expect } from 'bun:test';

describe('ProgramGraph concurrent ID safety', () => {
  it('generates unique IDs across concurrent builds', async () => {
    const { buildProgramGraph } = await import('../../../src/engine/program-graph.js');
    const { parse } = await import('../../../src/engine/parser.js');

    const sources = [
      'function a() { return 1; }',
      'function b() { return 2; }',
      'function c() { return 3; }',
      'class D { x() { return 4; } }',
      'const e = () => 5;',
    ];

    const results = await Promise.all(sources.map(async (src) => {
      const parsed = parse(src, 'javascript');
      return buildProgramGraph(parsed.ast, undefined, src);
    }));

    const allIds: string[] = [];
    for (const pg of results) {
      for (const id of pg.nodes.keys()) allIds.push(id);
    }
    const uniqueIds = new Set(allIds);
    expect(uniqueIds.size).toBe(allIds.length);
  });
});
