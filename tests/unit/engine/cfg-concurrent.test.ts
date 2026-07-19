import { describe, it, expect } from 'bun:test';

describe('CFG concurrent ID safety', () => {
  it('generates unique IDs across concurrent builds', async () => {
    const { buildCFG } = await import('../../../src/engine/cfg.js');
    const { parse } = await import('../../../src/engine/parser.js');

    const sources = [
      'function a() { return 1; }',
      'function b() { return 2; }',
      'function c() { return 3; }',
      'class D { x() { return 4; } }',
      'const e = () => 5;',
    ];

    const results = await Promise.all(sources.map((src) => {
      const parsed = parse(src, 'javascript');
      return buildCFG(parsed.ast);
    }));

    const allIds: string[] = [];
    for (const cfg of results) {
      for (const id of cfg.nodes.keys()) allIds.push(id);
    }
    const uniqueIds = new Set(allIds);
    expect(uniqueIds.size).toBe(allIds.length);
  });
});
