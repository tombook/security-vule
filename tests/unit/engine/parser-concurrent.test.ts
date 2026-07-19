import { describe, it, expect } from 'bun:test';

function collectIds(node: any, out: string[] = []): string[] {
  if (node && typeof node === 'object') {
    if (typeof node.id === 'string') out.push(node.id);
    if (Array.isArray(node.children)) for (const c of node.children) collectIds(c, out);
  }
  return out;
}

describe('Parser concurrent ID safety', () => {
  it('generates unique IDs across concurrent parses', async () => {
    const { parse } = await import('../../../src/engine/parser.js');
    const sources = [
      'function a() { return 1; }',
      'function b() { return 2; }',
      'function c() { return 3; }',
      'class D { x() { return 4; } }',
      'const e = () => 5;',
    ];

    const results = await Promise.all(sources.map((src) => parse(src, 'javascript')));

    const allIds: string[] = [];
    for (const r of results) {
      const ids = collectIds(r.ast);
      allIds.push(...ids);
    }
    const uniqueIds = new Set(allIds);
    expect(uniqueIds.size).toBe(allIds.length);
  });
});
