import { describe, it, expect } from 'bun:test';

describe('estimateCostUsd', () => {
  it('computes cost for a known model (gpt-4o)', async () => {
    const { estimateCostUsd } = await import('../../../src/llm/security.js');
    const cost = estimateCostUsd('gpt-4o', 1_000_000, 0);
    expect(cost).toBeCloseTo(5.0, 4);
  });

  it('throws on unknown model (no silent low-bill)', async () => {
    const { estimateCostUsd } = await import('../../../src/llm/security.js');
    expect(() => estimateCostUsd('unknown-model', 1000, 500)).toThrow(/unknown|not configured/i);
  });

  it('does not fallback to cheapest model on unknown', async () => {
    const { estimateCostUsd } = await import('../../../src/llm/security.js');
    let thrown = false;
    try { estimateCostUsd('totally-fake', 1, 1); } catch { thrown = true; }
    expect(thrown).toBe(true);
  });

  it('claude-sonnet-4-5 is more expensive than glm-5.1', async () => {
    const { estimateCostUsd } = await import('../../../src/llm/security.js');
    const sonnet = estimateCostUsd('claude-sonnet-4-5', 1_000_000, 0);
    const glm = estimateCostUsd('glm-5.1', 1_000_000, 0);
    expect(sonnet).toBeGreaterThan(glm);
  });
});
