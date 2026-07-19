import { describe, it, expect, beforeEach } from 'bun:test';

describe('cosm-x-evolver auto-execution', () => {
  beforeEach(() => {
  });

  it('should NOT auto-execute runEvolution() on import (DoS prevention)', async () => {
    const startTime = Date.now();
    await import('../../../src/evolution/cosm-x-evolver');
    const importDuration = Date.now() - startTime;

    expect(importDuration).toBeLessThan(500);
  });

  it('should expose runEvolution as exported function', async () => {
    const mod = await import('../../../src/evolution/cosm-x-evolver');
    expect(typeof mod.runEvolution).toBe('function');
  });
});
