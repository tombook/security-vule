import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

describe('Provider factory with missing key', () => {
  let originals: Record<string, string | undefined> = {};

  beforeEach(() => {
    originals = {
      DEEPSEEK_API_KEY: process.env.DEEPSEEK_API_KEY,
      DASHSCOPE_API_KEY: process.env.DASHSCOPE_API_KEY,
      ZHIPU_API_KEY: process.env.ZHIPU_API_KEY,
      ZHIPU_CODING_API_KEY: process.env.ZHIPU_CODING_API_KEY,
      MOONSHOT_API_KEY: process.env.MOONSHOT_API_KEY,
      MINIMAX_API_KEY: process.env.MINIMAX_API_KEY,
    };
    delete process.env.DEEPSEEK_API_KEY;
    delete process.env.DASHSCOPE_API_KEY;
    delete process.env.ZHIPU_API_KEY;
    delete process.env.ZHIPU_CODING_API_KEY;
    delete process.env.MOONSHOT_API_KEY;
    delete process.env.MINIMAX_API_KEY;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(originals)) {
      if (v !== undefined) process.env[k] = v; else delete process.env[k];
    }
  });

  it('DeepSeek provider throws without API key', async () => {
    const mod = await import('../../../src/llm/providers/openai-compatible.js');
    expect(() => mod.createDeepSeekProvider()).toThrow(/api[_ ]?key|DEEPSEEK_API_KEY/i);
  });

  it('GLM provider throws without API key', async () => {
    const mod = await import('../../../src/llm/providers/openai-compatible.js');
    expect(() => mod.createGLMProvider()).toThrow(/api[_ ]?key|ZHIPU_API_KEY/i);
  });

  it('Moonshot provider throws without API key', async () => {
    const mod = await import('../../../src/llm/providers/openai-compatible.js');
    expect(() => mod.createMoonshotProvider()).toThrow(/api[_ ]?key|MOONSHOT_API_KEY/i);
  });

  it('does not silently use dummy string', async () => {
    const mod = await import('../../../src/llm/providers/openai-compatible.js');
    let p: any;
    try { p = mod.createDeepSeekProvider(); } catch { return; }
    expect((p as any).client?.apiKey).not.toBe('dummy');
  });
});
