import { describe, expect, test } from 'bun:test';
import { LLMRouter } from '../../../src/llm/router.js';
import type { ChatRequest, ChatResponse } from '../../../src/llm/types.js';
import { LLMError } from '../../../src/llm/types.js';

interface MockProviderProto {
  chat(request: ChatRequest): Promise<ChatResponse>;
  listModels(): Array<{ id: string; name: string; contextWindow: number; inputPrice: number; outputPrice: number }>;
}

function createMockProvider(name: string, shouldFail = false): MockProviderProto {
  return {
    chat: async (request: ChatRequest): Promise<ChatResponse> => {
      if (shouldFail) {
        throw new LLMError('Mock error', 'provider_error', name as any, 500, true);
      }
      return {
        content: `response to: ${request.messages[request.messages.length - 1].content.slice(0, 30)}`,
        model: request.model || 'mock-model',
        provider: name as any,
        usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
      };
    },
    listModels: () => [{ id: 'mock-v1', name: 'Mock v1', contextWindow: 4096, inputPrice: 0, outputPrice: 0 }],
  };
}

describe('LLMRouter', () => {
  test('routes to a registered provider', async () => {
    const router = new LLMRouter();
    router.registerProvider('mock', createMockProvider('mock') as any);
    const response = await router.chat({ messages: [{ role: 'user', content: 'hello' }] });
    expect(response.content.includes('response to')).toBe(true);
  });

  test('throws when no providers available', async () => {
    const router = new LLMRouter();
    let threw = false;
    try { await router.chat({ messages: [{ role: 'user', content: 'fail' }] }); } catch { threw = true; }
    expect(threw).toBe(true);
  });

  test('returns correct token usage', async () => {
    const router = new LLMRouter();
    router.registerProvider('mock', createMockProvider('mock') as any);
    const response = await router.chat({ messages: [{ role: 'user', content: 'usage test' }] });
    expect(response.usage.totalTokens).toBe(150);
    expect(response.usage.promptTokens).toBe(100);
    expect(response.usage.completionTokens).toBe(50);
  });

  test('can register multiple providers', async () => {
    const router = new LLMRouter();
    router.registerProvider('mock1', createMockProvider('mock1') as any);
    router.registerProvider('mock2', createMockProvider('mock2') as any);
    const response = await router.chat({ messages: [{ role: 'user', content: 'multi test' }] });
    expect(response.content.includes('response to')).toBe(true);
  });
});

describe('LLMError', () => {
  test('preserves error properties', () => {
    const err = new LLMError('test error', 'rate_limit', 'openai' as any, 429, true);
    expect(err.message).toBe('test error');
    expect(err.type).toBe('rate_limit');
    expect(err.provider).toBe('openai');
    expect(err.statusCode).toBe(429);
    expect(err.retryable).toBe(true);
  });
});
