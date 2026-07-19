import { describe, test, expect, mock } from 'bun:test';
import {
  OpenAICompatibleProvider,
  createDeepSeekProvider,
  createQwenProvider,
  createGLMProvider,
  createMoonshotProvider,
  createMiniMaxProvider,
} from '../../../src/llm/providers/openai-compatible.js';

describe('openai-compatible: provider factory functions', () => {
  test('createDeepSeekProvider returns valid provider', () => {
    const p = createDeepSeekProvider('test-key');
    expect(p).toBeDefined();
    expect(p.name).toBe('openai-compatible');
  });

  test('createQwenProvider returns valid provider', () => {
    const p = createQwenProvider('test-key');
    expect(p).toBeDefined();
  });

  test('createGLMProvider returns valid provider', () => {
    const p = createGLMProvider('test-key');
    expect(p).toBeDefined();
  });

  test('createMoonshotProvider returns valid provider', () => {
    const p = createMoonshotProvider('test-key');
    expect(p).toBeDefined();
  });

  test('createMiniMaxProvider returns valid provider', () => {
    const p = createMiniMaxProvider('test-key');
    expect(p).toBeDefined();
  });

  test('constructor throws on empty API key (no env fallback)', () => {
    expect(() => new OpenAICompatibleProvider({
      label: 'Test',
      apiKey: '',
      baseURL: 'https://api.test.com',
      defaultModel: 'test-model',
    })).toThrow();
  });
});

describe('openai-compatible: OpenAICompatibleProvider', () => {
  test('constructor throws on empty API key', () => {
    expect(() => new OpenAICompatibleProvider({
      label: 'Test',
      apiKey: '',
      baseURL: 'https://api.test.com',
      defaultModel: 'test-model',
    })).toThrow();
  });

  test('constructor accepts valid config', () => {
    const p = new OpenAICompatibleProvider({
      label: 'Test',
      apiKey: 'sk-test',
      baseURL: 'https://api.test.com',
      defaultModel: 'test-model',
    });
    expect(p.name).toBe('openai-compatible');
  });

  test('default model is set from config', () => {
    const p = new OpenAICompatibleProvider({
      label: 'Test',
      apiKey: 'sk-test',
      baseURL: 'https://api.test.com',
      defaultModel: 'custom-model',
    });
    expect(p).toBeDefined();
  });

  test('accepts custom model list', () => {
    const models = [
      { id: 'model-1', name: 'Model 1', provider: 'openai-compatible' as const, capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 8000 } },
      { id: 'model-2', name: 'Model 2', provider: 'openai-compatible' as const, capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 16000 } },
    ];
    const p = new OpenAICompatibleProvider({
      label: 'Test',
      apiKey: 'sk-test',
      baseURL: 'https://api.test.com',
      defaultModel: 'model-1',
      models,
    });
    expect(p).toBeDefined();
  });
});
