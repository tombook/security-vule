import OpenAI from 'openai';
import type {
  ILLMProvider, LLMProvider, ChatRequest, ChatResponse,
  ChatStreamChunk, LLMModel, ChatMessage,
} from '../types.js';
import { LLMError } from '../types.js';
type LLMErrorKind = 'rate_limit' | 'authentication' | 'invalid_request' | 'model_not_found' | 'context_length_exceeded' | 'timeout' | 'network' | 'unknown';

export class OpenAICompatibleProvider implements ILLMProvider {
  readonly name: LLMProvider = 'openai-compatible';
  private client: OpenAI;
  private providerLabel: string;
  private defaultModel: string;
  private supportedModels: LLMModel[];

  constructor(config: {
    label: string;
    apiKey: string;
    baseURL: string;
    defaultModel: string;
    models?: LLMModel[];
  }) {
    if (!config.apiKey) throw new LLMError(`${config.label} API key not set`, 'authentication', 'openai-compatible');
    this.client = new OpenAI({ apiKey: config.apiKey, baseURL: config.baseURL });
    this.providerLabel = config.label;
    this.defaultModel = config.defaultModel;
    this.supportedModels = config.models || [
      { id: config.defaultModel, name: config.defaultModel, provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 32768 } },
    ];
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const response = await this.client.chat.completions.create({
        model: request.model || this.defaultModel,
        messages: request.messages.map((m): ChatMessage => ({ role: m.role, content: m.content })) as OpenAI.ChatCompletionMessageParam[],
        temperature: request.temperature,
        max_tokens: request.maxTokens,
        response_format: request.jsonMode ? { type: 'json_object' } : undefined,
        stop: request.stop,
      });
      const choice = response.choices[0];
      return {
        id: response.id,
        content: choice.message.content || '',
        model: response.model,
        provider: 'openai-compatible',
        usage: {
          promptTokens: response.usage?.prompt_tokens ?? 0,
          completionTokens: response.usage?.completion_tokens ?? 0,
          totalTokens: response.usage?.total_tokens ?? 0,
        },
        finishReason: choice.finish_reason || 'stop',
        created: response.created,
      };
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  async *chatStream(request: ChatRequest): AsyncGenerator<ChatStreamChunk> {
    try {
      const stream = await this.client.chat.completions.create({
        model: request.model || this.defaultModel,
        messages: request.messages.map((m): ChatMessage => ({ role: m.role, content: m.content })) as OpenAI.ChatCompletionMessageParam[],
        temperature: request.temperature,
        max_tokens: request.maxTokens,
        stream: true,
        stop: request.stop,
      });
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta?.content || '';
        if (delta) {
          yield {
            id: chunk.id,
            delta,
            model: chunk.model,
            provider: 'openai-compatible',
            finishReason: chunk.choices[0]?.finish_reason ?? null,
          };
        }
      }
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  listModels(): LLMModel[] { return this.supportedModels; }
  estimateTokens(text: string): number { return Math.ceil(text.length / 4); }
  validateConfig(): boolean { return true; }

  private handleError(err: unknown): LLMError {
    const e = err as { status?: number; message?: string; code?: string };
    const status = e.status || 0;
    let kind: LLMErrorKind = 'unknown';
    let retryable = false;
    if (status === 401) kind = 'authentication';
    else if (status === 429) { kind = 'rate_limit'; retryable = true; }
    else if (status === 400) kind = 'invalid_request';
    else if (status === 404) kind = 'model_not_found';
    else if (e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT') { kind = 'timeout'; retryable = true; }
    return new LLMError(`[${this.providerLabel}] ${e.message || 'Error'}`, kind, 'openai-compatible', status, retryable);
  }
}

export function createDeepSeekProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.DEEPSEEK_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'DeepSeek',
    apiKey: key || 'dummy',
    baseURL: 'https://api.deepseek.com/v1',
    defaultModel: 'deepseek-chat',
    models: [
      { id: 'deepseek-chat', name: 'DeepSeek V3', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 65536 }, inputPricePer1k: 0.00027, outputPricePer1k: 0.0011 },
      { id: 'deepseek-reasoner', name: 'DeepSeek R1', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: false, vision: false, maxTokens: 65536 }, inputPricePer1k: 0.00055, outputPricePer1k: 0.00219 },
    ],
  });
}

export function createQwenProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.DASHSCOPE_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'Qwen',
    apiKey: key || 'dummy',
    baseURL: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    defaultModel: 'qwen-plus',
    models: [
      { id: 'qwen-max', name: 'Qwen Max', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 32768 }, inputPricePer1k: 0.0024, outputPricePer1k: 0.0096 },
      { id: 'qwen-plus', name: 'Qwen Plus', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 131072 }, inputPricePer1k: 0.0008, outputPricePer1k: 0.002 },
      { id: 'qwen-turbo', name: 'Qwen Turbo', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 131072 }, inputPricePer1k: 0.0003, outputPricePer1k: 0.0006 },
      { id: 'qwen-coder-plus', name: 'Qwen Coder Plus', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 131072 }, inputPricePer1k: 0.0008, outputPricePer1k: 0.002 },
    ],
  });
}

export function createGLMProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.ZHIPU_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'GLM',
    apiKey: key || 'dummy',
    baseURL: 'https://open.bigmodel.cn/api/paas/v4',
    defaultModel: 'glm-4-plus',
    models: [
      { id: 'glm-4-plus', name: 'GLM-4 Plus', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 128000 }, inputPricePer1k: 0.05, outputPricePer1k: 0.05 },
      { id: 'glm-4-flash', name: 'GLM-4 Flash', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 128000 }, inputPricePer1k: 0.0001, outputPricePer1k: 0.0001 },
      { id: 'glm-4-flashx', name: 'GLM-4 FlashX', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 128000 }, inputPricePer1k: 0.0001, outputPricePer1k: 0.0001 },
    ],
  });
}

export function createZhipuCodingProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.ZHIPU_CODING_API_KEY || process.env.ZHIPU_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'Zhipu-Coding',
    apiKey: key || 'dummy',
    baseURL: 'https://open.bigmodel.cn/api/coding/paas/v4',
    defaultModel: 'glm-5.1',
    models: [
      { id: 'glm-5.1', name: 'GLM-5.1 (coding plan)', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 128000 }, inputPricePer1k: 0.001, outputPricePer1k: 0.002 },
    ],
  });
}

export function createMoonshotProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.MOONSHOT_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'Moonshot',
    apiKey: key || 'dummy',
    baseURL: 'https://api.moonshot.cn/v1',
    defaultModel: 'moonshot-v1-128k',
    models: [
      { id: 'moonshot-v1-8k', name: 'Moonshot V1 8K', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 8192 }, inputPricePer1k: 0.012, outputPricePer1k: 0.012 },
      { id: 'moonshot-v1-32k', name: 'Moonshot V1 32K', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 32768 }, inputPricePer1k: 0.024, outputPricePer1k: 0.024 },
      { id: 'moonshot-v1-128k', name: 'Moonshot V1 128K', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 131072 }, inputPricePer1k: 0.06, outputPricePer1k: 0.06 },
    ],
  });
}

export function createMiniMaxProvider(apiKey?: string): OpenAICompatibleProvider {
  const key = apiKey || process.env.MINIMAX_API_KEY || '';
  return new OpenAICompatibleProvider({
    label: 'MiniMax',
    apiKey: key || 'dummy',
    baseURL: 'https://api.minimaxi.com/v1',
    defaultModel: 'MiniMax-M3',
    models: [
      { id: 'MiniMax-M3', name: 'MiniMax M3', provider: 'openai-compatible', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: false, maxTokens: 131072 } },
    ],
  });
}
