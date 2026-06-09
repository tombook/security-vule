/**
 * OpenAI Provider — GPT-4o, GPT-4o-mini, o1, o3 series
 */
import OpenAI from 'openai';
import type {
  ILLMProvider, LLMProvider, ChatRequest, ChatResponse,
  ChatStreamChunk, LLMModel, ChatMessage,
} from '../types.js';
import { LLMError } from '../types.js';
type LLMErrorKind = 'rate_limit' | 'authentication' | 'invalid_request' | 'model_not_found' | 'context_length_exceeded' | 'timeout' | 'network' | 'unknown';

const SUPPORTED_MODELS: LLMModel[] = [
  { id: 'gpt-4o', name: 'GPT-4o', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 128000 }, inputPricePer1k: 0.0025, outputPricePer1k: 0.01 },
  { id: 'gpt-4o-mini', name: 'GPT-4o Mini', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 128000 }, inputPricePer1k: 0.00015, outputPricePer1k: 0.0006 },
  { id: 'gpt-4.1', name: 'GPT-4.1', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1047576 }, inputPricePer1k: 0.002, outputPricePer1k: 0.008 },
  { id: 'gpt-4.1-mini', name: 'GPT-4.1 Mini', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1047576 }, inputPricePer1k: 0.0004, outputPricePer1k: 0.0016 },
  { id: 'gpt-4.1-nano', name: 'GPT-4.1 Nano', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1047576 }, inputPricePer1k: 0.0001, outputPricePer1k: 0.0004 },
  { id: 'o3', name: 'o3', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 200000 }, inputPricePer1k: 0.002, outputPricePer1k: 0.008 },
  { id: 'o4-mini', name: 'o4-mini', provider: 'openai', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 200000 }, inputPricePer1k: 0.0011, outputPricePer1k: 0.0044 },
];

export class OpenAIProvider implements ILLMProvider {
  readonly name: LLMProvider = 'openai';
  private client: OpenAI;
  private defaultModel: string;

  constructor(apiKey?: string, defaultModel = 'gpt-4o') {
    const key = apiKey || process.env.OPENAI_API_KEY || '';
    if (!key) throw new LLMError('OPENAI_API_KEY not set', 'authentication', 'openai');
    this.client = new OpenAI({ apiKey: key });
    this.defaultModel = defaultModel;
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
        provider: 'openai',
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
            provider: 'openai',
            finishReason: chunk.choices[0]?.finish_reason ?? null,
          };
        }
      }
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  listModels(): LLMModel[] { return SUPPORTED_MODELS; }

  estimateTokens(text: string): number { return Math.ceil(text.length / 4); }

  validateConfig(): boolean {
    return !!(process.env.OPENAI_API_KEY || this.client.apiKey);
  }

  private handleError(err: unknown): LLMError {
    const e = err as { status?: number; message?: string; code?: string };
    const status = e.status || 0;
    let kind: LLMErrorKind = 'unknown';
    let retryable = false;
    if (status === 401) kind = 'authentication';
    else if (status === 429) { kind = 'rate_limit'; retryable = true; }
    else if (status === 400) kind = 'invalid_request';
    else if (status === 404) kind = 'model_not_found';
    else if (status === 413 || (e.message?.includes('context_length') ?? false)) kind = 'context_length_exceeded';
    else if (e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT') { kind = 'timeout'; retryable = true; }
    else if (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND') { kind = 'network'; retryable = true; }
    return new LLMError(e.message || 'OpenAI error', kind, 'openai', status, retryable);
  }
}
