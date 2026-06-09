import Anthropic from '@anthropic-ai/sdk';
import type {
  ILLMProvider, LLMProvider, ChatRequest, ChatResponse,
  ChatStreamChunk, LLMModel,
} from '../types.js';
import { LLMError } from '../types.js';
type LLMErrorKind = 'rate_limit' | 'authentication' | 'invalid_request' | 'model_not_found' | 'context_length_exceeded' | 'timeout' | 'network' | 'unknown';

const SUPPORTED_MODELS: LLMModel[] = [
  { id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4', provider: 'anthropic', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 200000 }, inputPricePer1k: 0.003, outputPricePer1k: 0.015 },
  { id: 'claude-opus-4-20250514', name: 'Claude Opus 4', provider: 'anthropic', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 200000 }, inputPricePer1k: 0.015, outputPricePer1k: 0.075 },
  { id: 'claude-3-5-haiku-20241022', name: 'Claude 3.5 Haiku', provider: 'anthropic', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 200000 }, inputPricePer1k: 0.0008, outputPricePer1k: 0.004 },
];

export class AnthropicProvider implements ILLMProvider {
  readonly name: LLMProvider = 'anthropic';
  private client: Anthropic;
  private defaultModel: string;

  constructor(apiKey?: string, defaultModel = 'claude-sonnet-4-20250514') {
    const key = apiKey || process.env.ANTHROPIC_API_KEY || '';
    if (!key) throw new LLMError('ANTHROPIC_API_KEY not set', 'authentication', 'anthropic');
    this.client = new Anthropic({ apiKey: key });
    this.defaultModel = defaultModel;
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const systemMsg = request.messages.find(m => m.role === 'system');
      const nonSystem = request.messages.filter(m => m.role !== 'system');
      const response = await this.client.messages.create({
        model: request.model || this.defaultModel,
        max_tokens: request.maxTokens || 4096,
        system: systemMsg?.content || '',
        messages: nonSystem.map(m => ({ role: m.role as 'user' | 'assistant', content: m.content })),
        temperature: request.temperature,
        stop_sequences: request.stop,
      });
      const textBlock = response.content.find(b => b.type === 'text');
      return {
        id: response.id,
        content: textBlock && 'text' in textBlock ? textBlock.text : '',
        model: response.model,
        provider: 'anthropic',
        usage: {
          promptTokens: response.usage.input_tokens,
          completionTokens: response.usage.output_tokens,
          totalTokens: response.usage.input_tokens + response.usage.output_tokens,
        },
        finishReason: response.stop_reason || 'end_turn',
        created: Math.floor(Date.now() / 1000),
      };
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  async *chatStream(request: ChatRequest): AsyncGenerator<ChatStreamChunk> {
    try {
      const systemMsg = request.messages.find(m => m.role === 'system');
      const nonSystem = request.messages.filter(m => m.role !== 'system');
      const stream = this.client.messages.stream({
        model: request.model || this.defaultModel,
        max_tokens: request.maxTokens || 4096,
        system: systemMsg?.content || '',
        messages: nonSystem.map(m => ({ role: m.role as 'user' | 'assistant', content: m.content })),
        temperature: request.temperature,
      });
      for await (const event of stream) {
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
          yield {
            id: event.type,
            delta: event.delta.text,
            model: request.model || this.defaultModel,
            provider: 'anthropic',
            finishReason: null,
          };
        }
        if (event.type === 'message_stop') {
          yield {
            id: event.type,
            delta: '',
            model: request.model || this.defaultModel,
            provider: 'anthropic',
            finishReason: 'end_turn',
          };
        }
      }
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  listModels(): LLMModel[] { return SUPPORTED_MODELS; }
  estimateTokens(text: string): number { return Math.ceil(text.length / 3.5); }
  validateConfig(): boolean { return !!(process.env.ANTHROPIC_API_KEY); }

  private handleError(err: unknown): LLMError {
    const e = err as { status?: number; message?: string; error?: { type?: string } };
    const status = e.status || 0;
    let kind: LLMErrorKind = 'unknown';
    let retryable = false;
    if (status === 401) kind = 'authentication';
    else if (status === 429) { kind = 'rate_limit'; retryable = true; }
    else if (status === 400) kind = 'invalid_request';
    else if (status === 404) kind = 'model_not_found';
    else if (e.error?.type === 'overloaded_error') { kind = 'rate_limit'; retryable = true; }
    return new LLMError(e.message || 'Anthropic error', kind, 'anthropic', status, retryable);
  }
}
