import { Ollama } from 'ollama';
import type {
  ILLMProvider, LLMProvider, ChatRequest, ChatResponse,
  ChatStreamChunk, LLMModel,
} from '../types.js';
import { LLMError } from '../types.js';

export class OllamaProvider implements ILLMProvider {
  readonly name: LLMProvider = 'ollama';
  private client: Ollama;
  private defaultModel: string;

  constructor(baseURL?: string, defaultModel = 'llama3') {
    this.client = new Ollama({ host: baseURL || process.env.OLLAMA_HOST || 'http://localhost:11434' });
    this.defaultModel = defaultModel;
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const response = await this.client.chat({
        model: request.model || this.defaultModel,
        messages: request.messages.map(m => ({ role: m.role, content: m.content })),
        options: {
          temperature: request.temperature,
          num_predict: request.maxTokens,
        },
        stream: false,
      });
      return {
        id: `ollama-${Date.now()}`,
        content: response.message.content,
        model: response.model,
        provider: 'ollama',
        usage: {
          promptTokens: response.prompt_eval_count ?? 0,
          completionTokens: response.eval_count ?? 0,
          totalTokens: (response.prompt_eval_count ?? 0) + (response.eval_count ?? 0),
        },
        finishReason: response.done ? 'stop' : 'max_tokens',
        created: Math.floor(Date.now() / 1000),
      };
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  async *chatStream(request: ChatRequest): AsyncGenerator<ChatStreamChunk> {
    try {
      const stream = await this.client.chat({
        model: request.model || this.defaultModel,
        messages: request.messages.map(m => ({ role: m.role, content: m.content })),
        options: { temperature: request.temperature, num_predict: request.maxTokens },
        stream: true,
      });
      for await (const chunk of stream) {
        if (chunk.message.content) {
          yield {
            id: `ollama-${Date.now()}`,
            delta: chunk.message.content,
            model: chunk.model,
            provider: 'ollama',
            finishReason: chunk.done ? 'stop' : null,
          };
        }
      }
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  listModels(): LLMModel[] {
    return [
      { id: 'llama3', name: 'Llama 3', provider: 'ollama', capabilities: { streaming: true, jsonMode: false, functionCalling: false, vision: false, maxTokens: 8192 } },
      { id: 'codellama', name: 'Code Llama', provider: 'ollama', capabilities: { streaming: true, jsonMode: false, functionCalling: false, vision: false, maxTokens: 16384 } },
      { id: 'deepseek-coder-v2', name: 'DeepSeek Coder V2', provider: 'ollama', capabilities: { streaming: true, jsonMode: true, functionCalling: false, vision: false, maxTokens: 128000 } },
      { id: 'qwen2.5-coder', name: 'Qwen 2.5 Coder', provider: 'ollama', capabilities: { streaming: true, jsonMode: true, functionCalling: false, vision: false, maxTokens: 32768 } },
    ];
  }

  estimateTokens(text: string): number { return Math.ceil(text.length / 4); }
  validateConfig(): boolean { return true; }

  private handleError(err: unknown): LLMError {
    const e = err as { status?: number; message?: string; statusCode?: number };
    const status = e.status || e.statusCode || 0;
    let type: 'rate_limit' | 'authentication' | 'invalid_request' | 'model_not_found' | 'context_length_exceeded' | 'timeout' | 'network' | 'unknown' = 'unknown';
    let retryable = false;
    if (status === 401) type = 'authentication';
    else if (status === 429) { type = 'rate_limit'; retryable = true; }
    else if (status === 404) type = 'model_not_found';
    else if ((e.message?.includes('connection') ?? false)) { type = 'network'; retryable = true; }
    return new LLMError(e.message || 'Ollama error', type, 'ollama', status, retryable);
  }
}
