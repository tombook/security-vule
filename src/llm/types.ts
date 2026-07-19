/**
 * Multi-LLM Provider — Types & Interfaces
 *
 * Supports: OpenAI, Anthropic, Google Gemini, Ollama, DeepSeek, Qwen, GLM, Moonshot
 * via a unified abstraction layer.
 */

/** Supported LLM providers */
export type LLMProvider = 'openai' | 'anthropic' | 'google' | 'ollama' | 'openai-compatible';

/** Chat message role */
export type ChatRole = 'system' | 'user' | 'assistant' | 'function';

/** Single chat message */
export interface ChatMessage {
  role: ChatRole;
  content: string;
  name?: string;
}

/** Model capability flags */
export interface ModelCapabilities {
  streaming: boolean;
  jsonMode: boolean;
  functionCalling: boolean;
  vision: boolean;
  maxTokens: number;
}

/** Model descriptor */
export interface LLMModel {
  id: string;
  name: string;
  provider: LLMProvider;
  capabilities: ModelCapabilities;
  inputPricePer1k?: number;  // USD per 1k input tokens
  outputPricePer1k?: number; // USD per 1k output tokens
}

/** Chat completion request */
export interface ChatRequest {
  messages: ChatMessage[];
  model?: string;
  temperature?: number;
  maxTokens?: number;
  jsonMode?: boolean;
  stream?: boolean;
  stop?: string[];
}

/** Usage statistics */
export interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

/** Chat completion response (non-streaming) */
export interface ChatResponse {
  id: string;
  content: string;
  model: string;
  provider: LLMProvider;
  usage: TokenUsage;
  finishReason: string;
  created: number;
}

/** Streaming chunk */
export interface ChatStreamChunk {
  id: string;
  delta: string;
  model: string;
  provider: LLMProvider;
  finishReason: string | null;
}

/** Provider configuration */
export interface ProviderConfig {
  provider: LLMProvider;
  apiKey?: string;
  baseURL?: string;
  models?: string[];
  defaultModel?: string;
  timeout?: number;
  maxRetries?: number;
}

/** OpenAI-compatible provider config (DeepSeek, Qwen, GLM, Moonshot, etc.) */
export interface OpenAICompatibleConfig extends ProviderConfig {
  provider: 'openai-compatible';
  baseURL: string;
  apiKey: string;
  defaultModel: string;
}

/** Router configuration */
export interface RouterConfig {
  providers: ProviderConfig[];
  routing: 'round-robin' | 'cost-based' | 'latency-based' | 'failover';
  defaultProvider?: LLMProvider;
  fallbackProvider?: LLMProvider;
  retryAttempts?: number;
  retryDelayMs?: number;
}

/** LLM error types */
export type LLMErrorType =
  | 'rate_limit'
  | 'authentication'
  | 'invalid_request'
  | 'model_not_found'
  | 'context_length_exceeded'
  | 'timeout'
  | 'network'
  | 'unknown';

/** Typed LLM error */
export class LLMError extends Error {
  constructor(
    message: string,
    public readonly type: LLMErrorType,
    public readonly provider: LLMProvider,
    public readonly statusCode?: number,
    public readonly retryable: boolean = false,
  ) {
    super(message);
    this.name = 'LLMError';
  }
}

/** Abstract provider interface */
export interface ILLMProvider {
  readonly name: LLMProvider;
  chat(request: ChatRequest): Promise<ChatResponse>;
  chatStream(request: ChatRequest): AsyncGenerator<ChatStreamChunk>;
  listModels(): LLMModel[];
  estimateTokens(text: string): number;
  validateConfig(): boolean;
}
