import { GoogleGenerativeAI } from '@google/generative-ai';
import type {
  ILLMProvider, LLMProvider, ChatRequest, ChatResponse,
  ChatStreamChunk, LLMModel,
} from '../types.js';
import { LLMError } from '../types.js';
type LLMErrorKind = 'rate_limit' | 'authentication' | 'invalid_request' | 'model_not_found' | 'context_length_exceeded' | 'timeout' | 'network' | 'unknown';

const SUPPORTED_MODELS: LLMModel[] = [
  { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', provider: 'google', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1048576 }, inputPricePer1k: 0.00125, outputPricePer1k: 0.005 },
  { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', provider: 'google', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1048576 }, inputPricePer1k: 0.00015, outputPricePer1k: 0.0006 },
  { id: 'gemini-2.0-flash', name: 'Gemini 2.0 Flash', provider: 'google', capabilities: { streaming: true, jsonMode: true, functionCalling: true, vision: true, maxTokens: 1048576 }, inputPricePer1k: 0.0001, outputPricePer1k: 0.0004 },
];

export class GoogleProvider implements ILLMProvider {
  readonly name: LLMProvider = 'google';
  private genAI: GoogleGenerativeAI;
  private defaultModel: string;

  constructor(apiKey?: string, defaultModel = 'gemini-2.5-flash') {
    const key = apiKey || process.env.GOOGLE_API_KEY || '';
    if (!key) throw new LLMError('GOOGLE_API_KEY not set', 'authentication', 'google');
    this.genAI = new GoogleGenerativeAI(key);
    this.defaultModel = defaultModel;
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const model = this.genAI.getGenerativeModel({
        model: request.model || this.defaultModel,
        generationConfig: {
          temperature: request.temperature,
          maxOutputTokens: request.maxTokens,
          responseMimeType: request.jsonMode ? 'application/json' : undefined,
        },
      });
      const history = request.messages
        .filter(m => m.role !== 'system')
        .map(m => ({
          role: m.role === 'assistant' ? 'model' as const : 'user' as const,
          parts: [{ text: m.content }],
        }));
      const systemInstruction = request.messages.find(m => m.role === 'system')?.content;
      const lastUserMsg = history.pop();
      if (!lastUserMsg || lastUserMsg.role !== 'user') {
        throw new LLMError('Last message must be from user', 'invalid_request', 'google');
      }
      const result = await model.generateContent({
        contents: history,
        systemInstruction: systemInstruction || undefined,
      });
      const response = result.response;
      return {
        id: `google-${Date.now()}`,
        content: response.text(),
        model: request.model || this.defaultModel,
        provider: 'google',
        usage: {
          promptTokens: response.usageMetadata?.promptTokenCount ?? 0,
          completionTokens: response.usageMetadata?.candidatesTokenCount ?? 0,
          totalTokens: response.usageMetadata?.totalTokenCount ?? 0,
        },
        finishReason: response.candidates?.[0]?.finishReason || 'stop',
        created: Math.floor(Date.now() / 1000),
      };
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  async *chatStream(request: ChatRequest): AsyncGenerator<ChatStreamChunk> {
    try {
      const model = this.genAI.getGenerativeModel({
        model: request.model || this.defaultModel,
        generationConfig: { temperature: request.temperature, maxOutputTokens: request.maxTokens },
      });
      const history = request.messages
        .filter(m => m.role !== 'system')
        .map(m => ({ role: m.role === 'assistant' ? 'model' as const : 'user' as const, parts: [{ text: m.content }] }));
      const systemInstruction = request.messages.find(m => m.role === 'system')?.content;
      const result = await model.generateContentStream({
        contents: history,
        systemInstruction: systemInstruction || undefined,
      });
      for await (const chunk of result.stream) {
        const text = chunk.text();
        if (text) {
          yield {
            id: `google-${Date.now()}`,
            delta: text,
            model: request.model || this.defaultModel,
            provider: 'google',
            finishReason: null,
          };
        }
      }
      yield { id: `google-${Date.now()}`, delta: '', model: request.model || this.defaultModel, provider: 'google', finishReason: 'stop' };
    } catch (err: unknown) {
      throw this.handleError(err);
    }
  }

  listModels(): LLMModel[] { return SUPPORTED_MODELS; }
  estimateTokens(text: string): number { return Math.ceil(text.length / 4); }
  validateConfig(): boolean { return !!process.env.GOOGLE_API_KEY; }

  private handleError(err: unknown): LLMError {
    const e = err as { status?: number; message?: string; statusCode?: number };
    const status = e.status || e.statusCode || 0;
    let kind: LLMErrorKind = 'unknown';
    let retryable = false;
    if (status === 401 || status === 403) kind = 'authentication';
    else if (status === 429) { kind = 'rate_limit'; retryable = true; }
    else if (status === 400) kind = 'invalid_request';
    else if (status === 404) kind = 'model_not_found';
    return new LLMError(e.message || 'Google AI error', kind, 'google', status, retryable);
  }
}
