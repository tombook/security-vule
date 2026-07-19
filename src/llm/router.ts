import type { ILLMProvider, ChatRequest, ChatResponse, ChatStreamChunk, RouterConfig, LLMProvider as LLMProviderType, LLMError } from './types.js';
import { LLMError as LLMErrorClass } from './types.js';
import { OpenAIProvider } from './providers/openai.js';
import { AnthropicProvider } from './providers/anthropic.js';
import { GoogleProvider } from './providers/google.js';
import { OllamaProvider } from './providers/ollama.js';
import { OpenAICompatibleProvider, createDeepSeekProvider, createQwenProvider, createGLMProvider, createMoonshotProvider, createMiniMaxProvider } from './providers/openai-compatible.js';
import type { QuotaManager } from '../usage/quota.js';
import type { UsageEvent } from '../usage/types.js';

export type { RouterConfig } from './types.js';

type RoutingStrategy = 'round-robin' | 'cost-based' | 'latency-based' | 'failover';

interface ProviderHealth {
  provider: ILLMProvider;
  failures: number;
  lastFailure: number;
  avgLatencyMs: number;
  totalRequests: number;
}

export class LLMRouter {
  private providers: Map<string, ProviderHealth> = new Map();
  private strategy: RoutingStrategy;
  private rrIndex = 0;
  private fallbackProvider?: string;
  private retryAttempts: number;
  private retryDelayMs: number;
  private quotaManager?: QuotaManager;
  private usageEvents: UsageEvent[] = [];

  constructor(config?: RouterConfig & { quotaManager?: QuotaManager }) {
    this.strategy = config?.routing || 'failover';
    this.retryAttempts = config?.retryAttempts ?? 3;
    this.retryDelayMs = config?.retryDelayMs ?? 1000;
    this.fallbackProvider = config?.fallbackProvider;
    this.quotaManager = config?.quotaManager;

    if (config?.providers) {
      for (const pc of config.providers) {
        const provider = this.createProvider(pc);
        if (provider) {
          this.providers.set(pc.provider, {
            provider,
            failures: 0,
            lastFailure: 0,
            avgLatencyMs: 0,
            totalRequests: 0,
          });
        }
      }
    }
  }

  registerProvider(id: string, provider: ILLMProvider): void {
    this.providers.set(id, { provider, failures: 0, lastFailure: 0, avgLatencyMs: 0, totalRequests: 0 });
  }

  async chat(request: ChatRequest, preferredProvider?: string): Promise<ChatResponse> {
    const selected = this.selectProvider(preferredProvider);
    if (!selected) throw new LLMErrorClass('No LLM providers available', 'unknown', 'openai');

    const attempt = async (providerName: string, attemptNum: number): Promise<ChatResponse> => {
      const health = this.providers.get(providerName);
      if (!health) throw new LLMErrorClass(`Provider ${providerName} not found`, 'unknown', providerName as LLMProviderType);
      const start = Date.now();
      try {
        const response = await health.provider.chat(request);
        const latency = Date.now() - start;
        health.avgLatencyMs = (health.avgLatencyMs * health.totalRequests + latency) / (health.totalRequests + 1);
        health.totalRequests++;
        health.failures = Math.max(0, health.failures - 1);

        // 记录用量事件并检查配额（不阻塞主流程）
        this.recordUsage(response, providerName);

        return response;
      } catch (err) {
        health.failures++;
        health.lastFailure = Date.now();
        const llmErr = err as LLMError;
        if (llmErr.retryable && attemptNum < this.retryAttempts) {
          await this.delay(this.retryDelayMs * Math.pow(2, attemptNum));
          return attempt(providerName, attemptNum + 1);
        }
        if (this.fallbackProvider && providerName !== this.fallbackProvider) {
          return attempt(this.fallbackProvider, 0);
        }
        throw err;
      }
    };

    return attempt(selected, 0);
  }

  /**
   * 记录用量事件并检查配额
   * 异步执行，不阻塞主流程
   */
  private recordUsage(response: ChatResponse, providerName: string): void {
    if (!this.quotaManager) return;

    const event: UsageEvent = {
      ts: new Date().toISOString(),
      capability: 'llm_chat',
      provider: providerName as LLMProviderType,
      model: response.model,
      prompt_tokens: response.usage.promptTokens,
      completion_tokens: response.usage.completionTokens,
      cost_usd: this.estimateCost(response, providerName),
    };

    this.usageEvents.push(event);

    // 异步检查配额，异常输出到 stderr 不抛错
    setImmediate(() => {
      try {
        const warnings = this.quotaManager!.check(this.usageEvents);
        if (warnings.length > 0) {
          for (const w of warnings) {
            const level = w.percentage >= 100 ? 'EXCEEDED' : 'WARN';
            console.error(
              `[Quota ${level}] ${w.type}: ${w.current.toFixed(2)} / ${w.limit.toFixed(2)} (${w.percentage.toFixed(1)}%)`,
            );
          }
        }
      } catch (err) {
        console.error('[Quota] check failed:', err);
      }
    });
  }

  /**
   * 估算调用成本（粗略估算，基于模型价格）
   */
  private estimateCost(response: ChatResponse, providerName: string): number {
    const health = this.providers.get(providerName);
    if (!health) return 0;

    const models = health.provider.listModels();
    const model = models.find(m => m.id === response.model) || models[0];
    if (!model) return 0;

    const inputPrice = model.inputPricePer1k ?? 0;
    const outputPrice = model.outputPricePer1k ?? 0;
    const inputCost = (response.usage.promptTokens / 1000) * inputPrice;
    const outputCost = (response.usage.completionTokens / 1000) * outputPrice;

    return inputCost + outputCost;
  }

  async *chatStream(request: ChatRequest, preferredProvider?: string): AsyncGenerator<ChatStreamChunk> {
    const providerName = this.selectProvider(preferredProvider);
    if (!providerName) throw new LLMErrorClass('No LLM providers available', 'unknown', 'openai');
    const health = this.providers.get(providerName);
    if (!health) throw new LLMErrorClass(`Provider ${providerName} not found`, 'unknown', providerName as LLMProviderType);
    yield* health.provider.chatStream(request);
  }

  getProvider(name: string): ILLMProvider | undefined {
    return this.providers.get(name)?.provider;
  }

  listProviders(): string[] {
    return Array.from(this.providers.keys());
  }

  getHealth(): Record<string, { failures: number; avgLatencyMs: number; totalRequests: number }> {
    const result: Record<string, { failures: number; avgLatencyMs: number; totalRequests: number }> = {};
    for (const [name, health] of this.providers) {
      result[name] = { failures: health.failures, avgLatencyMs: Math.round(health.avgLatencyMs), totalRequests: health.totalRequests };
    }
    return result;
  }

  private selectProvider(preferred?: string): string | undefined {
    if (preferred) {
      const health = this.providers.get(preferred);
      if (health && this.isHealthy(health)) return preferred;
    }

    const healthy = Array.from(this.providers.entries()).filter(([, h]) => this.isHealthy(h));
    if (healthy.length === 0) return this.fallbackProvider;

    switch (this.strategy) {
      case 'round-robin': {
        const idx = this.rrIndex % healthy.length;
        this.rrIndex++;
        return healthy[idx][0];
      }
      case 'latency-based':
        return healthy.sort((a, b) => a[1].avgLatencyMs - b[1].avgLatencyMs)[0][0];
      case 'cost-based':
        return healthy.sort((a, b) => {
          const aCost = a[1].provider.listModels()[0]?.inputPricePer1k ?? Infinity;
          const bCost = b[1].provider.listModels()[0]?.inputPricePer1k ?? Infinity;
          return aCost - bCost;
        })[0][0];
      case 'failover':
      default:
        return healthy[0][0];
    }
  }

  private isHealthy(health: ProviderHealth): boolean {
    if (health.failures >= 5) {
      if (Date.now() - health.lastFailure > 60000) {
        health.failures = 0;
        return true;
      }
      return false;
    }
    return true;
  }

  private createProvider(config: { provider: string; apiKey?: string; baseURL?: string; defaultModel?: string }): ILLMProvider | null {
    switch (config.provider) {
      case 'openai': return new OpenAIProvider(config.apiKey, config.defaultModel);
      case 'anthropic': return new AnthropicProvider(config.apiKey, config.defaultModel);
      case 'google': return new GoogleProvider(config.apiKey, config.defaultModel);
      case 'ollama': return new OllamaProvider(config.baseURL, config.defaultModel);
      case 'openai-compatible': return new OpenAICompatibleProvider({
        label: 'custom', apiKey: config.apiKey || '', baseURL: config.baseURL || '', defaultModel: config.defaultModel || 'default',
      });
      default: return null;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export function createDefaultRouter(options?: { quotaManager?: QuotaManager }): LLMRouter {
  const router = new LLMRouter({
    routing: 'failover',
    retryAttempts: 2,
    retryDelayMs: 500,
    providers: [],
    quotaManager: options?.quotaManager,
  });

  if (process.env.OPENAI_API_KEY) router.registerProvider('openai', new OpenAIProvider());
  if (process.env.ANTHROPIC_API_KEY) router.registerProvider('anthropic', new AnthropicProvider());
  if (process.env.GOOGLE_API_KEY) router.registerProvider('google', new GoogleProvider());
  if (process.env.DEEPSEEK_API_KEY) router.registerProvider('openai-compatible', createDeepSeekProvider());
  if (process.env.ZHIPU_API_KEY) router.registerProvider('openai-compatible', createGLMProvider());
  if (process.env.MOONSHOT_API_KEY) router.registerProvider('openai-compatible', createMoonshotProvider());
  if (process.env.DASHSCOPE_API_KEY) router.registerProvider('openai-compatible', createQwenProvider());
  if (process.env.MINIMAX_API_KEY) router.registerProvider('openai-compatible', createMiniMaxProvider());

  const ollamaHost = process.env.OLLAMA_HOST || 'http://localhost:11434';
  router.registerProvider('ollama', new OllamaProvider(ollamaHost));

  return router;
}
