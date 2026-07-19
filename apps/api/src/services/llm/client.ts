// apps/api/src/services/llm/client.ts
// P4.1 LLM Provider Router(Anthropic / OpenAI / Ollama 统一接口)

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMRequest {
  system?: string;
  messages: LLMMessage[];
  maxTokens?: number;
  temperature?: number;
  jsonSchema?: Record<string, unknown>;
}

export interface LLMResponse {
  content: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  model: string;
  provider: string;
  durationMs: number;
}

export interface LLMClient {
  provider: string;
  chat(req: LLMRequest): Promise<LLMResponse>;
}

export class OllamaClient implements LLMClient {
  provider = 'ollama';
  constructor(private baseUrl = 'http://localhost:11434', private model = 'security-vule-poc-v1') {}

  async chat(req: LLMRequest): Promise<LLMResponse> {
    const start = Date.now();
    const res = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages: [
          ...(req.system ? [{ role: 'system', content: req.system }] : []),
          ...req.messages,
        ],
        stream: false,
        options: { temperature: req.temperature ?? 0.2, num_predict: req.maxTokens ?? 2048 },
        format: req.jsonSchema ? 'json' : undefined,
      }),
    });
    if (!res.ok) throw new Error(`Ollama ${res.status}: ${await res.text()}`);
    const data: any = await res.json();
    return {
      content: data.message?.content ?? '',
      promptTokens: data.prompt_eval_count ?? 0,
      completionTokens: data.eval_count ?? 0,
      totalTokens: (data.prompt_eval_count ?? 0) + (data.eval_count ?? 0),
      costUsd: 0,
      model: data.model ?? this.model,
      provider: 'ollama',
      durationMs: Date.now() - start,
    };
  }
}

export class AnthropicClient implements LLMClient {
  provider = 'anthropic';
  constructor(private apiKey = process.env.ANTHROPIC_API_KEY ?? '', private model = 'claude-sonnet-4-5') {}

  async chat(req: LLMRequest): Promise<LLMResponse> {
    const start = Date.now();
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 2048,
        temperature: req.temperature ?? 0.2,
        system: req.system ?? '',
        messages: req.messages,
      }),
    });
    if (!res.ok) throw new Error(`Anthropic ${res.status}: ${await res.text()}`);
    const data: any = await res.json();
    return {
      content: data.content?.[0]?.text ?? '',
      promptTokens: data.usage?.input_tokens ?? 0,
      completionTokens: data.usage?.output_tokens ?? 0,
      totalTokens: (data.usage?.input_tokens ?? 0) + (data.usage?.output_tokens ?? 0),
      costUsd: estimateCostAnthropic(this.model, data.usage?.input_tokens ?? 0, data.usage?.output_tokens ?? 0),
      model: data.model ?? this.model,
      provider: 'anthropic',
      durationMs: Date.now() - start,
    };
  }
}

export class OpenAIClient implements LLMClient {
  provider = 'openai';
  constructor(private apiKey = process.env.OPENAI_API_KEY ?? '', private model = 'gpt-4o-mini', private baseUrl = 'https://api.openai.com/v1') {}

  async chat(req: LLMRequest): Promise<LLMResponse> {
    const start = Date.now();
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 2048,
        temperature: req.temperature ?? 0.2,
        messages: [
          ...(req.system ? [{ role: 'system', content: req.system }] : []),
          ...req.messages,
        ],
        response_format: req.jsonSchema ? { type: 'json_object' } : undefined,
      }),
    });
    if (!res.ok) throw new Error(`OpenAI ${res.status}: ${await res.text()}`);
    const data: any = await res.json();
    return {
      content: data.choices?.[0]?.message?.content ?? '',
      promptTokens: data.usage?.prompt_tokens ?? 0,
      completionTokens: data.usage?.completion_tokens ?? 0,
      totalTokens: data.usage?.total_tokens ?? 0,
      costUsd: estimateCostOpenAI(this.model, data.usage?.prompt_tokens ?? 0, data.usage?.completion_tokens ?? 0),
      model: data.model ?? this.model,
      provider: 'openai',
      durationMs: Date.now() - start,
    };
  }
}

export class GLMClient implements LLMClient {
  provider = 'glm';
  constructor(private apiKey = process.env.GLM_API_KEY ?? '', private model = 'glm-5.1', private baseUrl = 'https://open.bigmodel.cn/api/paas/v4') {}

  async chat(req: LLMRequest): Promise<LLMResponse> {
    const start = Date.now();
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 2048,
        temperature: req.temperature ?? 0.2,
        messages: [
          ...(req.system ? [{ role: 'system', content: req.system }] : []),
          ...req.messages,
        ],
        response_format: req.jsonSchema ? { type: 'json_object' } : undefined,
      }),
    });
    if (!res.ok) throw new Error(`GLM ${res.status}: ${await res.text()}`);
    const data: any = await res.json();
    return {
      content: data.choices?.[0]?.message?.content ?? '',
      promptTokens: data.usage?.prompt_tokens ?? 0,
      completionTokens: data.usage?.completion_tokens ?? 0,
      totalTokens: data.usage?.total_tokens ?? 0,
      costUsd: 0,
      model: data.model ?? this.model,
      provider: 'glm',
      durationMs: Date.now() - start,
    };
  }
}

export class DeepSeekClient implements LLMClient {
  provider = 'deepseek';
  constructor(private apiKey = process.env.DEEPSEEK_API_KEY ?? '', private model = 'deepseek-chat', private baseUrl = 'https://api.deepseek.com') {}

  async chat(req: LLMRequest): Promise<LLMResponse> {
    const start = Date.now();
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 2048,
        temperature: req.temperature ?? 0.2,
        messages: [
          ...(req.system ? [{ role: 'system', content: req.system }] : []),
          ...req.messages,
        ],
        response_format: req.jsonSchema ? { type: 'json_object' } : undefined,
      }),
    });
    if (!res.ok) throw new Error(`DeepSeek ${res.status}: ${await res.text()}`);
    const data: any = await res.json();
    return {
      content: data.choices?.[0]?.message?.content ?? '',
      promptTokens: data.usage?.prompt_tokens ?? 0,
      completionTokens: data.usage?.completion_tokens ?? 0,
      totalTokens: data.usage?.total_tokens ?? 0,
      costUsd: 0,
      model: data.model ?? this.model,
      provider: 'deepseek',
      durationMs: Date.now() - start,
    };
  }
}

function estimateCostAnthropic(model: string, input: number, output: number): number {
  const rates: Record<string, [number, number]> = {
    'claude-sonnet-4-5': [3 / 1_000_000, 15 / 1_000_000],
    'claude-opus-4': [15 / 1_000_000, 75 / 1_000_000],
  };
  const [inR, outR] = rates[model] ?? rates['claude-sonnet-4-5'];
  return input * inR + output * outR;
}

function estimateCostOpenAI(model: string, input: number, output: number): number {
  const rates: Record<string, [number, number]> = {
    'gpt-4o-mini': [0.15 / 1_000_000, 0.6 / 1_000_000],
    'gpt-4o': [2.5 / 1_000_000, 10 / 1_000_000],
  };
  const [inR, outR] = rates[model] ?? rates['gpt-4o-mini'];
  return input * inR + output * outR;
}

export const LLMCapabilityUsage = {
  poc_gen: { system: '你是 security-vule 的 PoC 生成器,严格 JSON 输出,不输出额外说明。', maxTokens: 2048, temperature: 0.2 },
  explain: { system: '你是安全分析师,用简洁中文解释漏洞、攻击路径、修复建议。', maxTokens: 1024, temperature: 0.3 },
  triage: { system: '你是漏洞预筛助手,判断是否疑似误报并给出建议。', maxTokens: 512, temperature: 0.1 },
  report: { system: '你是安全报告生成器,根据 findings 数据生成 Markdown 周报。', maxTokens: 4096, temperature: 0.4 },
} as const;

// 简单内存缓存的默认 providers（因为 DB 可能还没表，先兼容）
const DEFAULT_PROVIDERS = [
  { provider: 'ollama', baseUrl: 'http://localhost:11434', defaultModel: 'security-vule-poc-v1' },
];

export function createClientFromConfig(p: {
  provider: 'ollama' | 'openai' | 'anthropic' | 'glm' | 'deepseek' | 'custom';
  defaultModel: string;
  apiKey?: string;
  baseUrl?: string;
}): LLMClient {
  switch (p.provider) {
    case 'ollama':
      return new OllamaClient(p.baseUrl ?? 'http://localhost:11434', p.defaultModel);
    case 'anthropic':
      return new AnthropicClient(p.apiKey, p.defaultModel);
    case 'openai':
    case 'custom':
      // Most custom LLM APIs (MiniMax, Moonshot, Together AI, etc.)
      // are OpenAI-compatible: same /chat/completions format.
      return new OpenAIClient(p.apiKey, p.defaultModel, p.baseUrl ?? 'https://api.openai.com/v1');
    case 'glm':
      return new GLMClient(p.apiKey, p.defaultModel, p.baseUrl);
    case 'deepseek':
      return new DeepSeekClient(p.apiKey, p.defaultModel, p.baseUrl);
    default:
      return new OllamaClient();
  }
}

// 向后兼容的 getLLMClient（仍然支持 env 方式）
let _client: LLMClient | null = null;
export function getLLMClient(): LLMClient {
  if (_client) return _client;
  const provider = process.env.LLM_PROVIDER ?? 'ollama';
  if (provider === 'anthropic') {
    _client = new AnthropicClient();
  } else if (provider === 'openai') {
    _client = new OpenAIClient(process.env.OPENAI_API_KEY, 'gpt-4o-mini', 'https://api.openai.com/v1');
  } else if (provider === 'glm') {
    _client = new GLMClient();
  } else if (provider === 'deepseek') {
    _client = new DeepSeekClient();
  } else {
    _client = new OllamaClient();
  }
  return _client;
}