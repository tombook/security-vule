/**
 * Wave 3 · LLM PoC candidate generator
 *
 * 调用 LLM 为单个 finding 生成候选 PoC 文本(仅生成,不执行)。
 * 复用 LLMRouter(由调用方注入,方便测试)+ 复用 src/llm/security 的 redactSecrets
 * + 复用 src/llm/audit 的 AuditLogger 写指标。输出可序列化为 JSON 落盘,
 * 由人工审阅后再 submit 到 verify-poc 走运行时验证。
 */
import type { LLMRouter, ChatRequest } from '../llm/router.js';
import type { ChatResponse } from '../llm/types.js';
import type { VulnerabilityFinding } from '../engine/analyzer.js';
import { redactSecrets } from '../llm/security.js';
import { GLOBAL_AUDIT } from '../llm/audit.js';

export interface PocGenerationOptions {
  router: Pick<LLMRouter, 'chat'>;
  model?: string;
  preferredProvider?: string;
  temperature?: number;
  maxTokens?: number;
  now?: () => Date;
  audit?: typeof GLOBAL_AUDIT;
  logger?: { info: (msg: string) => void; warn: (msg: string) => void };
}

export interface PocCandidate {
  finding: { id: string; type: string; file: string; line: number; cwe?: string };
  category: string;
  request: { method: string; path: string; params?: Record<string, string>; data?: string };
  success_indicators: string[];
  rationale: string;
  llm: { provider: string; model: string; promptTokens: number; completionTokens: number; costUsd: number };
  generatedAt: string;
  manualReview: true;
}

export interface PocGenerationResult {
  ok: boolean;
  candidate?: PocCandidate;
  rawContent?: string;
  error?: string;
}

const CATEGORY_HINT: Record<string, string> = {
  sqli: 'sqli',
  sql_injection: 'sqli',
  'sql injection': 'sqli',
  xss: 'xss',
  'cross-site scripting': 'xss',
  cmdi: 'shell',
  command_injection: 'shell',
  rce: 'shell',
  'command injection': 'shell',
  lfi: 'fileinclude',
  rfi: 'fileinclude',
  file_inclusion: 'fileinclude',
  path_traversal: 'fileinclude',
  ssrf: 'ssrf',
  weakrand: 'weakrand',
  trustbound: 'trustbound',
  crypto: 'crypto',
  filewrite: 'filewrite',
  dynamic_code: 'dynamic_code',
};

function normalizeCategory(type: string): string {
  const t = (type || '').toLowerCase().replace(/[\s\-]+/g, '_');
  if (CATEGORY_HINT[t]) return CATEGORY_HINT[t];
  for (const [k, v] of Object.entries(CATEGORY_HINT)) {
    if (t.includes(k)) return v;
  }
  return t || 'unknown';
}

function buildPocPrompt(finding: VulnerabilityFinding): { system: string; user: string } {
  const safeCode = (finding.description || finding.title || '').slice(0, 800);
  const redaction = redactSecrets(safeCode);
  return {
    system: `You are a security engineer generating PoC (proof-of-concept) HTTP requests for runtime verification.
Output STRICT JSON (no prose, no markdown). Schema:
{
  "category": "<one of: sqli | shell | xss | fileinclude | ssrf | weakrand | trustbound | crypto | filewrite | dynamic_code>",
  "request": { "method": "GET"|"POST", "path": "/vulnerabilities/...", "params": {...}, "data": "..." },
  "success_indicators": ["regex or substring that, if present in response body, proves exploitation"],
  "rationale": "short explanation of the attack vector (<=200 chars)"
}
Target is a mock DVWA-like app. Do NOT include real exploits, payloads, or instructions. The PoC will be reviewed manually before sandbox execution.`,
    user: `Finding: ${finding.type} (severity=${finding.severity}, line=${finding.line}, cwe=${finding.cwe ?? 'n/a'})
File: ${finding.file}
Description: ${redaction.text}
Generate one candidate PoC for runtime verification.`,
  };
}

function isValidCandidate(x: any): x is Omit<PocCandidate, 'finding' | 'generatedAt' | 'manualReview' | 'llm'> {
  if (!x || typeof x !== 'object') return false;
  if (typeof x.category !== 'string' || !x.category) return false;
  if (!x.request || typeof x.request !== 'object') return false;
  if (typeof x.request.method !== 'string') return false;
  if (typeof x.request.path !== 'string' || !x.request.path.startsWith('/')) return false;
  if (!Array.isArray(x.success_indicators) || x.success_indicators.length === 0) return false;
  if (typeof x.rationale !== 'string') return false;
  return true;
}

function safeJsonParse(text: string): any | null {
  if (!text) return null;
  let t = text.trim();
  const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(t);
  if (fence) t = fence[1].trim();
  try { return JSON.parse(t); } catch { return null; }
}

function estimateCostUsdSafe(model: string, promptTokens: number, completionTokens: number): number {
  try {
    const { estimateCostUsd } = require('../llm/security.js') as typeof import('../llm/security.js');
    return estimateCostUsd(model, promptTokens, completionTokens);
  } catch {
    return 0;
  }
}

export async function generatePocForFinding(
  finding: VulnerabilityFinding,
  options: PocGenerationOptions
): Promise<PocGenerationResult> {
  const prompts = buildPocPrompt(finding);
  const request: ChatRequest = {
    messages: [
      { role: 'system', content: prompts.system },
      { role: 'user', content: prompts.user },
    ],
    model: options.model,
    temperature: options.temperature ?? 0.2,
    maxTokens: options.maxTokens ?? 600,
    jsonMode: true,
  };
  let response: ChatResponse;
  try {
    response = await options.router.chat(request, options.preferredProvider);
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
  const parsed = safeJsonParse(response.content || '');
  if (!parsed || !isValidCandidate(parsed)) {
    return { ok: false, rawContent: response.content, error: 'LLM did not return valid PoC JSON' };
  }
  const usage = response.usage || { promptTokens: 0, completionTokens: 0, totalTokens: 0 };
  const costUsd = estimateCostUsdSafe(response.model || options.model || 'gpt-4o-mini', usage.promptTokens, usage.completionTokens);
  const audit = options.audit ?? GLOBAL_AUDIT;
  audit.record({
    fileHash: '',
    fileSize: 0,
    language: undefined,
    provider: response.provider,
    model: response.model,
    promptTokens: usage.promptTokens,
    completionTokens: usage.completionTokens,
    totalTokens: usage.totalTokens,
    costUsd,
    durationMs: 0,
    redactions: [],
    injectionDetected: false,
    injectionRiskScore: 0,
    findingsAccepted: 0,
    findingsRejected: 0,
    rateLimitReached: false,
    outcome: 'success',
  });
  const now = (options.now ?? (() => new Date()))();
  const candidate: PocCandidate = {
    finding: {
      id: finding.id,
      type: normalizeCategory(finding.type),
      file: finding.file,
      line: finding.line,
      cwe: finding.cwe,
    },
    category: parsed.category,
    request: {
      method: String(parsed.request.method).toUpperCase(),
      path: parsed.request.path,
      params: parsed.request.params && typeof parsed.request.params === 'object' ? parsed.request.params : undefined,
      data: typeof parsed.request.data === 'string' ? parsed.request.data : undefined,
    },
    success_indicators: parsed.success_indicators.map(String),
    rationale: parsed.rationale,
    llm: {
      provider: response.provider,
      model: response.model,
      promptTokens: usage.promptTokens,
      completionTokens: usage.completionTokens,
      costUsd,
    },
    generatedAt: now.toISOString(),
    manualReview: true,
  };
  return { ok: true, candidate };
}
