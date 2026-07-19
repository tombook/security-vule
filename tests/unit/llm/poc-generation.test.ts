import { describe, test, expect, mock } from 'bun:test';
import { generatePocForFinding } from '../../../src/poc/generator.js';
import { GLOBAL_AUDIT } from '../../../src/llm/audit.js';
import type { LLMRouter } from '../../../src/llm/router.js';
import type { ChatRequest, ChatResponse } from '../../../src/llm/types.js';
import type { VulnerabilityFinding } from '../../../src/engine/analyzer.js';

function makeFinding(over: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: 'f1',
    type: 'sqli',
    severity: 'CRITICAL',
    title: 'SQLi',
    description: 'unsanitized user input flows into SQL query',
    file: 'a.php',
    line: 10,
    confidence: 0.9,
    cwe: 'CWE-89',
    ...over,
  };
}

interface MockRouterProto {
  chat(request: ChatRequest, preferredProvider?: string): Promise<ChatResponse>;
}

function makeMockRouter(responder: (req: ChatRequest) => ChatResponse): LLMRouter {
  const r: MockRouterProto = {
    chat: async (req) => responder(req),
  };
  return r as any;
}

describe('poc/generator: generatePocForFinding', () => {
  test('returns ok with candidate for valid LLM JSON', async () => {
    const router = makeMockRouter((req) => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'sqli',
        request: { method: 'POST', path: '/vulnerabilities/sqli/', params: { id: "1' OR 1=1 -- " } },
        success_indicators: ['admin', 'Dumb'],
        rationale: 'classic OR-1=1 injection in id param',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 100, completionTokens: 80, totalTokens: 180 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const fixedNow = new Date('2026-06-25T10:00:00Z');
    const finding = makeFinding();
    const r = await generatePocForFinding(finding, { router, now: () => fixedNow });
    expect(r.ok).toBe(true);
    expect(r.candidate).toBeDefined();
    expect(r.candidate!.category).toBe('sqli');
    expect(r.candidate!.request.method).toBe('POST');
    expect(r.candidate!.request.path).toBe('/vulnerabilities/sqli/');
    expect(r.candidate!.request.params!.id).toContain("OR 1=1");
    expect(r.candidate!.success_indicators.length).toBe(2);
    expect(r.candidate!.finding.id).toBe('f1');
    expect(r.candidate!.finding.type).toBe('sqli');
    expect(r.candidate!.finding.file).toBe('a.php');
    expect(r.candidate!.finding.line).toBe(10);
    expect(r.candidate!.llm.provider).toBe('openai');
    expect(r.candidate!.llm.model).toBe('gpt-4o-mini');
    expect(r.candidate!.llm.promptTokens).toBe(100);
    expect(r.candidate!.llm.completionTokens).toBe(80);
    expect(r.candidate!.manualReview).toBe(true);
    expect(r.candidate!.generatedAt).toBe('2026-06-25T10:00:00.000Z');
  });

  test('parses LLM output wrapped in ```json fences', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: '```json\n' + JSON.stringify({
        category: 'xss',
        request: { method: 'GET', path: '/vulnerabilities/xss_r/', params: { name: '<script>alert(1)</script>' } },
        success_indicators: ['<script>alert'],
        rationale: 'reflected XSS',
      }) + '\n```',
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding({ type: 'xss' }), { router });
    expect(r.ok).toBe(true);
    expect(r.candidate!.category).toBe('xss');
  });

  test('returns ok=false on invalid LLM JSON', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: 'not-json',
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(false);
    expect(r.error).toContain('valid PoC JSON');
    expect(r.rawContent).toBe('not-json');
  });

  test('returns ok=false on schema-invalid LLM JSON', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({ category: 'sqli' }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(false);
    expect(r.error).toContain('valid PoC JSON');
  });

  test('returns ok=false when path does not start with /', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'sqli',
        request: { method: 'GET', path: 'vulnerabilities/sqli' },
        success_indicators: ['x'],
        rationale: 'x',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(false);
  });

  test('returns ok=false on empty success_indicators', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'sqli',
        request: { method: 'POST', path: '/vuln/' },
        success_indicators: [],
        rationale: 'x',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(false);
  });

  test('returns ok=false when router throws', async () => {
    const router: LLMRouter = {
      chat: async () => { throw new Error('rate_limited'); },
    } as any;
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(false);
    expect(r.error).toBe('rate_limited');
  });

  test('normalizes category from finding type', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'should-be-overridden',
        request: { method: 'GET', path: '/vuln/' },
        success_indicators: ['x'],
        rationale: 'x',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding({ type: 'command_injection' }), { router });
    expect(r.ok).toBe(true);
    expect(r.candidate!.finding.type).toBe('shell');
  });

  test('uses upper-case method', async () => {
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'sqli',
        request: { method: 'post', path: '/vuln/' },
        success_indicators: ['x'],
        rationale: 'x',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 50, completionTokens: 50, totalTokens: 100 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router });
    expect(r.ok).toBe(true);
    expect(r.candidate!.request.method).toBe('POST');
  });

  test('records audit entry on success', async () => {
    const auditSpy = mock();
    const customAudit = { record: auditSpy } as any;
    const router = makeMockRouter(() => ({
      id: 'r1',
      content: JSON.stringify({
        category: 'sqli',
        request: { method: 'POST', path: '/vuln/' },
        success_indicators: ['x'],
        rationale: 'x',
      }),
      model: 'gpt-4o-mini',
      provider: 'openai',
      usage: { promptTokens: 11, completionTokens: 22, totalTokens: 33 },
      finishReason: 'stop',
      created: Date.now(),
    }));
    const r = await generatePocForFinding(makeFinding(), { router, audit: customAudit });
    expect(r.ok).toBe(true);
    expect(auditSpy).toHaveBeenCalled();
    const call = auditSpy.mock.calls[0][0];
    expect(call.provider).toBe('openai');
    expect(call.model).toBe('gpt-4o-mini');
    expect(call.promptTokens).toBe(11);
    expect(call.completionTokens).toBe(22);
  });
});
