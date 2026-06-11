/**
 * LLM vs AST benchmark — runs both modes against same target, compares metrics.
 * Usage: bun scripts/benchmark-llm-vs-ast.ts <target>
 */
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';

const TARGET = process.argv[2] ?? '/tmp/sv-poc-eval/test-fixtures/';
const LLM_API_KEY = process.env.MINIMAX_API_KEY ?? process.env.ZHIPU_API_KEY;

const AST_PATTERNS: Array<{ regex: RegExp; type: string; severity: string; dim: string }> = [
  { regex: /\beval\s*\(/i, type: 'Code Injection (eval)', severity: 'CRITICAL', dim: 'gravity' },
  { regex: /\bsystem\s*\(/i, type: 'Command Injection', severity: 'CRITICAL', dim: 'gravity' },
  { regex: /\bmysql_query\s*\(/i, type: 'SQL Injection', severity: 'CRITICAL', dim: 'gravity' },
  { regex: /\bmysqli_query\s*\(/i, type: 'SQL Injection', severity: 'CRITICAL', dim: 'gravity' },
  { regex: /\bfile_get_contents\s*\(/i, type: 'LFI', severity: 'HIGH', dim: 'tidal' },
  { regex: /\binclude\s*\(?\s*\$_/i, type: 'LFI', severity: 'HIGH', dim: 'tidal' },
  { regex: /move_uploaded_file/i, type: 'File Upload', severity: 'HIGH', dim: 'fileUpload' },
  {
    regex: /\bunserialize\s*\(/i,
    type: 'Insecure Deserialization',
    severity: 'HIGH',
    dim: 'chaos',
  },
  {
    regex: /\bmd5\s*\(|\bsha1\s*\(/i,
    type: 'Weak Cryptography',
    severity: 'MEDIUM',
    dim: 'information',
  },
  {
    regex: /password\s*=\s*["']\w{4,}/i,
    type: 'Hardcoded Credential',
    severity: 'HIGH',
    dim: 'darkMatter',
  },
];

async function astScan(
  target: string
): Promise<{
  files: number;
  findings: Array<{ type: string; file: string; line: number; severity: string }>;
  durationMs: number;
}> {
  const start = Date.now();
  const findings: Array<{ type: string; file: string; line: number; severity: string }> = [];
  const files = await collectFiles(target);

  for (const file of files) {
    const ext = extname(file);
    if (!['.php', '.py', '.js', '.ts'].includes(ext)) continue;
    const code = readFileSync(file, 'utf8');
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const p of AST_PATTERNS) {
        if (p.regex.test(lines[i] ?? '')) {
          findings.push({ type: p.type, file, line: i + 1, severity: p.severity });
        }
      }
    }
  }
  return { files: files.length, findings, durationMs: Date.now() - start };
}

async function collectFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    try {
      const stat = statSync(cur);
      if (stat.isFile()) {
        out.push(cur);
        continue;
      }
      if (!stat.isDirectory()) continue;
      const entries = readdirSync(cur);
      for (const e of entries) {
        if (e === 'node_modules' || e === '.git' || e.startsWith('.')) continue;
        stack.push(join(cur, e));
      }
    } catch {
      /* ignore */
    }
  }
  return out;
}

async function llmScan(
  target: string
): Promise<{
  files: number;
  findings: Array<{ type: string; file: string; line: number; severity: string }>;
  durationMs: number;
  costUsd: number;
  tokens: number;
}> {
  if (!LLM_API_KEY) {
    throw new Error('No LLM API key set (MINIMAX_API_KEY or ZHIPU_API_KEY)');
  }
  const start = Date.now();
  const { createDefaultRouter } = await import('../src/llm/router.js');
  const { LLMAgent } = await import('../src/detection/llm-agent.js');

  const router = createDefaultRouter();
  const provider = router.providers[0];
  if (!provider) throw new Error('No LLM provider available');

  const agent = new LLMAgent(router, provider.name, 'MiniMax-M3');
  const files = await collectFiles(target);

  const findings: Array<{ type: string; file: string; line: number; severity: string }> = [];
  let totalTokens = 0;
  let totalCost = 0;

  for (const file of files) {
    const ext = extname(file);
    if (!['.php', '.py', '.js', '.ts'].includes(ext)) continue;
    const code = readFileSync(file, 'utf8');
    const context = {
      file,
      language: ext.slice(1) as 'php' | 'python' | 'javascript' | 'typescript',
      code,
      lines: code.split('\n').length,
    };
    const result = await agent.analyze(context);
    totalTokens += result.tokensUsed;
    totalCost += result.costUsd;
    for (const f of result.findings) {
      findings.push({ type: f.type, file, line: f.line, severity: f.severity });
    }
  }
  return {
    files: files.length,
    findings,
    durationMs: Date.now() - start,
    costUsd: totalCost,
    tokens: totalTokens,
  };
}

async function main() {
  console.log('🌌 security-vule LLM vs AST benchmark');
  console.log(`Target: ${TARGET}`);
  console.log(`Files to scan:`);
  const files = await collectFiles(TARGET);
  console.log(` ${files.length} files`);
  console.log('');

  console.log('=== AST mode ===');
  const ast = await astScan(TARGET);
  console.log(` Duration: ${ast.durationMs}ms`);
  console.log(` Findings: ${ast.findings.length}`);
  console.log(` Cost: $0`);
  const astByType: Record<string, number> = {};
  for (const f of ast.findings) astByType[f.type] = (astByType[f.type] ?? 0) + 1;
  console.log(' By type:');
  for (const [k, v] of Object.entries(astByType)) {
    console.log(` ${k}: ${v}`);
  }
  console.log('');

  if (LLM_API_KEY) {
    console.log('=== LLM-enhanced mode ===');
    try {
      const llm = await llmScan(TARGET);
      console.log(` Duration: ${llm.durationMs}ms`);
      console.log(` Findings: ${llm.findings.length}`);
      console.log(` Cost: $${llm.costUsd.toFixed(4)}`);
      console.log(` Tokens: ${llm.tokens}`);
      const llmByType: Record<string, number> = {};
      for (const f of llm.findings) llmByType[f.type] = (llmByType[f.type] ?? 0) + 1;
      console.log(' By type:');
      for (const [k, v] of Object.entries(llmByType)) {
        console.log(` ${k}: ${v}`);
      }
      console.log('');
      console.log('=== Comparison ===');
      const astTypes = new Set(ast.findings.map((f) => f.type));
      const llmTypes = new Set(llm.findings.map((f) => f.type));
      const onlyLLM = [...llmTypes].filter((t) => !astTypes.has(t));
      const onlyAST = [...astTypes].filter((t) => !llmTypes.has(t));
      console.log(` AST only: ${onlyAST.join(', ') || '(none)'}`);
      console.log(` LLM only: ${onlyLLM.join(', ') || '(none)'}`);
      console.log(` Common: ${[...astTypes].filter((t) => llmTypes.has(t)).join(', ')}`);
      console.log(` Speed ratio: ${(llm.durationMs / ast.durationMs).toFixed(1)}x slower for LLM`);
    } catch (e) {
      console.log(` LLM mode skipped: ${(e as Error).message}`);
    }
  } else {
    console.log('LLM mode: skipped (set MINIMAX_API_KEY or ZHIPU_API_KEY to enable)');
  }

  console.log('');
  console.log('✅ Benchmark complete');
}

main().catch((e) => {
  console.error('❌ Benchmark failed:', e);
  process.exit(1);
});
