/**
 * Example 2: LLM-enhanced scan with verify pass.
 *
 * Demonstrates how to use the LLM scanning engine programmatically
 * with two-model consensus and false-positive filtering.
 *
 * Prereqs: Set MINIMAX_API_KEY and/or ZHIPU_API_KEY
 *
 * Run: export MINIMAX_API_KEY="sk-cp-..."; bun run examples/llm-scan/scan.ts
 */
import { readFileSync } from 'fs';
import { LLMAgent } from '../../src/detection/llm-agent.js';
import { createDefaultRouter } from '../../src/llm/router.js';
import { childLogger } from '../../src/utils/logger.js';

const log = childLogger('examples.llm-scan');

const TARGET = process.argv[2] || 'test-targets/php-vulns/dvwa_sqli_low.php';
const code = readFileSync(TARGET, 'utf-8');
log.info({ target: TARGET, lines: code.split('\n').length }, 'starting LLM scan');

// Step 1: Create LLM router
const router = createDefaultRouter();
log.info({ providers: router.listProviders() }, 'router initialized');

// Step 2: Create LLM agent (uses preferred provider)
const agent = new LLMAgent(
  router,
  process.env['LLM_PROVIDER'] || 'minimax',
  process.env['LLM_MODEL'] || 'MiniMax-M3'
);

// Step 3: Run analysis
const ctx = {
  code,
  language: 'php',
  filePath: TARGET,
};
const result = await agent.analyzeVulnerabilities(ctx, { maxFindings: 5 });

log.info(
  {
    findings: result.findings.length,
    model: result.model,
    provider: result.provider,
    duration: result.duration,
    tokens: result.tokenUsage?.total,
    redactions: result.redactions?.length,
    injectionDetected: result.injectionDetected,
  },
  'analysis complete'
);

// Step 4: Display findings
console.log(`\n🔍 Findings (${result.findings.length}):\n`);
for (const f of result.findings) {
  console.log(`   [${f.severity.toUpperCase().padEnd(8)}] ${f.type} @ line ${f.line}`);
  console.log(`           ${f.description.slice(0, 100)}...`);
  console.log(`           CWE: ${f.cwe} | Confidence: ${(f.confidence * 100).toFixed(0)}%`);
}

console.log(`\n📝 Summary: ${result.summary}`);
