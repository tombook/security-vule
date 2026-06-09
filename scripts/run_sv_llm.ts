#!/usr/bin/env bun
import * as fs from 'fs';
import * as path from 'path';
import { LLMRouter } from '../src/llm/router.js';
import { createZhipuCodingProvider } from '../src/llm/providers/openai-compatible.js';
import { LLMAgent, type VulnerabilityFinding } from '../src/detection/llm-agent.js';

interface ScannedFinding {
  file: string;
  type: string;
  severity: string;
  line: number;
  description: string;
  remediation: string;
  cwe?: string;
  confidence: number;
  model: string;
}

async function scanOne(agent: LLMAgent, filePath: string): Promise<ScannedFinding[]> {
  const code = fs.readFileSync(filePath, 'utf-8');
  const result = await agent.analyzeVulnerabilities({
    code,
    language: 'php',
    filePath,
  });
  return result.findings.map((f: VulnerabilityFinding) => ({
    file: path.basename(filePath),
    type: f.type,
    severity: f.severity,
    line: f.line,
    description: f.description,
    remediation: f.remediation,
    cwe: f.cwe,
    confidence: f.confidence,
    model: result.model,
  }));
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: bun run_sv_llm.ts <corpus_dir> [output.json] [parallelism]');
    process.exit(1);
  }
  const corpusDir = path.resolve(args[0]);
  const outFile = args[1] ? path.resolve(args[1]) : '/tmp/sv_llm_findings.json';
  const parallelism = args[2] ? parseInt(args[2], 10) : 4;

  const apiKey = process.env.ZHIPU_CODING_API_KEY || process.env.ZHIPU_API_KEY || '';
  if (!apiKey) {
    console.error('ZHIPU_CODING_API_KEY (or ZHIPU_API_KEY) env var required');
    process.exit(1);
  }

  const router = new LLMRouter();
  router.registerProvider('zhipu-coding', createZhipuCodingProvider(apiKey));
  const agent = new LLMAgent(router, 'zhipu-coding', 'glm-5.1');

  const files = fs.readdirSync(corpusDir)
    .filter(f => f.endsWith('.php'))
    .map(f => path.join(corpusDir, f))
    .sort();

  console.error(`Scanning ${files.length} files with security-vule + LLMAgent (GLM-5.1, parallelism=${parallelism})...`);

  const allFindings: ScannedFinding[] = [];
  const t0 = Date.now();
  let completed = 0;

  const queue = [...files];
  const workers = Array.from({ length: parallelism }, async () => {
    while (queue.length > 0) {
      const f = queue.shift()!;
      try {
        const findings = await scanOne(agent, f);
        allFindings.push(...findings);
        completed++;
        if (completed % 5 === 0 || completed === files.length) {
          console.error(`  [${completed}/${files.length}] elapsed=${((Date.now() - t0) / 1000).toFixed(1)}s findings=${allFindings.length}`);
        }
      } catch (e) {
        completed++;
        console.error(`  ${path.basename(f)}: ${(e as Error).message?.slice(0, 100)}`);
      }
    }
  });
  await Promise.all(workers);

  const elapsed = (Date.now() - t0) / 1000;
  const result = {
    tool: 'security-vule + LLMAgent (GLM-5.1)',
    model: 'glm-5.1',
    files_scanned: files.length,
    findings_total: allFindings.length,
    duration_seconds: elapsed,
    findings: allFindings,
  };
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
  console.error(`\nDone. ${allFindings.length} findings in ${elapsed.toFixed(1)}s. Saved to ${outFile}`);
}

main().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});