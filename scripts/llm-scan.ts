import { readFileSync, readdirSync, existsSync, writeFileSync, statSync } from 'fs';
import { extname, join } from 'path';
import { createDefaultRouter } from '../src/llm/router.js';
import { LLMAgent } from '../src/detection/llm-agent.js';
import { runConsensus, formatConsensusReport } from '../src/llm/consensus.js';
import type { VulnerabilityContext, LLMAnalysisResult, VulnerabilityFinding } from '../src/detection/llm-agent.js';
import type { ConsensusResult } from '../src/llm/consensus.js';

type ScanMode = 'consensus' | 'failover';

interface ScanOpts {
  target: string;
  mode: ScanMode;
  providerA: string;
  modelA: string;
  providerB: string;
  modelB: string;
  maxFindings: number;
  verify: boolean;
}

function parseArgs(argv: string[]): ScanOpts {
  const args = argv.slice(2);
  let target = 'test-targets/php-vulns/';
  let mode: ScanMode = 'failover';
  let providerA = 'minimax';
  let modelA = 'MiniMax-M3';
  let providerB = 'zhipu';
  let modelB = 'glm-5.1';
  let maxFindings = 5;
  let verify = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--mode' && args[i + 1]) { mode = args[i + 1] as ScanMode; i++; }
    else if (args[i] === '--provider-a' && args[i + 1]) { providerA = args[i + 1]; i++; }
    else if (args[i] === '--model-a' && args[i + 1]) { modelA = args[i + 1]; i++; }
    else if (args[i] === '--provider-b' && args[i + 1]) { providerB = args[i + 1]; i++; }
    else if (args[i] === '--model-b' && args[i + 1]) { modelB = args[i + 1]; i++; }
    else if (args[i] === '--max-findings' && args[i + 1]) { maxFindings = parseInt(args[i + 1], 10) || 5; i++; }
    else if (args[i] === '--verify') { verify = true; }
    else if (!args[i].startsWith('-')) { target = args[i]; }
  }

  return { target, mode, providerA, modelA, providerB, modelB, maxFindings, verify };
}

function makeCtx(filePath: string, code: string): VulnerabilityContext {
  const ext = extname(filePath).slice(1);
  const langMap: Record<string, string> = { php: 'PHP', py: 'Python', js: 'JavaScript', ts: 'TypeScript', java: 'Java', c: 'C', cpp: 'C++', go: 'Go', rs: 'Rust' };
  return { code, language: langMap[ext] || ext, filePath };
}

function printFinding(f: VulnerabilityFinding, prefix = '    ') {
  const sev = f.severity.toUpperCase().padEnd(8);
  const conf = (f.confidence * 100).toFixed(0).padStart(3);
  console.log(`${prefix}[${sev}] ${f.type} (line ${f.line}, ${conf}% conf) — ${f.description.slice(0, 80)}`);
}

async function scanFailover(
  files: string[], targetDir: string,
  agent: LLMAgent, provider: string, model: string,
  scanOpts: ScanOpts
) {
  console.log(`\n  模式: 主备容灾 (主: ${provider}/${model})`);
  console.log(`  最大发现数/文件: ${scanOpts.maxFindings}`);
  if (scanOpts.verify) console.log(`  二次验证: 开启`);
  console.log();

  const allResults: Array<{ file: string; result: LLMAnalysisResult; verified?: Array<VulnerabilityFinding & { verified: boolean; verifyReason: string }> }> = [];

  for (const file of files) {
    const filePath = join(targetDir, file);
    const code = readFileSync(filePath, 'utf-8');
    const ctx = makeCtx(filePath, code);

    try {
      console.log(`  [主备] ${file}...`);
      const result = await agent.analyzeVulnerabilities(ctx, { maxFindings: scanOpts.maxFindings });

      let verified: Array<VulnerabilityFinding & { verified: boolean; verifyReason: string }> | undefined;
      if (scanOpts.verify && result.findings.length > 0) {
        console.log(`    [验证] 二次验证 ${result.findings.length} 个发现...`);
        verified = await agent.verifyFindings(ctx, result.findings);
        const kept = verified.filter(v => v.verified).length;
        result.findings = verified.filter(v => v.verified);
        console.log(`    [验证] 保留 ${kept}/${verified.length} 个 (剔除 ${verified.length - kept} 个误报)`);
      }

      allResults.push({ file, result, verified });

      if (result.findings.length > 0) {
        for (const f of result.findings) printFinding(f);
      } else {
        console.log(`    未发现漏洞`);
      }
      console.log(`    模型: ${result.model} | Token: ${result.tokenUsage?.total ?? 0}`);
    } catch (err: any) {
      console.error(`    错误: ${err.message}`);
    }
  }

  return allResults;
}

async function scanConsensus(
  files: string[], targetDir: string,
  agentA: LLMAgent, agentB: LLMAgent,
  providerA: string, modelA: string, providerB: string, modelB: string,
  scanOpts: ScanOpts
) {
  console.log(`\n  模式: 双模型并行共识`);
  console.log(`  模型 A: ${providerA}/${modelA}`);
  console.log(`  模型 B: ${providerB}/${modelB}`);
  console.log(`  最大发现数/文件: ${scanOpts.maxFindings}`);
  if (scanOpts.verify) console.log(`  二次验证: 开启`);
  console.log(`  两个模型独立分析，合并共识结果\n`);

  const allConsensus: Array<{ file: string; consensus: ConsensusResult; resA: LLMAnalysisResult; resB: LLMAnalysisResult }> = [];

  for (const file of files) {
    const filePath = join(targetDir, file);
    const code = readFileSync(filePath, 'utf-8');
    const ctx = makeCtx(filePath, code);

    try {
      console.log(`  [共识] ${file}...`);

      const [resA, resB] = await Promise.all([
        agentA.analyzeVulnerabilities(ctx, { maxFindings: scanOpts.maxFindings }).catch(e => ({ findings: [] as VulnerabilityFinding[], summary: `Error: ${e.message}`, model: modelA, provider: providerA, tokenUsage: { prompt: 0, completion: 0, total: 0 }, duration: 0, redactions: [], injectionDetected: false, injectionMatches: [] })),
        agentB.analyzeVulnerabilities(ctx, { maxFindings: scanOpts.maxFindings }).catch(e => ({ findings: [] as VulnerabilityFinding[], summary: `Error: ${e.message}`, model: modelB, provider: providerB, tokenUsage: { prompt: 0, completion: 0, total: 0 }, duration: 0, redactions: [], injectionDetected: false, injectionMatches: [] })),
      ]);

      const consensus = await runConsensus(ctx, agentA, agentB);

      if (scanOpts.verify && consensus.confirmed.length > 0) {
        console.log(`    [验证] 二次验证 ${consensus.confirmed.length} 个共识发现...`);
        const verified = await agentA.verifyFindings(ctx, consensus.confirmed);
        consensus.confirmed = verified.filter(v => v.verified);
        const kept = consensus.confirmed.length;
        console.log(`    [验证] 保留 ${kept}/${verified.length} 个共识发现`);
      }

      console.log(`    模型A (${resA.model}): ${resA.findings.length} 个发现 | Token: ${resA.tokenUsage?.total ?? 0}`);
      console.log(`    模型B (${resB.model}): ${resB.findings.length} 个发现 | Token: ${resB.tokenUsage?.total ?? 0}`);

      if (consensus.confirmed.length > 0) {
        console.log(`    ✅ 共识确认 (${consensus.stats.confirmedCount} 个):`);
        for (const f of consensus.confirmed) printFinding(f, '      ');
      }
      if (consensus.onlyA.length > 0) {
        console.log(`    🔵 仅模型A (${consensus.onlyA.length} 个):`);
        for (const e of consensus.onlyA) { if (e.findingA) printFinding(e.findingA, '      '); }
      }
      if (consensus.onlyB.length > 0) {
        console.log(`    🟢 仅模型B (${consensus.onlyB.length} 个):`);
        for (const e of consensus.onlyB) { if (e.findingB) printFinding(e.findingB, '      '); }
      }
      if (consensus.disputed.length > 0) {
        console.log(`    ⚠️  存在争议 (${consensus.disputed.length} 个):`);
        for (const d of consensus.disputed) {
          console.log(`      A=${d.findingA?.severity} B=${d.findingB?.severity} line ${d.findingA?.line} — ${d.reason}`);
        }
      }

      allConsensus.push({ file, consensus, resA, resB });
    } catch (err: any) {
      console.error(`    错误: ${err.message}`);
    }
  }

  return allConsensus;
}

async function main() {
  const opts = parseArgs(process.argv);
  const exts = ['.php', '.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rs'];

  const stat = existsSync(opts.target) ? statSync(opts.target) : null;
  if (!stat) {
    console.error(`目标不存在: ${opts.target}`);
    process.exit(1);
  }

  let files: string[];
  let targetDir: string;
  if (stat.isFile()) {
    const p = opts.target;
    const sep = p.lastIndexOf('/');
    targetDir = sep >= 0 ? p.slice(0, sep) : '.';
    files = [sep >= 0 ? p.slice(sep + 1) : p];
  } else {
    targetDir = opts.target;
    files = readdirSync(targetDir)
      .filter(f => exts.includes(extname(f)))
      .sort();
  }

  console.log('═══════════════════════════════════════════════');
  console.log('  security-vule 双模型 LLM 扫描引擎');
  console.log('═══════════════════════════════════════════════');

  const router = createDefaultRouter();
  const providers = router.listProviders();
  console.log(`已注册提供商: ${providers.join(', ')}`);

  if (providers.length === 0) {
    console.error('未检测到 LLM 提供商。请设置 ZHIPU_API_KEY 或 MINIMAX_API_KEY。');
    process.exit(1);
  }

  console.log(`扫描目标: ${opts.target} (${files.length} 个文件)`);
  console.log(`扫描模式: ${opts.mode === 'consensus' ? '双模型并行共识' : '主备容灾'}`);
  console.log(`最大发现数: ${opts.maxFindings} | 二次验证: ${opts.verify ? '开' : '关'}`);

  const startTime = Date.now();

  if (opts.mode === 'consensus') {
    const agentA = new LLMAgent(router, opts.providerA, opts.modelA);
    const agentB = new LLMAgent(router, opts.providerB, opts.modelB);
    const results = await scanConsensus(files, targetDir, agentA, agentB, opts.providerA, opts.modelA, opts.providerB, opts.modelB, opts);

    let totalConfirmed = 0;
    let totalOnlyA = 0;
    let totalOnlyB = 0;
    let totalDisputed = 0;
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    let totalTokens = 0;

    for (const { consensus, resA, resB } of results) {
      totalConfirmed += consensus.confirmed.length;
      totalOnlyA += consensus.onlyA.length;
      totalOnlyB += consensus.onlyB.length;
      totalDisputed += consensus.disputed.length;
      for (const f of consensus.confirmed) {
        byType[f.type] = (byType[f.type] || 0) + 1;
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      }
      totalTokens += (resA.tokenUsage?.total ?? 0) + (resB.tokenUsage?.total ?? 0);
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    console.log('\n\n═══════════════════════════════════════════════');
    console.log('  双模型共识扫描报告');
    console.log('═══════════════════════════════════════════════\n');
    console.log(`模型 A: ${opts.providerA}/${opts.modelA}`);
    console.log(`模型 B: ${opts.providerB}/${opts.modelB}`);
    console.log(`文件数: ${files.length}`);
    console.log(`耗时: ${elapsed}s | Token 总计: ${totalTokens}`);
    console.log(`共识确认: ${totalConfirmed}`);
    console.log(`仅模型A: ${totalOnlyA}`);
    console.log(`仅模型B: ${totalOnlyB}`);
    console.log(`存在争议: ${totalDisputed}`);
    console.log(`按类型: ${JSON.stringify(byType)}`);
    console.log(`按严重度: ${JSON.stringify(bySeverity)}`);

    const report = {
      tool: 'security-vule (双模型共识)',
      mode: 'consensus',
      model_a: `${opts.providerA}/${opts.modelA}`,
      model_b: `${opts.providerB}/${opts.modelB}`,
      target: opts.target,
      files_scanned: files.length,
      elapsed_seconds: parseFloat(elapsed),
      total_tokens: totalTokens,
      total_confirmed: totalConfirmed,
      total_only_a: totalOnlyA,
      total_only_b: totalOnlyB,
      total_disputed: totalDisputed,
      by_type: byType,
      by_severity: bySeverity,
      files: results.map(({ file, consensus, resA, resB }) => ({
        file,
        model_a: { findings: resA.findings.length, tokens: resA.tokenUsage?.total ?? 0 },
        model_b: { findings: resB.findings.length, tokens: resB.tokenUsage?.total ?? 0 },
        confirmed: consensus.confirmed,
        only_a: consensus.onlyA,
        only_b: consensus.onlyB,
        disputed: consensus.disputed,
      })),
    };

    const outPath = 'docs/security-vule-llm-results.json';
    writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`\n报告已保存: ${outPath}`);

  } else {
    const agent = new LLMAgent(router, opts.providerA, opts.modelA);
    const results = await scanFailover(files, targetDir, agent, opts.providerA, opts.modelA, opts);

    let totalFindings = 0;
    const bySeverity: Record<string, number> = {};
    const byType: Record<string, number> = {};

    for (const { result } of results) {
      for (const f of result.findings) {
        totalFindings++;
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        byType[f.type] = (byType[f.type] || 0) + 1;
      }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    console.log('\n\n═══════════════════════════════════════════════');
    console.log('  主备容灾扫描报告');
    console.log('═══════════════════════════════════════════════\n');
    console.log(`主模型: ${opts.providerA}/${opts.modelA}`);
    console.log(`备用模型: ${opts.providerB}/${opts.modelB} (主模型失败时自动切换)`);
    console.log(`文件数: ${files.length}`);
    console.log(`耗时: ${elapsed}s`);
    console.log(`发现数: ${totalFindings}`);
    console.log(`按严重度: ${JSON.stringify(bySeverity)}`);
    console.log(`按类型: ${JSON.stringify(byType)}`);

    const report = {
      tool: 'security-vule (主备容灾)',
      mode: 'failover',
      primary: `${opts.providerA}/${opts.modelA}`,
      backup: `${opts.providerB}/${opts.modelB}`,
      target: opts.target,
      files_scanned: files.length,
      elapsed_seconds: parseFloat(elapsed),
      total_findings: totalFindings,
      by_severity: bySeverity,
      by_type: byType,
      results: results.map(({ file, result }) => ({
        file,
        findings: result.findings,
        summary: result.summary,
        model: result.model,
        provider: result.provider,
        tokenUsage: result.tokenUsage,
      })),
    };

    const outPath = 'docs/security-vule-llm-results.json';
    writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`\n报告已保存: ${outPath}`);
  }
}

main().catch(console.error);
