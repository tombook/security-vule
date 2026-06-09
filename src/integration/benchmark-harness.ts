#!/usr/bin/env bun
/**
 * Benchmark harness — run security-vule against real GitHub web-vulnerability apps
 * and compute TP/FP/FN/F1 against ground truth.
 */
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from 'fs';
import { join, relative, extname } from 'path';
import { analyzeFile, type AnalysisResult, type VulnerabilityFinding } from '../engine/analyzer.js';

const SUPPORTED_EXT = new Set(['.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.go', '.rs', '.php', '.phtml']);

interface GroundTruthFinding {
  file: string;
  line: number;
  type: string;
  cwe?: number;
  rule_id?: string;
}

interface PipelineFinding {
  file: string;
  line: number;
  type: string;
  cwe?: number;
  rule_id: string;
  confidence: number;
  message?: string;
}

interface BenchmarkResult {
  app: string;
  total_gt: number;
  total_predictions: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  by_type: Record<string, { tp: number; fp: number; fn: number }>;
  duration_ms: number;
}

function findFilesRecursive(dir: string, exts: Set<string>): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'target' || entry === 'build' || entry === 'dist' || entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...findFilesRecursive(full, exts));
    } else if (exts.has(extname(full))) {
      out.push(full);
    }
  }
  return out;
}

function normalizeType(t: string): string {
  return t.toLowerCase().replace(/[-_\s]/g, '').replace('sqlinjection', 'sqli').replace('xss', 'xss').replace('commandinjection', 'cmdi').replace('pathtraversal', 'pathtraver').replace('weakrandom', 'weakrand').replace('trustboundary', 'trustbound');
}

async function scanFile(path: string, rootDir: string): Promise<PipelineFinding[]> {
  const code = readFileSync(path, 'utf-8');
  const result: AnalysisResult = await analyzeFile(path, code);
  const relPath = relative(rootDir, path);
  return result.vulnerabilities.map((v: VulnerabilityFinding) => ({
    file: relPath,
    line: v.line ?? 0,
    type: normalizeType(v.type || ''),
    cwe: v.cwe ? parseInt(String(v.cwe).replace(/^CWE-/, '')) : undefined,
    rule_id: v.type || 'UNKNOWN',
    confidence: v.confidence ?? 0.5,
    message: v.description || v.title,
  }));
}

function fuzzyMatchType(predType: string, gtType: string): boolean {
  if (!predType || !gtType) return false;
  const p = predType.toLowerCase();
  const g = gtType.toLowerCase();
  if (p === g) return true;
  const syn: Record<string, string[]> = {
    sqli: ['sql_injection', 'sqli', 'sql'],
    xss: ['xss', 'crosssitescripting'],
    cmdi: ['command_injection', 'cmdi', 'os_command_injection', 'shell', 'shell_command', 'cmd'],
    pathtraver: ['path_traversal', 'pathtraver', 'file_write', 'filewrite', 'path'],
    weakrand: ['weak_random', 'weakrand', 'insecure_random'],
    trustbound: ['trust_boundary', 'trustbound', 'broken_access'],
    crypto: ['crypto', 'cryptographic_failures', 'weak_crypto'],
    hash: ['hash', 'insecure_hash', 'weak_hash'],
    securecookie: ['securecookie', 'insecure_cookie'],
    ldapi: ['ldap_injection', 'ldapi', 'ldap'],
    xpathi: ['xpath_injection', 'xpathi', 'xpath'],
    codeinjection: ['codeinjection', 'code_injection', 'eval', 'eval_injection', 'ssjs', 'ssjs_injection', 'dynamic_code', 'dynamiccode'],
    ssrf: ['ssrf', 'server_side_request_forgery', 'open_redirect', 'openredirect'],
  };
  for (const [key, syns] of Object.entries(syn)) {
    if (syns.includes(p) && syns.includes(g)) return true;
  }
  if (p.includes(g) || g.includes(p)) return true;
  return false;
}

function matchFinding(pred: PipelineFinding, gt: GroundTruthFinding): boolean {
  if (pred.file !== gt.file) return false;
  if (gt.line && pred.line && Math.abs(pred.line - gt.line) > 5) return false;
  if (!fuzzyMatchType(pred.type, gt.type)) return false;
  return true;
}

function evaluate(gts: GroundTruthFinding[], preds: PipelineFinding[]): BenchmarkResult {
  const by_type: Record<string, { tp: number; fp: number; fn: number }> = {};
  const usedGt = new Set<number>();
  const usedPred = new Set<number>();
  let tp = 0, fp = 0, fn = 0;

  for (let i = 0; i < preds.length; i++) {
    const p = preds[i];
    let matched = -1;
    for (let j = 0; j < gts.length; j++) {
      if (usedGt.has(j)) continue;
      if (matchFinding(p, gts[j])) { matched = j; break; }
    }
    if (matched >= 0) {
      tp++;
      usedGt.add(matched);
      usedPred.add(i);
      const t = p.type;
      if (!by_type[t]) by_type[t] = { tp: 0, fp: 0, fn: 0 };
      by_type[t].tp++;
    } else {
      fp++;
      const t = p.type;
      if (!by_type[t]) by_type[t] = { tp: 0, fp: 0, fn: 0 };
      by_type[t].fp++;
    }
  }

  for (let j = 0; j < gts.length; j++) {
    if (!usedGt.has(j)) {
      fn++;
      const t = normalizeType(gts[j].type);
      if (!by_type[t]) by_type[t] = { tp: 0, fp: 0, fn: 0 };
      by_type[t].fn++;
    }
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;

  return {
    app: '',
    total_gt: gts.length,
    total_predictions: preds.length,
    tp, fp, fn,
    precision, recall, f1,
    by_type,
    duration_ms: 0,
  };
}

async function runBenchmark(
  appName: string,
  appDir: string,
  gt: GroundTruthFinding[],
  negativeGt: { file: string; type: string; line: number }[] = []
): Promise<BenchmarkResult> {
  const start = Date.now();
  let files = findFilesRecursive(appDir, SUPPORTED_EXT);
  if (gt.length > 0) {
    const gtFiles = new Set(gt.map(g => g.file));
    const negFiles = new Set(negativeGt.map(n => n.file));
    files = files.filter(f => {
      const rel = relative(appDir, f);
      return gtFiles.has(rel) || negFiles.has(rel);
    });
  }
  console.log(`  Files (filtered to GT): ${files.length}`);
  const preds: PipelineFinding[] = [];
  for (const f of files) {
    try {
      const findings = await scanFile(f, appDir);
      preds.push(...findings);
    } catch (e) {
      console.log(`  [warn] failed to scan ${f}: ${(e as Error).message.slice(0, 100)}`);
    }
  }
  const result = evaluate(gt, preds);
  result.app = appName;
  result.duration_ms = Date.now() - start;

  for (const neg of negativeGt) {
    const falsePositive = preds.find(p => p.file === neg.file);
    if (falsePositive) {
      result.fp++;
      const t = normalizeType(neg.type);
      if (!result.by_type[t]) result.by_type[t] = { tp: 0, fp: 0, fn: 0 };
      result.by_type[t].fp++;
    }
  }
  if (negativeGt.length > 0) {
    const tp = result.tp;
    const fp = result.fp;
    const fn = result.fn;
    result.precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    result.recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    result.f1 = result.precision + result.recall > 0 ? 2 * result.precision * result.recall / (result.precision + result.recall) : 0;
  }
  return result;
}

function loadBenchmarkJavaGT(csvPath: string, sourceRoot: string): GroundTruthFinding[] {
  const lines = readFileSync(csvPath, 'utf-8').split('\n');
  const findings: GroundTruthFinding[] = [];
  for (const line of lines) {
    if (line.startsWith('#') || !line.trim()) continue;
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const [testName, category, isReal, cwe] = parts;
    if (isReal !== 'true') continue;
    findings.push({
      file: `${testName}.java`,
      line: 0,
      type: normalizeType(category),
      cwe: cwe ? parseInt(cwe) : undefined,
      rule_id: category,
    });
  }
  return findings;
}

function loadNodeGoatGT(): GroundTruthFinding[] {
  return [
    { file: 'app/routes/contributions.js', line: 32, type: 'codeinjection', rule_id: 'A1' },
    { file: 'app/routes/contributions.js', line: 33, type: 'codeinjection', rule_id: 'A1' },
    { file: 'app/routes/contributions.js', line: 34, type: 'codeinjection', rule_id: 'A1' },
    { file: 'app/routes/index.js', line: 72, type: 'ssrf', rule_id: 'A1-openredirect' },
    { file: 'app/routes/research.js', line: 15, type: 'ssrf', rule_id: 'A1-ssrf' },
    { file: 'app/routes/memos.js', line: 13, type: 'sqlinjection', rule_id: 'A1-nosqli' },
    { file: 'app/routes/profile.js', line: 50, type: 'xss', rule_id: 'A3' },
    { file: 'app/routes/session.js', line: 57, type: 'broken_access_control', rule_id: 'A4' },
    { file: 'app/routes/session.js', line: 198, type: 'broken_access_control', rule_id: 'A4' },
    { file: 'app/routes/benefits.js', line: 33, type: 'broken_access_control', rule_id: 'A4' },
    { file: 'app/routes/allocations.js', line: 18, type: 'broken_access_control', rule_id: 'A4' },
    { file: 'app/routes/allocations.js', line: 21, type: 'broken_access_control', rule_id: 'A4' },
  ];
}

interface DVWAEntry {
  category: string;
  vuln_type: string;
  true_positive_files: string[];
  true_negative_files: string[];
}

function loadDVWAGT(dvwaRoot: string): { positives: GroundTruthFinding[]; negatives: { file: string; type: string; line: number }[] } {
  const gtPath = join(dvwaRoot, 'ground-truth.json');
  if (!existsSync(gtPath)) return { positives: [], negatives: [] };
  const entries: DVWAEntry[] = JSON.parse(readFileSync(gtPath, 'utf-8'));
  const positives: GroundTruthFinding[] = [];
  const negatives: { file: string; type: string; line: number }[] = [];
  for (const e of entries) {
    for (const f of e.true_positive_files) {
      positives.push({ file: `${e.category}/${f}`, line: 0, type: e.vuln_type, rule_id: e.category });
    }
    for (const f of e.true_negative_files) {
      negatives.push({ file: `${e.category}/${f}`, type: e.vuln_type, line: 0 });
    }
  }
  return { positives, negatives };
}

function loadGenericGT(name: string, root: string): { positives: GroundTruthFinding[]; negatives: { file: string; type: string; line: number }[] } {
  const gtPath = join(root, 'ground-truth.json');
  if (!existsSync(gtPath)) return { positives: [], negatives: [] };
  const entries: DVWAEntry[] = JSON.parse(readFileSync(gtPath, 'utf-8'));
  const positives: GroundTruthFinding[] = [];
  const negatives: { file: string; type: string; line: number }[] = [];
  for (const e of entries) {
    for (const f of e.true_positive_files) {
      positives.push({ file: f, line: 0, type: e.vuln_type, rule_id: e.category });
    }
    for (const f of e.true_negative_files) {
      negatives.push({ file: f, type: e.vuln_type, line: 0 });
    }
  }
  return { positives, negatives };
}

function printResult(r: BenchmarkResult): void {
  console.log(`\n\x1b[1m=== ${r.app} ===\x1b[0m`);
  console.log(`  GT: ${r.total_gt}  Predictions: ${r.total_predictions}  TP: ${r.tp}  FP: ${r.fp}  FN: ${r.fn}`);
  console.log(`  Precision: \x1b[${r.precision >= 0.5 ? '32' : '31'}m${(r.precision * 100).toFixed(2)}%\x1b[0m  Recall: \x1b[${r.recall >= 0.5 ? '32' : '31'}m${(r.recall * 100).toFixed(2)}%\x1b[0m  F1: \x1b[${r.f1 >= 0.5 ? '32' : '31'}m${(r.f1 * 100).toFixed(2)}%\x1b[0m`);
  console.log(`  Duration: ${r.duration_ms}ms`);
  console.log(`  Per-type:`);
  const types = Object.keys(r.by_type).sort();
  for (const t of types) {
    const x = r.by_type[t];
    const total = x.tp + x.fp + x.fn;
    const precision = x.tp + x.fp > 0 ? x.tp / (x.tp + x.fp) : 0;
    const recall = x.tp + x.fn > 0 ? x.tp / (x.tp + x.fn) : 0;
    console.log(`    ${t.padEnd(15)} tp=${x.tp} fp=${x.fp} fn=${x.fn}  P=${(precision * 100).toFixed(0)}%  R=${(recall * 100).toFixed(0)}%`);
  }
}

async function main(): Promise<void> {
  console.log('\x1b[1msecurity-vule benchmark — real GitHub vulnerable web apps\x1b[0m\n');

  const results: BenchmarkResult[] = [];

  const nodegoatDir = join(process.cwd(), 'corpus/benchmark/NodeGoat');
  if (existsSync(nodegoatDir)) {
    console.log('Running NodeGoat (OWASP, 2044⭐)...');
    const gt = loadNodeGoatGT();
    const r = await runBenchmark('NodeGoat', nodegoatDir, gt);
    results.push(r);
    printResult(r);
  }

  const benchmarkJavaDir = join(process.cwd(), 'corpus/benchmark/BenchmarkJava');
  const benchmarkJavaGT = join(benchmarkJavaDir, 'expectedresults-1.2.csv');
  const benchmarkJavaSrc = join(benchmarkJavaDir, 'src/main/java/org/owasp/benchmarker');
  if (existsSync(benchmarkJavaDir)) {
    console.log('\nRunning BenchmarkJava (OWASP, 801⭐)...');
    if (existsSync(benchmarkJavaGT)) {
      const gt = loadBenchmarkJavaGT(benchmarkJavaGT, benchmarkJavaDir);
      console.log(`  GT loaded: ${gt.length} real vulnerabilities`);
      const sampleDir = join(benchmarkJavaDir, 'src/main/java/org/owasp/benchmark/testcode');
      const scanDir = existsSync(sampleDir) ? sampleDir : benchmarkJavaSrc;
      const r = await runBenchmark('BenchmarkJava', scanDir, gt);
      results.push(r);
      printResult(r);
    }
  }

  const dvwaDir = join(process.cwd(), 'corpus/benchmark/DVWA');
  if (existsSync(dvwaDir)) {
    console.log('\nRunning DVWA (digininja, 13182⭐)...');
    const dvwaGT = loadDVWAGT(dvwaDir);
    if (dvwaGT.positives.length > 0) {
      console.log(`  GT loaded: ${dvwaGT.positives.length} positive cases, ${dvwaGT.negatives.length} negative cases`);
      const vulnsDir = join(dvwaDir, 'vulnerabilities');
      const r = await runBenchmark('DVWA', vulnsDir, dvwaGT.positives, dvwaGT.negatives);
      results.push(r);
      printResult(r);
    }
  }

  const bwappSrc = '/tmp/bwapp/bWAPP';
  const bwappGTDir = join(process.cwd(), 'corpus/benchmark/bWAPP');
  if (existsSync(bwappSrc) && existsSync(bwappGTDir)) {
    console.log('\nRunning bWAPP (chillitray, 4⭐)...');
    const bwappGT = loadGenericGT('bWAPP', bwappGTDir);
    if (bwappGT.positives.length > 0) {
      console.log(`  GT loaded: ${bwappGT.positives.length} positive cases`);
      const r = await runBenchmark('bWAPP', bwappSrc, bwappGT.positives, bwappGT.negatives);
      results.push(r);
      printResult(r);
    }
  }

  const sqlilabsSrc = '/tmp/sqli-labs';
  const sqlilabsGTDir = join(process.cwd(), 'corpus/benchmark/sqli-labs');
  if (existsSync(sqlilabsSrc) && existsSync(sqlilabsGTDir)) {
    console.log('\nRunning sqli-labs (Audi-1, 9k+⭐)...');
    const slGT = loadGenericGT('sqli-labs', sqlilabsGTDir);
    if (slGT.positives.length > 0) {
      console.log(`  GT loaded: ${slGT.positives.length} positive cases`);
      const r = await runBenchmark('sqli-labs', sqlilabsSrc, slGT.positives, slGT.negatives);
      results.push(r);
      printResult(r);
    }
  }

  const pikachuSrc = '/tmp/pikachu';
  const pikachuGTDir = join(process.cwd(), 'corpus/benchmark/pikachu');
  if (existsSync(pikachuSrc) && existsSync(pikachuGTDir)) {
    console.log('\nRunning Pikachu (zhuifengshaonianhanlu, 4403⭐)...');
    const pGT = loadGenericGT('pikachu', pikachuGTDir);
    if (pGT.positives.length > 0) {
      console.log(`  GT loaded: ${pGT.positives.length} positive cases`);
      const r = await runBenchmark('Pikachu', pikachuSrc, pGT.positives, pGT.negatives);
      results.push(r);
      printResult(r);
    }
  }

  const summaryPath = join(process.cwd(), 'corpus/benchmark/results.json');
  writeFileSync(summaryPath, JSON.stringify(results, null, 2));
  console.log(`\nResults saved to ${summaryPath}`);
}

main().catch(e => { console.error(e); process.exit(1); });
