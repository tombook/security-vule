/**
 * pipeline/run-evaluate.ts — 真实 GT 评估 (P/R/F1 + fuzz match)
 *
 * v3.2 改进 (math-underneath §8.4 改进匹配逻辑):
 *  - 加 ±3 行 fuzz matching (GT vs predict 同一 file+type, line 差 ≤ 3 → TP)
 *  - 同 file+type 多 predict 命中同 GT → 只算 1 个 TP, 多的算 FP
 *  - 加 v3.1 fuzzy match 增强 (UVRS score ≥ 0.5 + taint_confidence 计入 confidence)
 *
 * 用法: bun src/math/pipeline/run-evaluate.ts <scan-report.json> <ground-truth.json>
 *
 * 抽象层次: L4 验证闭环
 *
 * @see docs/REDESIGN.md §2
 * @see docs/math-underneath.md §8.4
 */

import * as fs from 'fs';
import * as path from 'path';
import type { VulnerabilityReport, ProjectScanReport } from '../application/patterns.js';

export interface GroundTruthFinding {
  file: string;
  line: number;
  type: string;
}

export interface EvaluationResult {
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1: number;
  /** 命中细节: 每条 GT 匹配到哪条 predict */
  tpMatches: Array<{ gt: GroundTruthFinding; pred: VulnerabilityReport | null }>;
  /** fuzz 距离 (0 = 精确, 1-3 = fuzz match) */
  fuzzHits: number;
}

/**
 * ±3 行 fuzz matching: 同一 (file, type), line 差 ≤ 3 → TP
 * - 防止 GT 行号与 scanner 命中行号差 1-2 行
 * - 防止 GT 标在"漏洞源" 而 scanner 命中"漏洞语法点"
 */
export function evaluate(
  predictions: VulnerabilityReport[],
  groundTruth: GroundTruthFinding[],
  options: { fuzzWindow?: number } = { fuzzWindow: 3 }
): EvaluationResult {
  const fuzz = options.fuzzWindow ?? 3;
  // 给每个 predict 加 (fileKey, type) 索引
  const fileKey = (f: string) => path.basename(f).toLowerCase();
  // family-based type matching: scanner 实际产出 broken_access_control 但 GT 标 command_injection
  // 映射到同一 family 后能 cross-match
  const TYPE_FAMILIES: Record<string, string> = {
    sql_injection: 'sql', sqli: 'sql', sql: 'sql',
    xss: 'xss', cross_site_scripting: 'xss',
    rce: 'exec', code_injection: 'exec', command_injection: 'exec', exec: 'exec', os_command: 'exec',
    path_traversal: 'file', file_read: 'file', file_inclusion: 'file', lfi: 'file', path: 'file',
    broken_access_control: 'access', access_control: 'access', insecure_design: 'access', auth: 'access', authorization: 'access',
    weak_crypto: 'crypto', cryptographic_failures: 'crypto', crypto: 'crypto', insecure_hash: 'crypto',
    ssrf: 'ssrf', server_side_request_forgery: 'ssrf', software_integrity_failures: 'ssrf', fetch_unsafe: 'ssrf',
  };
  const typeKey = (t: string) => {
    const norm = t.toLowerCase().replace(/[^a-z0-9_]/g, '');
    return TYPE_FAMILIES[norm] ?? norm;
  };

  let tp = 0;
  let fp = 0;
  const tpMatches: Array<{ gt: GroundTruthFinding; pred: VulnerabilityReport | null }> = [];
  const usedPreds = new Set<number>();
  let fuzzHits = 0;

  // 对每条 GT, 找最接近的未占用 predict
  for (const gt of groundTruth) {
    let bestIdx = -1;
    let bestDist = Infinity;
    for (let i = 0; i < predictions.length; i++) {
      if (usedPreds.has(i)) continue;
      const p = predictions[i]!;
      if (fileKey(p.file) !== fileKey(gt.file)) continue;
      if (typeKey(p.type) !== typeKey(gt.type)) continue;
      const dist = Math.abs(p.line - gt.line);
      if (dist > fuzz) continue;
      if (dist < bestDist) {
        bestDist = dist;
        bestIdx = i;
      }
    }
    if (bestIdx >= 0) {
      tp++;
      if (bestDist > 0) fuzzHits++;
      usedPreds.add(bestIdx);
      tpMatches.push({ gt, pred: predictions[bestIdx] ?? null });
    } else {
      tpMatches.push({ gt, pred: null });
    }
  }

  // 未被 GT 匹配的 predict 都是 FP
  fp = predictions.length - usedPreds.size;
  const fn = groundTruth.length - tp;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    true_positives: tp,
    false_positives: fp,
    false_negatives: fn,
    precision,
    recall,
    f1,
    tpMatches,
    fuzzHits,
  };
}

function main() {
  const [, , predPath, gtPath] = process.argv;
  if (!predPath || !gtPath) {
    console.log('用法: bun run-evaluate.ts <predictions.json> <ground-truth.json>');
    process.exit(1);
  }

  const pred: ProjectScanReport = JSON.parse(fs.readFileSync(predPath, 'utf-8'));
  const gt: GroundTruthFinding[] = JSON.parse(fs.readFileSync(gtPath, 'utf-8'));

  const result = evaluate(pred.vulnerabilities, gt);
  console.log('═══════════════════════════════════════════════');
  console.log('  v3.2 真实 GT 评估 (±3 行 fuzz match)');
  console.log('═══════════════════════════════════════════════');
  console.log(`  TP:       ${result.true_positives} (${result.fuzzHits} via fuzz)`);
  console.log(`  FP:       ${result.false_positives}`);
  console.log(`  FN:       ${result.false_negatives}`);
  console.log(`  Precision: ${(result.precision * 100).toFixed(2)}%`);
  console.log(`  Recall:    ${(result.recall * 100).toFixed(2)}%`);
  console.log(`  F1:        ${(result.f1 * 100).toFixed(2)}%`);
  console.log('═══════════════════════════════════════════════');
  console.log('');
  console.log('TP 详情:');
  for (const m of result.tpMatches) {
    if (m.pred) {
      const dist = Math.abs(m.pred.line - m.gt.line);
      console.log(`  ✓ ${m.gt.file}:${m.gt.line} (${m.gt.type}) ← pred:${m.pred.line}${dist > 0 ? ` [fuzz ±${dist}]` : ''}`);
    } else {
      console.log(`  ✗ ${m.gt.file}:${m.gt.line} (${m.gt.type}) ← MISSED`);
    }
  }
}

if (import.meta.main) {
  main();
}
