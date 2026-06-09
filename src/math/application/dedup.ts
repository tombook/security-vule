/**
 * application/dedup.ts — 去重 + 置信度过滤
 *
 * v3.0 重新设计后, 从此处导出.
 * 原 cosm-x-dedup.ts (79 行) 完整迁入, 修复 import 路径指向新 patterns.ts.
 *
 * 抽象层次: L3 漏洞挖掘应用
 *
 * @see docs/REDESIGN.md §2
 */

import type { VulnerabilityReport } from './patterns.js';

/**
 * 判断一行代码是否在注释内
 * 支持 // (行注释), /* *​/ (块注释), # (Python/Ruby/shell)
 */
export function isInComment(line: string, fileExt: string): boolean {
  const trimmed = line.trim();
  if (fileExt === '.py' || fileExt === '.rb' || fileExt === '.sh') {
    if (trimmed.startsWith('#')) return true;
  } else {
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return true;
  }
  // 行内注释在匹配位置之前
  if (fileExt !== '.py' && fileExt !== '.rb' && fileExt !== '.sh') {
    if (/\/\//.test(line)) return true;
  }
  return false;
}

/**
 * 按 (file, type) 维度去重, 保留 UVRS unified_score 最高的一条
 * Precision 提升主手段: 同一文件同一漏洞类型只报 1 个
 */
export function deduplicateByFileType(reports: VulnerabilityReport[]): VulnerabilityReport[] {
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const map = new Map<string, VulnerabilityReport>();
  for (const r of reports) {
    const key = `${r.file}::${r.type}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, r);
      continue;
    }
    const rScore = r.uvrs?.unified_score ?? r.score;
    const eScore = existing.uvrs?.unified_score ?? existing.score;
    if (
      rScore > eScore ||
      (rScore === eScore && sevRank[r.severity]! > sevRank[existing.severity]!)
    ) {
      map.set(key, r);
    }
  }
  return Array.from(map.values());
}

/**
 * 按 (file, line, type) 精确去重
 */
export function deduplicateByFileLineType(reports: VulnerabilityReport[]): VulnerabilityReport[] {
  const map = new Map<string, VulnerabilityReport>();
  for (const r of reports) {
    const key = `${r.file}::${r.line}::${r.type}`;
    if (!map.has(key)) map.set(key, r);
  }
  return Array.from(map.values());
}

/**
 * 按 score 阈值过滤 (低置信度匹配直接丢弃)
 * 优先级: UVRS (×100 归一到 0-100) > 6 维 score
 *
 * v2.5.1 修复: 之前用 max(uvrs*100, score) → score 恒 100 → 过滤失效.
 * 改用 UVRS 优先 (UVRS > 0.1 即认为 informative), 0.01/0.05 那种 UVRS 才 fallback score.
 */
export function filterByMinScore(reports: VulnerabilityReport[], minScore: number): VulnerabilityReport[] {
  if (minScore <= 0) return reports;
  return reports.filter((r) => {
    const uvrs0to100 = (r.uvrs?.unified_score ?? 0) * 100;
    // UVRS < 10/100 (0.1) 视为不 informative (broken 集成), 用 6 维 score 兜底
    const s = uvrs0to100 >= 10 ? uvrs0to100 : r.score;
    return s >= minScore;
  });
}
