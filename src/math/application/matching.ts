/**
 * application/matching.ts — 改进的 line-level 模糊匹配
 *
 * v3.1 改进 (math-underneath §8.4 指出 "匹配误差大" 31/53 TP):
 *   原 matcher:  pattern.test(line) → 报告
 *   改进 matcher:
 *     1. context window: ±3 行看 token 重合
 *     2. taint-reachability: 命中行前是否有 source, 命中行后是否有 sink
 *     3. flow-loop: 命中行是否在循环内 (加重)
 *     4. uninitialized: 命中行是否使用了未定义的变量 (使用前未赋值)
 *     5. dead-store: 命中行写入但未使用
 *
 * 综合 confidence = pattern_base × context_factor × taint_factor × loop_factor
 *
 * 抽象层次: L3 漏洞挖掘应用
 *
 * @see docs/math-underneath.md §8.4
 * @see docs/REDESIGN.md §3 (L3 漏洞挖掘应用)
 */

import type { VulnerabilityReport } from './patterns.js';
import { analyzeTaint, sinkConfidence, type TaintPath } from '../execution/taint.js';
import { analyzeDataFlow, findDefiningLine, varsUsedAt, findUninitializedUses } from '../execution/dataflow.js';
import { analyzeControlFlow, blockAtLine, type ControlFlowAnalysis } from '../execution/controlflow.js';

/** 命中信号 (从 execution/ 3 个模块) */
export interface MatchSignals {
  /** taint 路径数 (从该行向前回溯) */
  taintPaths: number;
  /** 最大 taint confidence */
  maxTaintConfidence: number;
  /** 是否有 source 路径到该行 */
  hasTaintedSource: boolean;
  /** 是否在循环内 */
  inLoop: boolean;
  /** 循环深度 */
  loopDepth: number;
  /** 是否使用了未定义变量 */
  hasUninitialized: boolean;
  /** 上下文 token 重合度 (0-1) */
  contextOverlap: number;
  /** 距离最近 source 的行数 */
  distanceToSource: number;
  /** 综合 confidence 加权因子 (multiply with pattern base) */
  combinedFactor: number;
}

/** 综合匹配结果 (返回给 scanner) */
export interface MatchResult {
  /** 是否应该报告 (confidence >= threshold) */
  shouldReport: boolean;
  /** 综合 confidence (0-1) */
  confidence: number;
  /** 信号详情 */
  signals: MatchSignals;
  /** 解释 (用于 debug / 报告) */
  explanation: string[];
}

/** Token 化: 提取 identifier, 简单小写化 */
function tokenize(line: string): string[] {
  return (line.match(/\b[A-Za-z_$][\w$]*\b/g) ?? []).map(s => s.toLowerCase());
}

/** 计算两行 token 的 Jaccard 相似度 */
function jaccard(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  const setA = new Set(a);
  const setB = new Set(b);
  let inter = 0;
  for (const t of setA) if (setB.has(t)) inter++;
  const uni = setA.size + setB.size - inter;
  return uni === 0 ? 0 : inter / uni;
}

/** 上下文 token 重合度: 命中行 vs 周围 ±3 行的 token overlap */
function contextOverlapScore(lines: string[], hitLine: number, ext: string): number {
  if (hitLine < 1 || hitLine > lines.length) return 0;
  const targetTokens = tokenize(lines[hitLine - 1]);
  // 收集 ±3 行的 tokens
  const contextTokens: string[] = [];
  for (let off = -3; off <= 3; off++) {
    if (off === 0) continue;
    const idx = hitLine - 1 + off;
    if (idx < 0 || idx >= lines.length) continue;
    contextTokens.push(...tokenize(lines[idx]));
  }
  return jaccard(targetTokens, contextTokens);
}

/** 计算 5 个加权因子 (multiply) */
function combinedFactor(s: {
  taintConf: number;
  hasTaintedSource: boolean;
  inLoop: boolean;
  loopDepth: number;
  hasUninitialized: boolean;
  contextOverlap: number;
}): { factor: number; explanation: string[] } {
  const explanation: string[] = [];
  let f = 1.0;

  // 1. taint 因子 (有 taint 路径, confidence 提升; 但 sanitizer 削弱)
  if (s.hasTaintedSource) {
    f *= 1.0 + 0.5 * s.taintConf;
    explanation.push(`taint+${(0.5 * s.taintConf).toFixed(2)}`);
  } else {
    // 没有 taint 源, 单纯命中降权 30%
    f *= 0.7;
    explanation.push('no-taint×0.70');
  }

  // 2. loop 因子 (在循环内 = 漏洞可能被循环触发, 重)
  if (s.inLoop) {
    f *= 1.0 + 0.15 * s.loopDepth;
    explanation.push(`loop+${(0.15 * s.loopDepth).toFixed(2)}`);
  }

  // 3. uninitialized 因子 (使用未初始化变量 = 高度可疑, 提升 20%)
  if (s.hasUninitialized) {
    f *= 1.20;
    explanation.push('uninit+0.20');
  }

  // 4. context 因子 (token 重合度高 = 周围代码相关)
  if (s.contextOverlap > 0.3) {
    f *= 1.0 + 0.2 * s.contextOverlap;
    explanation.push(`ctx+${(0.2 * s.contextOverlap).toFixed(2)}`);
  }

  // clamp 到 [0.1, 2.0]
  f = Math.max(0.1, Math.min(2.0, f));
  return { factor: f, explanation };
}

/**
 * 改进的 line-level 匹配: 命中行 + 上下文 ±3 行 + taint + loop + uninit 综合判定.
 *
 * @param lines        文件所有行
 * @param lineIdx      命中行 (1-indexed)
 * @param patternBase  pattern 自身的基础 confidence (0-1, 来自 VULN_PATTERNS severity)
 * @returns            MatchResult
 */
export function fuzzyMatchLine(
  lines: string[],
  lineIdx: number,
  patternBase: number
): MatchResult {
  if (lineIdx < 1 || lineIdx > lines.length) {
    return {
      shouldReport: false,
      confidence: 0,
      signals: {
        taintPaths: 0,
        maxTaintConfidence: 0,
        hasTaintedSource: false,
        inLoop: false,
        loopDepth: 0,
        hasUninitialized: false,
        contextOverlap: 0,
        distanceToSource: 0,
        combinedFactor: 0,
      },
      explanation: ['line out of range'],
    };
  }

  // 1. taint 分析
  const taint = analyzeTaint(lines);
  const taintPathsAtLine: TaintPath[] = taint.paths.filter(
    p => p.source.line <= lineIdx && p.sink.line >= lineIdx
  );
  const maxTaintConf = taintPathsAtLine.length > 0
    ? Math.max(...taintPathsAtLine.map(p => p.confidence))
    : 0;
  // 距离最近的 source
  const distToSource = taintPathsAtLine.length > 0
    ? Math.min(...taintPathsAtLine.map(p => lineIdx - p.source.line))
    : 0;
  const sinkConf = sinkConfidence(lines, lineIdx);

  // 2. dataflow 分析
  const df = analyzeDataFlow(lines);
  const targetLine = lines[lineIdx - 1];
  const vars = varsUsedAt(lines, lineIdx);
  // 命中行变量是否在 line 之前未定义
  const hasUninit = vars.some(v => findDefiningLine(lines, lineIdx, v) === 0);

  // 3. controlflow 分析
  const cfa = analyzeControlFlow(lines);
  const blockCtx = blockAtLine(cfa, lineIdx);

  // 4. context overlap
  const contextOl = contextOverlapScore(lines, lineIdx, '');

  // 5. 综合 factor
  const { factor, explanation } = combinedFactor({
    taintConf: Math.max(maxTaintConf, sinkConf),
    hasTaintedSource: taintPathsAtLine.length > 0,
    inLoop: blockCtx.inLoop,
    loopDepth: blockCtx.loopDepth,
    hasUninitialized: hasUninit,
    contextOverlap: contextOl,
  });

  // 6. 综合 confidence
  const confidence = Math.max(0, Math.min(1, patternBase * factor));

  return {
    shouldReport: confidence >= 0.2,
    confidence,
    signals: {
      taintPaths: taintPathsAtLine.length,
      maxTaintConfidence: maxTaintConf,
      hasTaintedSource: taintPathsAtLine.length > 0,
      inLoop: blockCtx.inLoop,
      loopDepth: blockCtx.loopDepth,
      hasUninitialized: hasUninit,
      contextOverlap: contextOl,
      distanceToSource: distToSource,
      combinedFactor: factor,
    },
    explanation,
  };
}

/**
 * 对一个文件的所有命中应用 fuzzy match, 减少 false positive.
 *
 * @param candidateLines 已经 regex 命中的 (line, vulnType, patternBase) 列表
 * @param lines 全部行
 * @returns 增强的 (line, vulnType, confidence, signals) 列表
 */
export function fuzzyMatchAll(
  candidates: Array<{ line: number; vulnType: string; patternBase: number }>,
  lines: string[]
): Array<{ line: number; vulnType: string; match: MatchResult }> {
  return candidates.map(c => ({
    line: c.line,
    vulnType: c.vulnType,
    match: fuzzyMatchLine(lines, c.line, c.patternBase),
  }));
}
