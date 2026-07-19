/**
 * pipeline/run-evolve.ts — v3.2 真实 GA 进化 (替换 schema-only 入口)
 *
 * 数学: 标准遗传算法 (Holland 1975)
 *   个体: GAGeneVector (12 dim)
 *   适应度: 1 - F1 (越小越好)
 *   选择: tournament size 3
 *   交叉: 单点 crossover
 *   变异: 高斯扰动, 10% 概率每基因
 *   精英: 保留 top 10%
 *
 * 闭环: 数学(GA) → 物理(scanner + GT) → 适应度(F1) → 反馈到下一代
 *
 * 用法: bun src/math/pipeline/run-evolve.ts [--rounds N] [--population M] [--corpus DIR] [--gt FILE]
 *
 * 抽象层次: L4 验证闭环
 *
 * @see docs/REDESIGN.md §4.3
 * @see docs/math-underneath.md §8.4
 */

import * as fs from 'fs';
import * as path from 'path';
import { scanProject } from '../application/scanner.js';
import { evaluate, type EvaluationResult } from './run-evaluate.js';
import {
  DEFAULT_GAGENE_VECTOR,
  decodeGAGene,
  applyGAGene,
  type GAGeneVector,
  type GAGeneSpace,
} from '../application/calibration.js';
import type { VulnerabilityReport } from '../application/patterns.js';
import { createRng, rngInt, rngBool, rngUniform, type Rng } from '../../utils/rng.js';

interface GAConfig {
  rounds: number;
  population: number;
  corpusDir: string;
  gtPath: string;
  eliteCount: number;     // 保留 top N
  tournamentSize: number; // 选择压
  mutationRate: number;   // 每基因变异概率
  sigma: number;          // 高斯变异标准差 (相对归一化基因值)
  seed: number;
}

const DEFAULT_CONFIG: GAConfig = {
  rounds: 100,
  population: 12,
  corpusDir: path.resolve(process.cwd(), 'corpus/vuln'),
  gtPath: path.resolve(process.cwd(), 'corpus/ground-truth.json'),
  eliteCount: 2,
  tournamentSize: 3,
  mutationRate: 0.10,
  sigma: 0.15,
  seed: 42,
};

interface Individual {
  genes: GAGeneVector;
  fitness: number;        // 1 - F1 (越小越好)
  f1: number;
  precision: number;
  recall: number;
  tp: number;
  fp: number;
  fn: number;
}

/* ─── GA operators ────────────────────────────────────────────── */

function clampGene(vec: GAGeneVector): GAGeneVector {
  return [
    clamp(vec[0], 0, 100),                                 // min_score
    clamp(Math.round(vec[1]), 0, 2),                       // dedup_strategy
    clamp(vec[2], 0, 2),                                   // w_sqli
    clamp(vec[3], 0, 2),                                   // w_xss
    clamp(vec[4], 0, 2),                                   // w_rce
    clamp(vec[5], 0, 2),                                   // w_path
    clamp(vec[6], 0, 2),                                   // w_auth
    clamp(vec[7], 0, 1),                                   // use_kepler
    clamp(vec[8], 0, 1),                                   // use_entropy
    clamp(vec[9], 0, 1),                                   // use_tda
    clamp(vec[10], 0, 1),                                  // use_chaos
    clamp(vec[11], 0, 1),                                  // use_gravitational
  ] as GAGeneVector;
}

function clamp(x: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, x));
}

function mutate(genes: GAGeneVector, rate: number, sigma: number, rng: Rng): GAGeneVector {
  return genes.map((g, i) => {
    if (rngBool(rng, rate)) {
      if (i >= 7) {
        return g > 0.5 ? 0 : 1;
      }
      return g + (rng() - 0.5) * 2 * sigma;
    }
    return g;
  }) as GAGeneVector;
}

function crossover(a: GAGeneVector, b: GAGeneVector, rng: Rng): GAGeneVector {
  const point = 1 + rngInt(rng, a.length - 1);
  return [
    ...a.slice(0, point),
    ...b.slice(point),
  ] as GAGeneVector;
}

function tournamentSelect(pop: Individual[], size: number, rng: Rng): Individual {
  let best: Individual | null = null;
  for (let i = 0; i < size; i++) {
    const cand = pop[rngInt(rng, pop.length)]!;
    if (best === null || cand.fitness < best.fitness) best = cand;
  }
  return best!;
}

/* ─── Fitness evaluation ──────────────────────────────────────── */

function evaluateIndividual(
  genes: GAGeneVector,
  config: GAConfig,
  rawReports: VulnerabilityReport[],
  groundTruth: { file: string; line: number; type: string }[]
): Individual {
  const space: GAGeneSpace = decodeGAGene(genes);
  const reports = applyGAGene(rawReports, space);
  const result: EvaluationResult = evaluate(reports, groundTruth, { fuzzWindow: 3 });
  return {
    genes,
    fitness: 1 - result.f1,
    f1: result.f1,
    precision: result.precision,
    recall: result.recall,
    tp: result.true_positives,
    fp: result.false_positives,
    fn: result.false_negatives,
  };
}

/* ─── Main GA loop ────────────────────────────────────────────── */

function main() {
  const config = parseArgs(process.argv.slice(2), DEFAULT_CONFIG);
  const rng = createRng(config.seed);

  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  v3.2 真实 GA 进化 (12 维基因, ±3 行 fuzz, 真实 GT)    ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`轮数: ${config.rounds}  种群: ${config.population}  精英: ${config.eliteCount}`);
  console.log(`语料: ${config.corpusDir}`);
  console.log(`GT:   ${config.gtPath}`);
  console.log('');

  // 1. 加载 GT + 原始扫描结果
  const groundTruth = JSON.parse(fs.readFileSync(config.gtPath, 'utf-8'));
  const rawReports = scanProject(config.corpusDir, { minScore: 0, dedupMode: 'none' });
  console.log(`[1] 原始扫描: ${rawReports.length} findings, GT: ${groundTruth.length} 个漏洞`);
  console.log('');

  // 2. 初始化种群: 1 个默认 + 其余随机
  let population: Individual[] = [];
  population.push(evaluateIndividual(DEFAULT_GAGENE_VECTOR, config, rawReports, groundTruth));
  for (let i = 1; i < config.population; i++) {
    const genes = randomGenes(rng);
    population.push(evaluateIndividual(genes, config, rawReports, groundTruth));
  }
  population.sort((a, b) => a.fitness - b.fitness);
  console.log(`[2] 初始化 ${population.length} 个个体:`);
  printPopSummary(population);
  console.log('');

  // 3. 进化循环
  let bestEver = population[0]!;
  let noImproveRounds = 0;
  const history: Array<{ round: number; bestF1: number; meanF1: number; bestP: number; bestR: number }> = [];

  for (let round = 0; round < config.rounds; round++) {
    const newPop: Individual[] = [];

    // 精英保留
    for (let i = 0; i < config.eliteCount; i++) {
      newPop.push(population[i]!);
    }

    // 繁殖
    while (newPop.length < config.population) {
      const a = tournamentSelect(population, config.tournamentSize, rng);
      const b = tournamentSelect(population, config.tournamentSize, rng);
      const childGenes = clampGene(crossover(a.genes, b.genes, rng));
      const mutated = clampGene(mutate(childGenes, config.mutationRate, config.sigma, rng));
      newPop.push(evaluateIndividual(mutated, config, rawReports, groundTruth));
    }

    newPop.sort((a, b) => a.fitness - b.fitness);
    population = newPop;

    const best = population[0]!;
    const meanF1 = population.reduce((s, p) => s + p.f1, 0) / population.length;
    history.push({ round, bestF1: best.f1, meanF1, bestP: best.precision, bestR: best.recall });

    // 进度日志 (每 10 轮 + 最后一轮)
    if (round < 5 || round % 10 === 9 || round === config.rounds - 1) {
      console.log(`[round ${(round + 1).toString().padStart(3)}]  best F1=${(best.f1 * 100).toFixed(1)}%  P=${(best.precision * 100).toFixed(0)}%  R=${(best.recall * 100).toFixed(0)}%  TP=${best.tp}  FP=${best.fp}  FN=${best.fn}  mean=${(meanF1 * 100).toFixed(1)}%`);
    }

    if (best.f1 > bestEver.f1 + 0.001) {
      bestEver = best;
      noImproveRounds = 0;
    } else {
      noImproveRounds++;
      if (noImproveRounds >= 30 && round >= 50) {
        console.log(`\n  早停: ${noImproveRounds} 轮无提升`);
        break;
      }
    }
  }

  // 4. 输出最终结果
  console.log('');
  console.log('════════════════════════════════════════════════════════');
  console.log('  GA 进化完成');
  console.log('════════════════════════════════════════════════════════');
  console.log(`轮数: ${history.length}`);
  console.log(`最佳 F1:        ${(bestEver.f1 * 100).toFixed(2)}%  (P=${(bestEver.precision * 100).toFixed(1)}%, R=${(bestEver.recall * 100).toFixed(1)}%)`);
  console.log(`  TP:           ${bestEver.tp}`);
  console.log(`  FP:           ${bestEver.fp}`);
  console.log(`  FN:           ${bestEver.fn}`);
  console.log(`最佳基因向量:   [${bestEver.genes.map((g) => g.toFixed(2)).join(', ')}]`);
  const bestSpace = decodeGAGene(bestEver.genes);
  console.log(`解码后基因空间:`);
  console.log(`  min_score:    ${bestSpace.min_score}`);
  console.log(`  dedup:        ${bestSpace.dedup_strategy}`);
  console.log(`  rule_weights: sqli=${bestSpace.rule_weights.sqli.toFixed(2)} xss=${bestSpace.rule_weights.xss.toFixed(2)} rce=${bestSpace.rule_weights.rce.toFixed(2)} path=${bestSpace.rule_weights.path.toFixed(2)} auth=${bestSpace.rule_weights.auth.toFixed(2)}`);
  console.log(`  signals:      kepler=${bestSpace.signal_switches.use_kepler} entropy=${bestSpace.signal_switches.use_entropy} tda=${bestSpace.signal_switches.use_tda} chaos=${bestSpace.signal_switches.use_chaos} grav=${bestSpace.signal_switches.use_gravitational}`);
  console.log('');

  // 5. 写结果到 state.json
  const stateDir = path.resolve(process.cwd(), 'data/evolution');
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { recursive: true });
  const statePath = path.join(stateDir, 'ga-state.json');
  fs.writeFileSync(statePath, JSON.stringify({
    timestamp: new Date().toISOString(),
    config,
    bestF1: bestEver.f1,
    bestPrecision: bestEver.precision,
    bestRecall: bestEver.recall,
    bestGenes: bestEver.genes,
    bestGeneSpace: bestSpace,
    history,
  }, null, 2));
  console.log(`State written: ${statePath}`);

  // 6. 与 baseline 对比
  const baseline = evaluateIndividual(DEFAULT_GAGENE_VECTOR, config, rawReports, groundTruth);
  const f1Delta = bestEver.f1 - baseline.f1;
  console.log('');
  console.log('════════════════════════════════════════════════════════');
  console.log('  对比默认基因 vs GA 优化');
  console.log('════════════════════════════════════════════════════════');
  console.log(`  Default:    F1=${(baseline.f1 * 100).toFixed(2)}%  P=${(baseline.precision * 100).toFixed(1)}%  R=${(baseline.recall * 100).toFixed(1)}%  TP=${baseline.tp}  FP=${baseline.fp}  FN=${baseline.fn}`);
  console.log(`  GA best:    F1=${(bestEver.f1 * 100).toFixed(2)}%  P=${(bestEver.precision * 100).toFixed(1)}%  R=${(bestEver.recall * 100).toFixed(1)}%  TP=${bestEver.tp}  FP=${bestEver.fp}  FN=${bestEver.fn}`);
  console.log(`  Delta F1:   ${f1Delta >= 0 ? '+' : ''}${(f1Delta * 100).toFixed(2)}%`);
  console.log('════════════════════════════════════════════════════════');
}

function randomGenes(rng: Rng): GAGeneVector {
  return clampGene([
    rngUniform(rng, 0, 50),
    rngInt(rng, 3),
    rngUniform(rng, 0.5, 2.0),
    rngUniform(rng, 0.5, 2.0),
    rngUniform(rng, 0.5, 2.0),
    rngUniform(rng, 0.5, 2.0),
    rngUniform(rng, 0.5, 2.0),
    rngBool(rng, 0.5) ? 1 : 0,
    rngBool(rng, 0.5) ? 1 : 0,
    rngBool(rng, 0.5) ? 1 : 0,
    rngBool(rng, 0.5) ? 1 : 0,
    rngBool(rng, 0.5) ? 1 : 0,
  ] as GAGeneVector);
}

function printPopSummary(pop: Individual[]) {
  for (const p of pop.slice(0, 6)) {
    console.log(`  F1=${(p.f1 * 100).toFixed(1).padStart(5)}% P=${(p.precision * 100).toFixed(0).padStart(3)}% R=${(p.recall * 100).toFixed(0).padStart(3)}%  genes=[${p.genes.map((g) => g.toFixed(1)).join(',')}]`);
  }
  if (pop.length > 6) console.log(`  ... (${pop.length - 6} more)`);
}

/* ─── Argv parsing ────────────────────────────────────────────── */

function parseArgs(argv: string[], defaults: GAConfig): GAConfig {
  const cfg = { ...defaults };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--rounds' && argv[i + 1]) cfg.rounds = parseInt(argv[++i] ?? '100', 10);
    else if (a === '--population' && argv[i + 1]) cfg.population = parseInt(argv[++i] ?? '12', 10);
    else if (a === '--corpus' && argv[i + 1]) cfg.corpusDir = argv[++i]!;
    else if (a === '--gt' && argv[i + 1]) cfg.gtPath = argv[++i]!;
    else if (a === '--seed' && argv[i + 1]) cfg.seed = parseInt(argv[++i] ?? '42', 10);
  }
  return cfg;
}

if (import.meta.main) {
  main();
}
