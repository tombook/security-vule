/**
 * Benchmark Framework — Evaluates detection accuracy against labeled datasets
 *
 * Metrics: Precision, Recall, F1, FPR, FNR, Accuracy
 * Inspired by LineVul/Devign evaluation methodology from DL-VD-Empirical-Study.
 */

export interface BenchmarkSample {
  id: string;
  code: string;
  language: string;
  isVulnerable: boolean;
  cwe?: string[];
  filePath?: string;
  vulnerableLines?: number[];
}

export interface DetectionOutput {
  sampleId: string;
  detected: boolean;
  confidence: number;
  ruleIds: string[];
  cwe?: string[];
  lineLocation?: { startLine: number; endLine: number };
}

export interface BenchmarkResult {
  dataset: string;
  totalSamples: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  fnr: number;
  accuracy: number;
  perCwe?: Record<string, { precision: number; recall: number; f1: number; count: number }>;
  timing: { totalMs: number; avgMsPerSample: number };
}

export interface BenchmarkConfig {
  minConfidence: number;
  groupByCwe: boolean;
}

export function computeMetrics(tp: number, fp: number, fn: number, tn: number): Omit<BenchmarkResult, 'dataset' | 'totalSamples' | 'perCwe' | 'timing'> {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const fnr = fn + tp > 0 ? fn / (fn + tp) : 0;
  const accuracy = tp + fp + fn + tn > 0 ? (tp + tn) / (tp + fp + fn + tn) : 0;

  return { tp, fp, fn, tn, precision, recall, f1, fpr, fnr, accuracy };
}

export function evaluate(
  samples: BenchmarkSample[],
  detections: DetectionOutput[],
  config?: Partial<BenchmarkConfig>,
): BenchmarkResult {
  const minConf = config?.minConfidence ?? 0.5;
  const startTime = Date.now();

  const detMap = new Map<string, DetectionOutput>();
  for (const d of detections) detMap.set(d.sampleId, d);

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const cweStats = new Map<string, { tp: number; fp: number; fn: number; count: number }>();

  for (const sample of samples) {
    const det = detMap.get(sample.id);
    const predicted = det ? det.detected && det.confidence >= minConf : false;

    if (sample.isVulnerable && predicted) tp++;
    else if (sample.isVulnerable && !predicted) fn++;
    else if (!sample.isVulnerable && predicted) fp++;
    else tn++;

    if (config?.groupByCwe && sample.cwe) {
      for (const cwe of sample.cwe) {
        const stats = cweStats.get(cwe) ?? { tp: 0, fp: 0, fn: 0, count: 0 };
        stats.count++;
        if (sample.isVulnerable && predicted) stats.tp++;
        else if (sample.isVulnerable && !predicted) stats.fn++;
        else if (!sample.isVulnerable && predicted) stats.fp++;
        cweStats.set(cwe, stats);
      }
    }
  }

  const metrics = computeMetrics(tp, fp, fn, tn);
  const totalTime = Date.now() - startTime;

  let perCwe: BenchmarkResult['perCwe'] = undefined;
  if (config?.groupByCwe) {
    perCwe = {};
    for (const [cwe, stats] of cweStats) {
      const cweMetrics = computeMetrics(stats.tp, stats.fp, stats.fn, 0);
      perCwe[cwe] = { ...cweMetrics, count: stats.count };
    }
  }

  return {
    dataset: 'custom',
    totalSamples: samples.length,
    ...metrics,
    perCwe,
    timing: { totalMs: totalTime, avgMsPerSample: samples.length > 0 ? totalTime / samples.length : 0 },
  };
}

export function formatReport(result: BenchmarkResult): string {
  const lines = [
    `=== Benchmark Report: ${result.dataset} ===`,
    `Samples: ${result.totalSamples}`,
    `TP=${result.tp} FP=${result.fp} FN=${result.fn} TN=${result.tn}`,
    `Precision:  ${(result.precision * 100).toFixed(1)}%`,
    `Recall:     ${(result.recall * 100).toFixed(1)}%`,
    `F1:         ${(result.f1 * 100).toFixed(1)}%`,
    `FPR:        ${(result.fpr * 100).toFixed(1)}%`,
    `FNR:        ${(result.fnr * 100).toFixed(1)}%`,
    `Accuracy:   ${(result.accuracy * 100).toFixed(1)}%`,
    `Time: ${result.timing.totalMs}ms (${result.timing.avgMsPerSample.toFixed(1)}ms/sample)`,
  ];

  if (result.perCwe) {
    lines.push('', 'Per-CWE Breakdown:');
    for (const [cwe, stats] of Object.entries(result.perCwe)) {
      lines.push(`  ${cwe}: P=${(stats.precision * 100).toFixed(1)}% R=${(stats.recall * 100).toFixed(1)}% F1=${(stats.f1 * 100).toFixed(1)}% (n=${stats.count})`);
    }
  }

  return lines.join('\n');
}
