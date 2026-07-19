/**
 * Combiner - Ensemble combining all detection methods with confidence scoring
 * Weighted ensemble with vulnerability score aggregator
 */

// Detection result types
export interface DetectionResult {
  ruleId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  location?: string;
  message?: string;
}

export interface CombinedDetection {
  ruleId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  scores: {
    pattern: number;
    statistical: number;
    ml: number;
  };
  combinedScore: number;
  confidence: number;
  methods: string[];
  location?: string;
  message?: string;
}

// Severity weights for scoring
const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
  info: 0.1
};

// Default method weights
export interface MethodWeights {
  pattern: number;
  statistical: number;
  ml: number;
}

export const DEFAULT_WEIGHTS: MethodWeights = {
  pattern: 0.3,
  statistical: 0.3,
  ml: 0.4
};

// Aggregated vulnerability score
export interface VulnerabilityScore {
  overall: number;
  pattern: number;
  statistical: number;
  ml: number;
  severityBreakdown: Record<string, number>;
  confidence: number;
  detections: CombinedDetection[];
}

// Combine pattern and statistical detections
export function combinePatternStatistical(
  patternResults: DetectionResult[],
  statisticalResults: DetectionResult[]
): CombinedDetection[] {
  const combined: CombinedDetection[] = [];
  const seen = new Map<string, CombinedDetection>();
  
  // Add pattern results
  for (const r of patternResults) {
    seen.set(r.ruleId, {
      ruleId: r.ruleId,
      name: r.name,
      severity: r.severity,
      scores: { pattern: r.confidence, statistical: 0, ml: 0 },
      combinedScore: r.confidence * DEFAULT_WEIGHTS.pattern,
      confidence: r.confidence,
      methods: ['pattern'],
      location: r.location,
      message: r.message
    });
  }
  
  // Add or merge statistical results
  for (const r of statisticalResults) {
    const existing = seen.get(r.ruleId);
    if (existing) {
      existing.scores.statistical = r.confidence;
      existing.methods.push('statistical');
      existing.confidence = Math.max(existing.confidence, r.confidence);
    } else {
      seen.set(r.ruleId, {
        ruleId: r.ruleId,
        name: r.name,
        severity: r.severity,
        scores: { pattern: 0, statistical: r.confidence, ml: 0 },
        combinedScore: r.confidence * DEFAULT_WEIGHTS.statistical,
        confidence: r.confidence,
        methods: ['statistical'],
        location: r.location,
        message: r.message
      });
    }
  }
  
  return Array.from(seen.values());
}

// Add ML results to combined detections
export function addMLResults(
  combined: CombinedDetection[],
  mlResults: Array<{ ruleId: string; confidence: number }>
): CombinedDetection[] {
  const seen = new Map<string, CombinedDetection>();
  
  for (const c of combined) {
    seen.set(c.ruleId, c);
  }
  
  for (const r of mlResults) {
    const existing = seen.get(r.ruleId);
    if (existing) {
      existing.scores.ml = r.confidence;
      existing.methods.push('ml');
      existing.confidence = Math.max(existing.confidence, r.confidence);
    } else {
      seen.set(r.ruleId, {
        ruleId: r.ruleId,
        name: 'ML-detected',
        severity: 'high',
        scores: { pattern: 0, statistical: 0, ml: r.confidence },
        combinedScore: r.confidence * DEFAULT_WEIGHTS.ml,
        confidence: r.confidence,
        methods: ['ml']
      });
    }
  }
  
  return Array.from(seen.values());
}

// Recalculate combined scores with weights
export function recalculateScores(
  detections: CombinedDetection[],
  weights: MethodWeights = DEFAULT_WEIGHTS
): CombinedDetection[] {
  const totalWeight = weights.pattern + weights.statistical + weights.ml;
  const patternW = weights.pattern / totalWeight;
  const statisticalW = weights.statistical / totalWeight;
  const mlW = weights.ml / totalWeight;
  
  return detections.map(d => ({
    ...d,
    combinedScore: d.scores.pattern * patternW +
      d.scores.statistical * statisticalW +
      d.scores.ml * mlW,
    confidence: (d.scores.pattern + d.scores.statistical + d.scores.ml) / 3
  }));
}

// Aggregate vulnerability scores
export function aggregateScores(
  detections: CombinedDetection[],
  weights: MethodWeights = DEFAULT_WEIGHTS
): VulnerabilityScore {
  const patternDetections = detections.filter(d => d.scores.pattern > 0);
  const statisticalDetections = detections.filter(d => d.scores.statistical > 0);
  const mlDetections = detections.filter(d => d.scores.ml > 0);
  
  const patternAvg = patternDetections.length > 0
    ? patternDetections.reduce((s, d) => s + d.scores.pattern, 0) / patternDetections.length
    : 0;
  
  const statisticalAvg = statisticalDetections.length > 0
    ? statisticalDetections.reduce((s, d) => s + d.scores.statistical, 0) / statisticalDetections.length
    : 0;
  
  const mlAvg = mlDetections.length > 0
    ? mlDetections.reduce((s, d) => s + d.scores.ml, 0) / mlDetections.length
    : 0;
  
  const severityBreakdown: Record<string, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0
  };
  
  for (const d of detections) {
    severityBreakdown[d.severity]++;
  }
  
  const totalWeight = weights.pattern + weights.statistical + weights.ml;
  const patternW = weights.pattern / totalWeight;
  const statisticalW = weights.statistical / totalWeight;
  const mlW = weights.ml / totalWeight;
  
  return {
    overall: patternAvg * patternW + statisticalAvg * statisticalW + mlAvg * mlW,
    pattern: patternAvg,
    statistical: statisticalAvg,
    ml: mlAvg,
    severityBreakdown,
    confidence: detections.length > 0
      ? detections.reduce((s, d) => s + d.confidence, 0) / detections.length
      : 0,
    detections
  };
}

// Rank detections by combined score
export function rankDetections(
  detections: CombinedDetection[],
  limit?: number
): CombinedDetection[] {
  const sorted = [...detections].sort((a, b) => b.combinedScore - a.combinedScore);
  return limit ? sorted.slice(0, limit) : sorted;
}

// Filter by severity threshold
export function filterBySeverity(
  detections: CombinedDetection[],
  minSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info'
): CombinedDetection[] {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const minIdx = severityOrder.indexOf(minSeverity);
  
  return detections.filter(d => severityOrder.indexOf(d.severity) <= minIdx);
}

// Merge results from multiple sources
export function mergeDetections(
  allResults: Map<string, DetectionResult[]>
): CombinedDetection[] {
  const combined = new Map<string, CombinedDetection>();
  
  for (const [source, results] of allResults.entries()) {
    for (const r of results) {
      const key = `${r.ruleId}-${source}`;
      combined.set(key, {
        ruleId: r.ruleId,
        name: r.name,
        severity: r.severity,
        scores: { pattern: 0, statistical: 0, ml: 0 },
        combinedScore: r.confidence,
        confidence: r.confidence,
        methods: [source],
        location: r.location,
        message: r.message
      });
    }
  }
  
  return Array.from(combined.values());
}

// Finalize combined detection with confidence
export function finalizeDetection(
  detection: CombinedDetection,
  weights: MethodWeights = DEFAULT_WEIGHTS
): CombinedDetection {
  const totalWeight = weights.pattern + weights.statistical + weights.ml;
  const patternW = weights.pattern / totalWeight;
  const statisticalW = weights.statistical / totalWeight;
  const mlW = weights.ml / totalWeight;
  
  const combinedScore = detection.scores.pattern * patternW +
    detection.scores.statistical * statisticalW +
    detection.scores.ml * mlW;
  
  const avgConfidence = (detection.scores.pattern +
    detection.scores.statistical +
    detection.scores.ml) / 3;
  
  return {
    ...detection,
    combinedScore,
    confidence: avgConfidence
  };
}

// Get top detections by method
export function getTopByMethod(
  detections: CombinedDetection[],
  method: 'pattern' | 'statistical' | 'ml',
  limit: number = 10
): CombinedDetection[] {
  return detections
    .filter(d => d.scores[method] > 0)
    .sort((a, b) => b.scores[method] - a.scores[method])
    .slice(0, limit);
}

// Summary report
export function summaryReport(score: VulnerabilityScore): string {
  const lines = [
    '=== Vulnerability Detection Summary ===',
    `Overall Score: ${(score.overall * 100).toFixed(1)}%`,
    `Confidence: ${(score.confidence * 100).toFixed(1)}%`,
    '',
    'By Method:',
    `  Pattern:  ${(score.pattern * 100).toFixed(1)}%`,
    `  Statistical: ${(score.statistical * 100).toFixed(1)}%`,
    `  ML: ${(score.ml * 100).toFixed(1)}%`,
    '',
    'By Severity:',
    ...Object.entries(score.severityBreakdown).map(([sev, count]) =>
      `  ${sev}: ${count}`
    ),
    '',
    `Total Detections: ${score.detections.length}`
  ];
  
  return lines.join('\n');
}