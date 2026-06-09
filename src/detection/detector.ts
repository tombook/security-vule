/**
 * Main Detector - Orchestrates all detection methods
 */
import { detectPattern, ALL_RULES, type PatternMatch } from './patterns.js';
import { detectStatisticalAnomaly, computeAnomalyScore, type CodeComplexityFeatures, type AnomalyResult } from './statistical.js';
import { computeGraphEmbedding, computeTokenEmbedding, type FeatureVector } from './ml-classifier.js';
import { aggregateScores, filterBySeverity, type CombinedDetection, type VulnerabilityScore, type MethodWeights } from './combiner.js';

// Detector configuration
export interface DetectorConfig {
  weights: MethodWeights;
  minConfidence: number;
  minSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enablePattern: boolean;
  enableStatistical: boolean;
  enableML: boolean;
}

export const DEFAULT_CONFIG: DetectorConfig = {
  weights: { pattern: 0.3, statistical: 0.3, ml: 0.4 },
  minConfidence: 0.3,
  minSeverity: 'low',
  enablePattern: true,
  enableStatistical: true,
  enableML: true
};

// Detection context
export interface DetectionContext {
  code: string;
  language?: string;
  filePath?: string;
  cpg?: Map<string, string[]>;
  features?: FeatureVector;
}

interface DetectionResult {
  ruleId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  message: string;
  location?: string;
}

// Main detector class
export class Detector {
  private config: DetectorConfig;
  
  constructor(config: Partial<DetectorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }
  
  // Detect all vulnerability types
  detect(context: DetectionContext): VulnerabilityScore {
    const detections: CombinedDetection[] = [];
    
    if (this.config.enablePattern) {
      const patternResults = this.detectPatterns(context);
      for (const r of patternResults) {
        detections.push({
          ruleId: r.ruleId,
          name: r.name,
          severity: r.severity,
          scores: { pattern: r.confidence, statistical: 0, ml: 0 },
          combinedScore: r.confidence * this.config.weights.pattern,
          confidence: r.confidence,
          methods: ['pattern'],
          location: r.location,
          message: r.message
        });
      }
    }
    
    if (this.config.enableStatistical) {
      const statResults = this.detectStatistical(context);
      for (const r of statResults) {
        detections.push({
          ruleId: r.ruleId,
          name: r.name,
          severity: r.severity,
          scores: { pattern: 0, statistical: r.confidence, ml: 0 },
          combinedScore: r.confidence * this.config.weights.statistical,
          confidence: r.confidence,
          methods: ['statistical'],
          location: r.location,
          message: r.message
        });
      }
    }
    
    if (this.config.enableML) {
      const mlResults = this.detectML(context);
      for (const r of mlResults) {
        detections.push({
          ruleId: r.ruleId,
          name: r.name,
          severity: r.severity,
          scores: { pattern: 0, statistical: 0, ml: r.confidence },
          combinedScore: r.confidence * this.config.weights.ml,
          confidence: r.confidence,
          methods: ['ml'],
          location: r.location,
          message: r.message
        });
      }
    }
    
    const filtered = filterBySeverity(detections, this.config.minSeverity)
      .filter(d => d.confidence >= this.config.minConfidence);
    
    return aggregateScores(filtered, this.config.weights);
  }
  
  // Pattern-based detection
  private detectPatterns(context: DetectionContext): DetectionResult[] {
    const results: DetectionResult[] = [];
    const matches = detectPattern(context.code, context.filePath);
    
    for (const match of matches) {
      results.push({
        ruleId: match.rule_id,
        name: match.name,
        severity: match.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
        confidence: match.confidence,
        message: `Pattern-based: ${match.name}`,
        location: match.location ? `${context.filePath || ''}:${match.location.line}` : undefined
      });
    }
    
    return results;
  }
  
  // Statistical anomaly detection
  private detectStatistical(context: DetectionContext): DetectionResult[] {
    const results: DetectionResult[] = [];
    
    if (!context.features) return results;
    
    const features: CodeComplexityFeatures = {
      cyclomatic: context.features[0] || 0,
      cognitive: context.features[1] || 0,
      halstead: context.features[2] || 0,
      linesOfCode: context.features[3] || 0,
      parameterCount: context.features[5] || 0,
      nestingDepth: context.features[7] || 0,
    };
    
    // Detect anomalies using statistical methods
    const anomalies = detectStatisticalAnomaly([[
      features.cyclomatic, features.cognitive, features.linesOfCode,
      features.halstead, features.parameterCount, features.nestingDepth
    ]], 2.5);
    
    for (const anomaly of anomalies) {
      results.push({
        ruleId: 'STAT-001',
        name: 'Statistical Anomaly',
        severity: 'medium',
        confidence: Math.min(anomaly.score, 1),
        message: `Statistical anomaly detected with score ${anomaly.score.toFixed(3)}`
      });
    }
    
    return results;
  }
  
  // ML-based detection
  private detectML(context: DetectionContext): DetectionResult[] {
    const results: DetectionResult[] = [];
    
    if (!context.features || context.features.length === 0) return results;
    
    // Simple feature deviation-based detection
    const featureMean = context.features.reduce((a, b) => a + b, 0) / context.features.length;
    const featureStd = Math.sqrt(
      context.features.reduce((s, v) => s + (v - featureMean) ** 2, 0) / context.features.length
    );
    
    if (featureStd > 2.0) {
      results.push({
        ruleId: 'ML-001',
        name: 'ML-Detected Anomaly',
        severity: 'high',
        confidence: Math.min(featureStd / 5, 1),
        message: 'High feature deviation detected by ML'
      });
    }
    
    return results;
  }
}

// Convenience functions
export function detect(code: string, config?: Partial<DetectorConfig>): VulnerabilityScore {
  return new Detector(config).detect({ code });
}

export function detectWithFeatures(code: string, features: FeatureVector, config?: Partial<DetectorConfig>): VulnerabilityScore {
  return new Detector(config).detect({ code, features });
}