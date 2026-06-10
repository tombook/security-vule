/**
 * 统一漏洞风险评分 (Unified Vulnerability Risk Score)
 *
 * S_VULE(v) = σ(Σᵢ wᵢ · Rᵢ(v))
 * σ(x) = 1/(1 + e^(-x))
 *
 * 设计哲学对齐 cosmic-galaxy 的 UVRS 引擎
 * 详见 docs/design-philosophy.md
 */

export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface UVRSWeights {
  taint: number;
  ast: number;
  llm: number;
  consensus: number;
  verify: number;
  chain: number;
  darkMatter: number;
  evolution: number;
  quantum: number;
  entropy: number;
}

export interface UVRSComponents {
  taint?: number;
  ast?: number;
  llm?: number;
  consensus?: number;
  verify?: number;
  chain?: number;
  darkMatter?: number;
  evolution?: number;
  quantum?: number;
  entropy?: number;
}

export interface UVRSResult {
  score: number;
  level: RiskLevel;
  dominantDimension: { name: string; contribution: number };
  contributions: Record<string, number>;
}

const DEFAULT_WEIGHTS: UVRSWeights = {
  taint: 0.2,
  ast: 0.15,
  llm: 0.1,
  consensus: 0.1,
  verify: 0.1,
  chain: 0.1,
  darkMatter: 0.08,
  evolution: 0.05,
  quantum: 0.07,
  entropy: 0.05,
};

const RISK_THRESHOLDS: Record<RiskLevel, number> = {
  [RiskLevel.LOW]: 0.25,
  [RiskLevel.MEDIUM]: 0.5,
  [RiskLevel.HIGH]: 0.75,
  [RiskLevel.CRITICAL]: 0.85,
};

const DIMENSION_DEFAULTS: UVRSComponents = {
  taint: 0.2,
  ast: 0.3,
  llm: 0.2,
  consensus: 0.15,
  verify: 0.15,
  chain: 0.1,
  darkMatter: 0.1,
  evolution: 0.1,
  quantum: 0.1,
  entropy: 0.2,
};

export class UVRS {
  private weights: UVRSWeights;
  private thresholds: Record<RiskLevel, number>;

  constructor(weights?: Partial<UVRSWeights>, thresholds?: Partial<Record<RiskLevel, number>>) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
    if (thresholds) {
      this.thresholds = { ...RISK_THRESHOLDS };
      for (const [k, v] of Object.entries(thresholds)) {
        if (v !== undefined) {
          this.thresholds[k as RiskLevel] = v;
        }
      }
    } else {
      this.thresholds = { ...RISK_THRESHOLDS };
    }
    this.validateWeights();
  }

  private validateWeights(): void {
    const total = Object.values(this.weights).reduce((s, w) => s + (w > 0 ? w : 0), 0);
    if (Math.abs(total - 1.0) > 0.01 && total > 0) {
      for (const k of Object.keys(this.weights) as (keyof UVRSWeights)[]) {
        if (this.weights[k] > 0) this.weights[k] /= total;
      }
    }
  }

  compute(components: UVRSComponents): UVRSResult {
    let weightedSum = 0;
    const contributions: Record<string, number> = {};

    for (const [dim, weight] of Object.entries(this.weights) as [keyof UVRSWeights, number][]) {
      if (weight > 0) {
        const value = components[dim] ?? DIMENSION_DEFAULTS[dim] ?? 0;
        weightedSum += weight * value;
        contributions[dim] = weight * value;
      }
    }

    const score = this.sigmoid(weightedSum);
    const level = this.classify(score);
    const dominant = this.dominantDimension(contributions);

    return { score, level, dominantDimension: dominant, contributions };
  }

  private sigmoid(x: number): number {
    if (x > 50) return 1.0;
    if (x < -50) return 0.0;
    return 1.0 / (1.0 + Math.exp(-x));
  }

  classify(score: number): RiskLevel {
    const order: RiskLevel[] = [
      RiskLevel.CRITICAL,
      RiskLevel.HIGH,
      RiskLevel.MEDIUM,
      RiskLevel.LOW,
    ];
    for (const level of order) {
      if (score >= this.thresholds[level]) return level;
    }
    return RiskLevel.LOW;
  }

  private dominantDimension(contributions: Record<string, number>): {
    name: string;
    contribution: number;
  } {
    const entries = Object.entries(contributions);
    if (entries.length === 0) return { name: 'unknown', contribution: 0 };
    const [name, contrib] = entries.reduce((max, curr) => (curr[1] > max[1] ? curr : max));
    const total = Object.values(contributions).reduce((s, v) => s + v, 0);
    return { name, contribution: total > 0 ? contrib / total : 0 };
  }

  getRiskDistribution(scores: number[]): Record<RiskLevel, number> {
    const dist = {
      [RiskLevel.LOW]: 0,
      [RiskLevel.MEDIUM]: 0,
      [RiskLevel.HIGH]: 0,
      [RiskLevel.CRITICAL]: 0,
    };
    for (const s of scores) dist[this.classify(s)]++;
    return dist;
  }

  exportConfig(): { weights: UVRSWeights; thresholds: Record<RiskLevel, number> } {
    return { weights: { ...this.weights }, thresholds: { ...this.thresholds } };
  }

  static fromConfig(config: {
    weights?: UVRSWeights;
    thresholds?: Record<RiskLevel, number>;
  }): UVRS {
    return new UVRS(config.weights, config.thresholds);
  }
}
