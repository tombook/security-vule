/**
 * VuleConfig — runtime configuration for VuleEngine.
 * Spec: §7.1 YAML configuration
 */
import yaml from 'js-yaml';
import { readFileSync, existsSync } from 'fs';

export interface UVRSWeightsConfig {
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

export interface RiskThresholdsConfig {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
  CRITICAL: number;
}

export interface VuleConfig {
  weights: UVRSWeightsConfig;
  thresholds: RiskThresholdsConfig;
  dimensions: { enabled: string[] };
  llm: {
    provider: string;
    model: string;
    maxFindings: number;
    verify: boolean;
    consensusMode: 'failover' | 'consensus';
  };
  cache: { enabled: boolean; size: number; persistPath: string };
  report: {
    format: 'json' | 'html' | 'markdown';
    savePath: string;
    topK: number;
    includeVisualization: boolean;
  };
}

export function defaultConfig(): VuleConfig {
  return {
    weights: {
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
    },
    thresholds: { LOW: 0.25, MEDIUM: 0.5, HIGH: 0.75, CRITICAL: 0.85 },
    dimensions: { enabled: ['ast'] },
    llm: {
      provider: 'minimax',
      model: 'MiniMax-M3',
      maxFindings: 5,
      verify: false,
      consensusMode: 'failover',
    },
    cache: { enabled: true, size: 1000, persistPath: '.vule-cache/' },
    report: { format: 'json', savePath: 'cosmic_report', topK: 20, includeVisualization: false },
  };
}

export function loadConfig(
  source: string | object,
  defaults: VuleConfig = defaultConfig()
): VuleConfig {
  let parsed: unknown;
  if (typeof source === 'string') {
    if (existsSync(source)) parsed = yaml.load(readFileSync(source, 'utf-8'));
    else parsed = yaml.load(source);
  } else {
    parsed = source;
  }
  const p = parsed as {
    uvrs?: { weights?: Partial<UVRSWeightsConfig>; thresholds?: Partial<RiskThresholdsConfig> };
    weights?: Partial<UVRSWeightsConfig>;
    thresholds?: Partial<RiskThresholdsConfig>;
    dimensions?: { enabled?: string[] };
    llm?: Partial<VuleConfig['llm']>;
    cache?: Partial<VuleConfig['cache']>;
    report?: Partial<VuleConfig['report']>;
  };
  return {
    weights: { ...defaults.weights, ...(p.uvrs?.weights || p.weights || {}) },
    thresholds: { ...defaults.thresholds, ...(p.uvrs?.thresholds || p.thresholds || {}) },
    dimensions: { enabled: p.dimensions?.enabled || defaults.dimensions.enabled },
    llm: { ...defaults.llm, ...(p.llm || {}) },
    cache: { ...defaults.cache, ...(p.cache || {}) },
    report: { ...defaults.report, ...(p.report || {}) },
  };
}
