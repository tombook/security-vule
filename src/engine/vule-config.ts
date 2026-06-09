/**
 * VuleConfig — runtime configuration for VuleEngine.
 * Spec: §7.1 YAML configuration
 */
import yaml from 'js-yaml';
import { readFileSync, existsSync } from 'fs';

export interface UVRSWeightsConfig {
  taint: number; ast: number; llm: number; consensus: number;
  verify: number; chain: number; darkMatter: number;
  evolution: number; quantum: number; entropy: number;
}

export interface RiskThresholdsConfig {
  LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number;
}

export interface VuleConfig {
  weights: UVRSWeightsConfig;
  thresholds: RiskThresholdsConfig;
  dimensions: { enabled: string[] };
  llm: { provider: string; model: string; maxFindings: number; verify: boolean; consensusMode: 'failover' | 'consensus' };
  cache: { enabled: boolean; size: number; persistPath: string };
  report: { format: 'json' | 'html' | 'markdown'; savePath: string; topK: number; includeVisualization: boolean };
}

export function defaultConfig(): VuleConfig {
  return {
    weights: {
      taint: 0.20, ast: 0.15, llm: 0.10, consensus: 0.10, verify: 0.10,
      chain: 0.10, darkMatter: 0.08, evolution: 0.05, quantum: 0.07, entropy: 0.05,
    },
    thresholds: { LOW: 0.25, MEDIUM: 0.50, HIGH: 0.75, CRITICAL: 0.85 },
    dimensions: { enabled: ['ast'] },
    llm: { provider: 'minimax', model: 'MiniMax-M3', maxFindings: 5, verify: false, consensusMode: 'failover' },
    cache: { enabled: true, size: 1000, persistPath: '.vule-cache/' },
    report: { format: 'json', savePath: 'cosmic_report', topK: 20, includeVisualization: false },
  };
}

export function loadConfig(source: string | object, defaults: VuleConfig = defaultConfig()): VuleConfig {
  let parsed: any;
  if (typeof source === 'string') {
    if (existsSync(source)) parsed = yaml.load(readFileSync(source, 'utf-8'));
    else parsed = yaml.load(source);
  } else {
    parsed = source;
  }
  return {
    weights: { ...defaults.weights, ...(parsed?.uvrs?.weights || parsed?.weights || {}) },
    thresholds: { ...defaults.thresholds, ...(parsed?.uvrs?.thresholds || parsed?.thresholds || {}) },
    dimensions: { enabled: parsed?.dimensions?.enabled || defaults.dimensions.enabled },
    llm: { ...defaults.llm, ...(parsed?.llm || {}) },
    cache: { ...defaults.cache, ...(parsed?.cache || {}) },
    report: { ...defaults.report, ...(parsed?.report || {}) },
  };
}