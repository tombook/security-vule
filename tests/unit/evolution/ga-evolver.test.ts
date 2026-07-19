import { describe, expect, test } from 'bun:test';
import { runGA, DEFAULT_GA_CONFIG } from '../../../src/evolution/ga-evolver.js';
import type { CosmXParams } from '../../../src/evolution/cosm-x-evolver.js';

const SEED: CosmXParams = {
  semiMajorAxisWeight: 1.0, eccentricityWeight: 1.0, inclinationWeight: 0.5,
  gravityConstant: 1.0, perturbationScale: 0.01,
  zscoreThreshold: 2.0, mahalanobisThreshold: 3.0,
  transferTimeWeight: 1.0, transferAngleWeight: 0.5,
  forceThreshold: 10.0, convergenceRadius: 5.0,
  anomalyWeight: 0.4, perturbationWeight: 0.3, gravityWeight: 0.3,
};

function simpleFitness(params: CosmXParams) {
  const score = 1 - Math.abs(params.zscoreThreshold - 2.5) / 10
    - Math.abs(params.gravityConstant - 1.2) / 10
    - Math.abs(params.anomalyWeight - 0.35) / 10;
  const clamped = Math.max(0, Math.min(1, score));
  return { f1: clamped, precision: clamped * 0.9, recall: clamped * 0.85 };
}

describe('GA Evolver', () => {
  test('runs to completion with correct result shape', () => {
    const config = { ...DEFAULT_GA_CONFIG, populationSize: 10, maxGenerations: 5, eliteCount: 2, tournamentSize: 3 };
    const result = runGA(SEED, simpleFitness, config);

    expect(result.bestIndividual).toBeDefined();
    expect(result.bestIndividual.fitness > 0).toBe(true);
    expect(result.bestIndividual.params).toBeDefined();
    expect(result.population.length).toBe(config.populationSize);
    expect(result.generation).toBe(config.maxGenerations);
    expect(result.totalEvaluations > 0).toBe(true);
    expect(result.history.length).toBe(config.maxGenerations);
  });

  test('history tracks best fitness', () => {
    const config = { ...DEFAULT_GA_CONFIG, populationSize: 10, maxGenerations: 10, eliteCount: 2, tournamentSize: 3 };
    const result = runGA(SEED, simpleFitness, config);
    for (const entry of result.history) {
      expect(entry.bestFitness >= 0).toBe(true);
      expect(entry.avgFitness >= 0).toBe(true);
      expect(entry.diversity >= 0).toBe(true);
    }
  });

  test('calls onGeneration callback', () => {
    const generations: number[] = [];
    const config = { ...DEFAULT_GA_CONFIG, populationSize: 10, maxGenerations: 20, eliteCount: 2, tournamentSize: 3 };
    runGA(SEED, simpleFitness, config, (gen) => { generations.push(gen); });
    expect(generations.length > 0).toBe(true);
    expect(generations.includes(1)).toBe(true);
    expect(generations.includes(10)).toBe(true);
  });

  test('elite individuals have highest fitness', () => {
    const config = { ...DEFAULT_GA_CONFIG, populationSize: 10, maxGenerations: 3, eliteCount: 2, tournamentSize: 3 };
    const result = runGA(SEED, simpleFitness, config);
    const sorted = [...result.population].sort((a, b) => b.fitness - a.fitness);
    expect(sorted[0].fitness >= sorted[sorted.length - 1].fitness).toBe(true);
  });

  test('each individual has valid params', () => {
    const config = { ...DEFAULT_GA_CONFIG, populationSize: 10, maxGenerations: 3, eliteCount: 2, tournamentSize: 3 };
    const result = runGA(SEED, simpleFitness, config);
    for (const ind of result.population) {
      expect(ind.params.zscoreThreshold > 0).toBe(true);
      expect(ind.params.gravityConstant > 0).toBe(true);
      expect(ind.params.anomalyWeight > 0).toBe(true);
    }
  });
});
