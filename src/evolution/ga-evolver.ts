import type { CosmXParams } from './cosm-x-evolver.js';
import { createRng, rngInt, rngBool, rngUniform, type Rng } from '../utils/rng.js';

export interface GAIndividual {
  id: string;
  params: CosmXParams;
  fitness: number;
  precision: number;
  recall: number;
  generation: number;
  parentIds: string[];
}

export interface GAConfig {
  populationSize: number;
  eliteCount: number;
  tournamentSize: number;
  crossoverRate: number;
  mutationRate: number;
  mutationStrength: number;
  maxGenerations: number;
  stagnationLimit: number;
}

export interface GAResult {
  bestIndividual: GAIndividual;
  population: GAIndividual[];
  generation: number;
  totalEvaluations: number;
  history: Array<{ generation: number; bestFitness: number; avgFitness: number; diversity: number }>;
}

export const DEFAULT_GA_CONFIG: GAConfig = {
  populationSize: 50,
  eliteCount: 5,
  tournamentSize: 5,
  crossoverRate: 0.8,
  mutationRate: 0.3,
  mutationStrength: 0.15,
  maxGenerations: 200,
  stagnationLimit: 30,
};

type FitnessFn = (params: CosmXParams) => { f1: number; precision: number; recall: number };

const PARAM_KEYS: (keyof CosmXParams)[] = [
  'semiMajorAxisWeight', 'eccentricityWeight', 'inclinationWeight',
  'gravityConstant', 'perturbationScale',
  'zscoreThreshold', 'mahalanobisThreshold',
  'transferTimeWeight', 'transferAngleWeight',
  'forceThreshold', 'convergenceRadius',
  'anomalyWeight', 'perturbationWeight', 'gravityWeight',
];

function randomParams(base: CosmXParams, strength: number, rng: Rng): CosmXParams {
  const result = { ...base };
  for (const key of PARAM_KEYS) {
    const val = base[key];
    const delta = (rng() - 0.5) * 2 * strength * val;
    result[key] = Math.max(0.001, val + delta);
  }
  return result;
}

function crossover(parentA: GAIndividual, parentB: GAIndividual, config: GAConfig, rng: Rng): CosmXParams {
  const child: CosmXParams = { ...parentA.params };

  if (rngBool(rng, config.crossoverRate)) {
    const crossPoint = rngInt(rng, PARAM_KEYS.length);
    for (let i = crossPoint; i < PARAM_KEYS.length; i++) {
      child[PARAM_KEYS[i]] = parentB.params[PARAM_KEYS[i]];
    }
  } else {
    for (const key of PARAM_KEYS) {
      child[key] = rngBool(rng, 0.5) ? parentA.params[key] : parentB.params[key];
    }
  }

  return child;
}

function mutate(params: CosmXParams, config: GAConfig, rng: Rng): CosmXParams {
  const mutated = { ...params };
  const numMutations = rngInt(rng, 3) + 1;

  for (let i = 0; i < numMutations; i++) {
    if (rngBool(rng, config.mutationRate)) {
      const key = PARAM_KEYS[rngInt(rng, PARAM_KEYS.length)];
      const val = mutated[key];
      const delta = (rng() - 0.5) * 2 * config.mutationStrength * val;
      mutated[key] = Math.max(0.001, val + delta);
    }
  }

  return mutated;
}

function tournamentSelect(population: GAIndividual[], tournamentSize: number, rng: Rng): GAIndividual {
  let best: GAIndividual | null = null;
  for (let i = 0; i < tournamentSize; i++) {
    const candidate = population[rngInt(rng, population.length)];
    if (!best || candidate.fitness > best.fitness) {
      best = candidate;
    }
  }
  return best;
}

function computeDiversity(population: GAIndividual[]): number {
  if (population.length < 2) return 0;
  let totalDist = 0;
  let count = 0;
  const sampleSize = Math.min(population.length, 20);

  for (let i = 0; i < sampleSize; i++) {
    for (let j = i + 1; j < sampleSize; j++) {
      let dist = 0;
      for (const key of PARAM_KEYS) {
        const diff = population[i].params[key] - population[j].params[key];
        dist += diff * diff;
      }
      totalDist += Math.sqrt(dist);
      count++;
    }
  }
  return count > 0 ? totalDist / count : 0;
}

export function runGA(
  seedParams: CosmXParams,
  fitnessFn: FitnessFn,
  config: GAConfig = DEFAULT_GA_CONFIG,
  onGeneration?: (gen: number, best: GAIndividual, diversity: number) => void,
  seed: number = 42,
): GAResult {
  const rng = createRng(seed);
  let idCounter = 0;
  const makeId = () => `ind_${++idCounter}`;

  const population: GAIndividual[] = [];
  for (let i = 0; i < config.populationSize; i++) {
    const params = i === 0 ? { ...seedParams } : randomParams(seedParams, 0.5, rng);
    const fitness = fitnessFn(params);
    population.push({
      id: makeId(),
      params,
      fitness: fitness.f1,
      precision: fitness.precision,
      recall: fitness.recall,
      generation: 0,
      parentIds: [],
    });
  }

  const history: GAResult['history'] = [];
  let stagnationCount = 0;
  let prevBestFitness = 0;
  let totalEvaluations = config.populationSize;

  for (let gen = 1; gen <= config.maxGenerations; gen++) {
    population.sort((a, b) => b.fitness - a.fitness);
    const currentBest = population[0].fitness;

    if (currentBest <= prevBestFitness + 1e-6) {
      stagnationCount++;
    } else {
      stagnationCount = 0;
      prevBestFitness = currentBest;
    }

    if (stagnationCount >= config.stagnationLimit) {
      const injectCount = Math.floor(config.populationSize * 0.3);
      for (let i = config.eliteCount; i < config.eliteCount + injectCount && i < population.length; i++) {
        const params = randomParams(population[0].params, 0.8, rng);
        const fitness = fitnessFn(params);
        population[i] = {
          id: makeId(),
          params,
          fitness: fitness.f1,
          precision: fitness.precision,
          recall: fitness.recall,
          generation: gen,
          parentIds: [],
        };
        totalEvaluations++;
      }
      stagnationCount = 0;
    }

    const diversity = computeDiversity(population);
    history.push({ generation: gen, bestFitness: currentBest, avgFitness: population.reduce((s, p) => s + p.fitness, 0) / population.length, diversity });

    if (onGeneration && (gen % 10 === 0 || gen === 1)) {
      onGeneration(gen, population[0], diversity);
    }

    const nextGen: GAIndividual[] = [];
    for (let i = 0; i < config.eliteCount && i < population.length; i++) {
      nextGen.push({ ...population[i], generation: gen });
    }

    while (nextGen.length < config.populationSize) {
      const parentA = tournamentSelect(population, config.tournamentSize, rng);
      const parentB = tournamentSelect(population, config.tournamentSize, rng);
      let childParams = crossover(parentA, parentB, config, rng);
      childParams = mutate(childParams, config, rng);
      const fitness = fitnessFn(childParams);
      totalEvaluations++;

      nextGen.push({
        id: makeId(),
        params: childParams,
        fitness: fitness.f1,
        precision: fitness.precision,
        recall: fitness.recall,
        generation: gen,
        parentIds: [parentA.id, parentB.id],
      });
    }

    population.length = 0;
    population.push(...nextGen);
  }

  population.sort((a, b) => b.fitness - a.fitness);

  return {
    bestIndividual: population[0],
    population,
    generation: config.maxGenerations,
    totalEvaluations,
    history,
  };
}
