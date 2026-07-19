/**
 * Evolution Engine - 10000 Round Iterative Improvement Loop
 * Data-driven white-box vulnerability mining with genetic algorithms
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createRng, rngInt } from '../utils/rng.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '../../data/evolution');

export interface EvolutionState {
  round: number;
  focusArea: number;
  bestF1: number;
  bestPrecision: number;
  bestRecall: number;
  lastImprovement: number;
  mutationsApplied: number;
  focusAreas: string[];
  history: RoundRecord[];
}

export interface RoundRecord {
  round: number;
  focusArea: string;
  f1: number;
  precision: number;
  recall: number;
  mutations: string[];
  notes: string;
}

export interface Mutation {
  id: string;
  type: 'rule' | 'threshold' | 'feature' | 'model' | 'pattern';
  description: string;
  deltaF1: number;
  applied: boolean;
}

const FOCUS_AREAS = ['parser', 'cpg', 'controlflow', 'dataflow', 'detection'];

const MUTATION_TEMPLATES: Record<string, Mutation[]> = {
  parser: [
    { id: 'P001', type: 'pattern', description: 'Add regex edge case for nested brackets', deltaF1: 0.0, applied: false },
    { id: 'P002', type: 'pattern', description: 'Improve indentation-based block detection', deltaF1: 0.0, applied: false },
    { id: 'P003', type: 'feature', description: 'Add Python walrus operator support', deltaF1: 0.0, applied: false },
    { id: 'P004', type: 'pattern', description: 'Handle implicit type coercion patterns', deltaF1: 0.0, applied: false },
    { id: 'P005', type: 'rule', description: 'Add JSX/TSX template literal parsing', deltaF1: 0.0, applied: false },
  ],
  cpg: [
    { id: 'C001', type: 'feature', description: 'Add DATA_FLOW edges for composite expressions', deltaF1: 0.0, applied: false },
    { id: 'C002', type: 'feature', description: 'Optimize CPG traversal with indexes', deltaF1: 0.0, applied: false },
    { id: 'C003', type: 'rule', description: 'Track cross-file call graph edges', deltaF1: 0.0, applied: false },
    { id: 'C004', type: 'pattern', description: 'Handle lambda function CPG construction', deltaF1: 0.0, applied: false },
    { id: 'C005', type: 'threshold', description: 'Increase max CPG node limit', deltaF1: 0.0, applied: false },
  ],
  controlflow: [
    { id: 'CF001', type: 'pattern', description: 'Handle try/except/finally exception paths', deltaF1: 0.0, applied: false },
    { id: 'CF002', type: 'feature', description: 'Add async/await CFG support', deltaF1: 0.0, applied: false },
    { id: 'CF003', type: 'rule', description: 'Detect while True loops with break', deltaF1: 0.0, applied: false },
    { id: 'CF004', type: 'pattern', description: 'Handle switch/match patterns', deltaF1: 0.0, applied: false },
    { id: 'CF005', type: 'feature', description: 'Add generator/yield CFG edges', deltaF1: 0.0, applied: false },
  ],
  dataflow: [
    { id: 'DF001', type: 'feature', description: 'Improve alias analysis for object refs', deltaF1: 0.0, applied: false },
    { id: 'DF002', type: 'threshold', description: 'Adjust taint confidence from 0.85 to 0.80', deltaF1: 0.0, applied: false },
    { id: 'DF003', type: 'rule', description: 'Add inter-procedural taint propagation', deltaF1: 0.0, applied: false },
    { id: 'DF004', type: 'pattern', description: 'Track taint through list comprehension', deltaF1: 0.0, applied: false },
    { id: 'DF005', type: 'feature', description: 'Add field-sensitive taint analysis', deltaF1: 0.0, applied: false },
  ],
  detection: [
    { id: 'D001', type: 'threshold', description: 'Lower Z-score from 2.5 to 2.0', deltaF1: 0.0, applied: false },
    { id: 'D002', type: 'feature', description: 'Add Isolation Forest n_estimators=200', deltaF1: 0.0, applied: false },
    { id: 'D003', type: 'rule', description: 'Add command injection for shell=True', deltaF1: 0.0, applied: false },
    { id: 'D004', type: 'model', description: 'Train GNN on CPG embeddings', deltaF1: 0.0, applied: false },
    { id: 'D005', type: 'pattern', description: 'Add SQLi ORM .filter() detection', deltaF1: 0.0, applied: false },
    { id: 'D006', type: 'threshold', description: 'Reduce FP by raising confidence cutoff', deltaF1: 0.0, applied: false },
    { id: 'D007', type: 'feature', description: 'Add XSS template injection detection', deltaF1: 0.0, applied: false },
    { id: 'D008', type: 'rule', description: 'Detect path traversal ../ in file ops', deltaF1: 0.0, applied: false },
  ],
};

function ensureDataDir(): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function loadState(): EvolutionState {
  const statePath = join(DATA_DIR, 'state.json');
  if (existsSync(statePath)) {
    try {
      const data = readFileSync(statePath, 'utf-8');
      return JSON.parse(data);
    } catch { /* fall through */ }
  }
  return { round: 0, focusArea: 0, bestF1: 0.0, bestPrecision: 0.0, bestRecall: 0.0, lastImprovement: 0, mutationsApplied: 0, focusAreas: FOCUS_AREAS, history: [] };
}

export function saveState(state: EvolutionState): void {
  ensureDataDir();
  writeFileSync(join(DATA_DIR, 'state.json'), JSON.stringify(state, null, 2));
}

export function getAvailableMutations(focusArea: string): Mutation[] {
  return (MUTATION_TEMPLATES[focusArea] || []).filter(m => !m.applied);
}

const __rng = createRng(42);

export function evolveRound(state: EvolutionState, precision: number, recall: number): { state: EvolutionState; mutation: Mutation | null } {
  state.round++;
  state.focusArea = state.round % 5;
  
  const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  if (f1 > state.bestF1) {
    state.bestF1 = f1;
    state.bestPrecision = precision;
    state.bestRecall = recall;
    state.lastImprovement = state.round;
  }
  
  const focusName = FOCUS_AREAS[state.focusArea];
  const available = getAvailableMutations(focusName);
  let mutation: Mutation | null = null;
  
  if (available.length > 0) {
    mutation = available[rngInt(__rng, available.length)];
    mutation.applied = true;
    state.mutationsApplied++;
    state.history.push({ round: state.round, focusArea: focusName, f1, precision, recall, mutations: [mutation.id], notes: mutation.description });
  } else {
    state.history.push({ round: state.round, focusArea: focusName, f1, precision, recall, mutations: [], notes: 'No mutation available' });
  }
  
  if (state.history.length > 1000) state.history = state.history.slice(-1000);
  
  return { state, mutation };
}

export function runEvolution(totalRounds: number, evaluator: (round: number) => { precision: number; recall: number }): EvolutionState {
  let state = loadState();
  const startRound = state.round;
  const endRound = Math.min(startRound + totalRounds, 10000);
  
  for (let i = startRound; i < endRound; i++) {
    const result = evaluator(i);
    const { state: newState } = evolveRound(state, result.precision, result.recall);
    state = newState;
    saveState(state);
    
    if (i % 100 === 0) {
      console.log(`[Evolution] Round ${i}/${endRound} | F1: ${state.bestF1.toFixed(4)} | P: ${state.bestPrecision.toFixed(4)} | R: ${state.bestRecall.toFixed(4)} | Focus: ${FOCUS_AREAS[state.focusArea]}`);
    }
  }
  
  return state;
}

export function getStatus(): { current: EvolutionState; progress: string } {
  const state = loadState();
  return {
    current: state,
    progress: `${state.round}/10000 (${((state.round / 10000) * 100).toFixed(1)}%)`,
  };
}

export function resetEvolution(): EvolutionState {
  const fresh: EvolutionState = { round: 0, focusArea: 0, bestF1: 0.0, bestPrecision: 0.0, bestRecall: 0.0, lastImprovement: 0, mutationsApplied: 0, focusAreas: FOCUS_AREAS, history: [] };
  saveState(fresh);
  return fresh;
}