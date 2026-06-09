/**
 * Dimension Registry — global catalog of cosmic-galaxy dimension detectors.
 * Spec: §4.2
 *
 * Sprint 4 registers 5 P1 dimensions (perturbation, tidal, relativistic,
 * darkMatter, entropy) and 3 P2 dimensions (quantum, topology, information).
 * Combined with Sprint 3's 4 P0 dimensions and the ast placeholder,
 * the registry has 13 entries (P0+P1+P2) at this point.
 */
import { BaseDimension, type DimensionModule } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';
import { GravityDimension } from './gravity.js';
import { KeplerDimension } from './kepler.js';
import { OrbitalDimension } from './orbital.js';
import { NBodyDimension } from './nbody.js';
import { PerturbationDimension } from './perturbation.js';
import { TidalDimension } from './tidal.js';
import { RelativisticDimension } from './relativistic.js';
import { DarkMatterDimension } from './dark-matter.js';
import { EntropyDimension } from './entropy.js';
import { QuantumDimension } from './quantum.js';
import { TopologyDimension } from './topology.js';
import { InformationDimension } from './information.js';

class AstPlaceholderDim extends BaseDimension {
  readonly name = 'ast';
  readonly weight = 0.15;
  compute(node: CPGNode, _cpg: CPG): number {
    return Math.min(1, (node.features['complexity'] || 0) / 10);
  }
}

export const DIMENSIONS: Record<string, DimensionModule> = {
  ast: new AstPlaceholderDim(),
  gravity: new GravityDimension(),
  kepler: new KeplerDimension(),
  orbital: new OrbitalDimension(),
  nbody: new NBodyDimension(),
  perturbation: new PerturbationDimension(),
  tidal: new TidalDimension(),
  relativistic: new RelativisticDimension(),
  darkMatter: new DarkMatterDimension(),
  entropy: new EntropyDimension(),
  quantum: new QuantumDimension(),
  topology: new TopologyDimension(),
  information: new InformationDimension(),
};

export function registerDimension(dim: DimensionModule): void {
  DIMENSIONS[dim.name] = dim;
}

export function getEnabledDimensions(flags: Record<string, boolean>): DimensionModule[] {
  return Object.values(DIMENSIONS).filter(d => flags[d.name] !== false);
}

export function normalizeWeights(weights: Record<string, number>): Record<string, number> {
  const total = Object.values(weights).reduce((s, w) => s + (w > 0 ? w : 0), 0);
  if (total === 0) return weights;
  const result: Record<string, number> = {};
  for (const [k, w] of Object.entries(weights)) result[k] = w > 0 ? w / total : 0;
  return result;
}