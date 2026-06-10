/**
 * Dimension Registry — global catalog of cosmic-galaxy dimension detectors.
 * Spec: §4.2
 *
 * Sprint 8 adds 10 P3 dimensions (chaos, phaseTransition, fieldTheory,
 * fractal, nonEquilibrium, gameTheory, transfer, differentialGeometry,
 * renormalization, categoryBasic), bringing the total to 29 dimensions
 * (23 cosmic-galaxy + 6 math frameworks).
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
import { TypeTheoryDimension } from './type-theory.js';
import { FunctorDimension } from './functor.js';
import { TdaDimension } from './tda.js';
import { PureFunctionalDimension } from './pure-functional.js';
import { AbstractInterpretDimension } from './abstract-interpret.js';
import { SymbolicExecDimension } from './symbolic-exec.js';
import { ChaosDimension } from './chaos.js';
import { PhaseTransitionDimension } from './phase-transition.js';
import { FieldTheoryDimension } from './field-theory.js';
import { FractalDimension } from './fractal.js';
import { NonEquilibriumDimension } from './non-equilibrium.js';
import { GameTheoryDimension } from './game-theory.js';
import { TransferDimension } from './transfer.js';
import { DifferentialGeometryDimension } from './differential-geometry.js';
import { RenormalizationDimension } from './renormalization.js';
import { CategoryBasicDimension } from './category-basic.js';

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
  typeTheory: new TypeTheoryDimension(),
  functor: new FunctorDimension(),
  tda: new TdaDimension(),
  pureFunctional: new PureFunctionalDimension(),
  abstractInterpret: new AbstractInterpretDimension(),
  symbolicExec: new SymbolicExecDimension(),
  chaos: new ChaosDimension(),
  phaseTransition: new PhaseTransitionDimension(),
  fieldTheory: new FieldTheoryDimension(),
  fractal: new FractalDimension(),
  nonEquilibrium: new NonEquilibriumDimension(),
  gameTheory: new GameTheoryDimension(),
  transfer: new TransferDimension(),
  differentialGeometry: new DifferentialGeometryDimension(),
  renormalization: new RenormalizationDimension(),
  categoryBasic: new CategoryBasicDimension(),
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