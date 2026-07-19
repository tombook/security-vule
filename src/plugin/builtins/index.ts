export { PatternProbe } from './probe-pattern.js';
export { StatisticalProbe } from './probe-statistical.js';
export { EnsembleDetector } from './detector-ensemble.js';

import type { PluginRegistry } from '../registry.js';
import { PatternProbe } from './probe-pattern.js';
import { StatisticalProbe } from './probe-statistical.js';
import { EnsembleDetector } from './detector-ensemble.js';

export function registerBuiltins(registry: PluginRegistry): void {
  const patternProbe = new PatternProbe();
  registry.register(patternProbe.meta, () => new PatternProbe());

  const statProbe = new StatisticalProbe();
  registry.register(statProbe.meta, () => new StatisticalProbe());

  const ensemble = new EnsembleDetector();
  registry.register(ensemble.meta, () => new EnsembleDetector());
}
