/**
 * CPG (Code Property Graph) — public API.
 * Cosmic-galaxy aligned: shared data substrate for all 23+6 dimension detectors.
 *
 * Spec: §2 (CPG core)
 */

export * from './types.js';
export { CPGBuilder, createCPG } from './builder.js';
export { bfs, dfs, allPaths, downstreamNodes, upstreamNodes } from './queries.js';
export { computePagerank, computeBetweenness, computeDegreeStats, type DegreeStats } from './metrics.js';
export { isSinkFunction, getSinks, type SinkConfig, type SinksByLanguage } from './sinks.js';