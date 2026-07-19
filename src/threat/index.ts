export type {
  STRIDECategory,
  TrustLevel,
  BoundaryType,
  TrustZone,
  TrustBoundary,
  EntryPointType,
  DataFlowPath,
  AttackSurface,
  Threat,
  ThreatModelMethod,
  ThreatModel,
  DetectionSchedule,
  RecalibrationAction,
  CalibrationResult,
  ThreatModelPipelineResult,
} from './types.js';

export {
  STRIDE_CATEGORIES,
  STRIDE_LABELS,
} from './types.js';

export { GraphQuery } from './graph-query.js';
export { extractTrustBoundaries } from './trust-boundary.js';
export { generateThreatModel } from './model-generator.js';
export {
  STRIDE_MAPPINGS,
  classifySourceSink,
  getCategoriesForSourceSink,
  computeThreatPriority,
  mapBoundaryType,
  type STRIDEMapping,
} from './stride-mapper.js';
export { ThreatModelPipeline, type ThreatPipelineConfig } from './threat-pipeline.js';
export { ThreatAgent, type ThreatAgentConfig, type ThreatAgentResult, type ThreatAgentFinding } from './threat-agent.js';
export { calibrateResults, type CalibrationInput } from './calibration.js';
