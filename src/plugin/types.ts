/**
 * Plugin Architecture — Core Types
 * 
 * Inspired by garak's Probe/Detector/Generator three-layer decoupling.
 * 
 * Layers:
 *   Probe     — Code analysis that produces raw findings (AST, pattern, CFG, taint, etc.)
 *   Detector  — Consumes findings and classifies/verifies vulnerabilities
 *   Generator — Produces test inputs or LLM-enhanced analysis (LLM providers)
 * 
 * All layers implement a common Plugin interface with lifecycle hooks.
 */

/** Unique plugin identifier: namespace.name (e.g. "probe.pattern-sqli") */
export type PluginId = string;

/** Plugin execution phase */
export type PluginPhase = 'probe' | 'detector' | 'generator';

/** Plugin lifecycle states */
export type PluginState = 'uninitialized' | 'ready' | 'running' | 'error' | 'disabled';

/** Severity levels matching existing detection system */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** A single finding produced by a probe */
export interface ProbeFinding {
  /** Source plugin that produced this finding */
  source: PluginId;
  /** Rule ID (e.g. INJ-001) */
  ruleId: string;
  /** Human-readable name */
  name: string;
  /** Finding description */
  message: string;
  /** Confidence score 0-1 */
  confidence: number;
  /** Severity level */
  severity: Severity;
  /** File path if applicable */
  filePath?: string;
  /** Line number (1-based) */
  line?: number;
  /** Column number (0-based) */
  column?: number;
  /** Code snippet */
  codeSnippet?: string;
  /** CWE identifiers */
  cwe?: string[];
  /** Extra metadata */
  metadata: Record<string, unknown>;
}

/** A verified vulnerability produced by a detector */
export interface Detection {
  /** Source detector */
  source: PluginId;
  /** Probes that contributed */
  probeSources: PluginId[];
  /** Rule ID */
  ruleId: string;
  /** Vulnerability name */
  name: string;
  /** Description */
  message: string;
  /** Overall confidence 0-1 */
  confidence: number;
  /** Severity */
  severity: Severity;
  /** Location */
  location?: {
    file: string;
    line?: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
  };
  /** CWE */
  cwe?: string[];
  /** Method scores */
  scores: Record<string, number>;
  /** All contributing findings */
  findings: ProbeFinding[];
}

/** Context passed to probes during execution */
export interface ProbeContext {
  /** Source code to analyze */
  code: string;
  /** Programming language hint */
  language?: string;
  /** File path */
  filePath?: string;
  /** Plugin configuration */
  config: Record<string, unknown>;
  /** Shared data store for inter-probe communication */
  sharedData: Map<string, unknown>;
}

/** Context passed to detectors */
export interface DetectorContext {
  /** Findings from probes */
  findings: ProbeFinding[];
  /** Source code */
  code: string;
  /** Plugin configuration */
  config: Record<string, unknown>;
}

/** Context passed to generators */
export interface GeneratorContext {
  /** Current detections to enhance */
  detections: Detection[];
  /** Source code */
  code: string;
  /** Plugin configuration */
  config: Record<string, unknown>;
}

/** Plugin metadata */
export interface PluginMeta {
  /** Unique plugin ID */
  id: PluginId;
  /** Phase */
  phase: PluginPhase;
  /** Display name */
  name: string;
  /** Description */
  description: string;
  /** Version */
  version: string;
  /** Supported languages (empty = all) */
  languages: string[];
  /** Configuration schema (JSON Schema subset) */
  configSchema?: Record<string, unknown>;
  /** Default configuration */
  defaultConfig: Record<string, unknown>;
  /** Dependencies on other plugins */
  depends?: PluginId[];
  /** Tags for filtering */
  tags: string[];
}

/** Core plugin interface */
export interface Plugin {
  /** Plugin metadata */
  readonly meta: PluginMeta;
  /** Current state */
  state: PluginState;
  /** Initialize the plugin */
  init(config?: Record<string, unknown>): Promise<void>;
  /** Tear down the plugin */
  destroy(): Promise<void>;
}

/** Probe plugin — produces findings from code analysis */
export interface ProbePlugin extends Plugin {
  /** Execute the probe */
  execute(context: ProbeContext): Promise<ProbeFinding[]>;
}

/** Detector plugin — classifies/verifies probe findings */
export interface DetectorPlugin extends Plugin {
  /** Execute the detector */
  execute(context: DetectorContext): Promise<Detection[]>;
}

/** Generator plugin — enhances detections with LLM or other means */
export interface GeneratorPlugin extends Plugin {
  /** Execute the generator */
  execute(context: GeneratorContext): Promise<Detection[]>;
}

/** Plugin factory function */
export type PluginFactory = () => Plugin;

/** Plugin registry entry */
export interface RegistryEntry {
  meta: PluginMeta;
  factory: PluginFactory;
}

/** Pipeline execution result */
export interface PipelineResult {
  /** All findings from probes */
  findings: ProbeFinding[];
  /** All detections from detectors */
  detections: Detection[];
  /** Enhanced detections from generators */
  enhancedDetections: Detection[];
  /** Execution time per phase in ms */
  timing: {
    probes: number;
    detectors: number;
    generators: number;
    total: number;
  };
  /** Errors encountered */
  errors: Array<{ plugin: PluginId; error: string }>;
}
