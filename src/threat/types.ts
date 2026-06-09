/**
 * Threat Model Type System — Core types for threat-modeling-driven detection
 *
 * Defines the data structures for automated threat modeling:
 *   TrustBoundary  — security zone boundaries derived from taint analysis
 *   AttackSurface  — entry points + reachable dangerous operations
 *   Threat         — STRIDE-classified threat with CWE/OWASP mapping
 *   ThreatModel    — complete model combining boundaries, surfaces, threats
 */

// ─── STRIDE Categories ────────────────────────────────────────────────

/** STRIDE threat classification categories */
export type STRIDECategory =
  | 'spoofing'              // 身份欺骗
  | 'tampering'             // 数据篡改
  | 'repudiation'           // 否认
  | 'information_disclosure' // 信息泄露
  | 'denial_of_service'     // 拒绝服务
  | 'elevation_of_privilege'; // 权限提升

/** All STRIDE categories for iteration */
export const STRIDE_CATEGORIES: STRIDECategory[] = [
  'spoofing',
  'tampering',
  'repudiation',
  'information_disclosure',
  'denial_of_service',
  'elevation_of_privilege',
];

/** STRIDE category display names */
export const STRIDE_LABELS: Record<STRIDECategory, string> = {
  spoofing: 'Spoofing (身份欺骗)',
  tampering: 'Tampering (数据篡改)',
  repudiation: 'Repudiation (否认)',
  information_disclosure: 'Information Disclosure (信息泄露)',
  denial_of_service: 'Denial of Service (拒绝服务)',
  elevation_of_privilege: 'Elevation of Privilege (权限提升)',
};

// ─── Trust Zones & Boundaries ─────────────────────────────────────────

/** Security zone classification */
export type TrustLevel = 'trusted' | 'untrusted' | 'semi_trusted';

/** Boundary crossing type */
export type BoundaryType = 'input' | 'output' | 'data_store' | 'process' | 'network';

/** A security zone containing program graph nodes */
export interface TrustZone {
  id: string;
  name: string;
  level: TrustLevel;
  /** PGNode IDs in this zone */
  nodes: string[];
  /** Scope identifier (function name, module, etc.) */
  scope: string;
}

/** A trust boundary between two security zones */
export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  /** Inside (higher trust) zone */
  inside: TrustZone;
  /** Outside (lower trust) zone */
  outside: TrustZone;
  /** Boundary crossing type */
  type: BoundaryType;
  /** Associated taint path IDs (from TaintPath.path) */
  taintPaths: string[];
  /** Source location */
  location: {
    file: string;
    line?: number;
  };
  /** Confidence of boundary detection (0-1) */
  confidence: number;
}

// ─── Attack Surfaces ──────────────────────────────────────────────────

/** Entry point types for attack surface identification */
export type EntryPointType =
  | 'http_handler'
  | 'cli_handler'
  | 'api_endpoint'
  | 'file_input'
  | 'db_query'
  | 'event_handler'
  | 'function_export';

/** A data flow path through the program graph */
export interface DataFlowPath {
  id: string;
  /** Source PGNode ID */
  source: string;
  /** Sink PGNode ID */
  sink: string;
  /** Intermediate PGNode IDs in order */
  intermediaries: string[];
  /** Sanitizer PGNode IDs */
  sanitizers: string[];
  /** Whether this path crosses a trust boundary */
  crossBoundary: boolean;
  /** Confidence score (0-1) */
  confidence: number;
}

/** An attack surface: entry point + reachable dangerous operations */
export interface AttackSurface {
  id: string;
  name: string;
  description: string;
  /** Entry point PGNode ID */
  entryPoint: string;
  /** Entry point type */
  entryType: EntryPointType;
  /** Reachable dangerous sink PGNode IDs */
  reachableSinks: string[];
  /** Trust boundary IDs crossed from this entry point */
  boundariesCrossed: string[];
  /** Data flow paths from this entry point */
  dataFlowPaths: DataFlowPath[];
  /** Computed risk score (0-100) */
  riskScore: number;
  /** Location in source */
  location: {
    file: string;
    line?: number;
  };
}

// ─── Threats ──────────────────────────────────────────────────────────

/** A STRIDE-classified threat */
export interface Threat {
  id: string;
  /** STRIDE category */
  category: STRIDECategory;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** Associated attack surface ID */
  attackSurfaceId: string;
  /** Associated trust boundary ID (if applicable) */
  trustBoundaryId?: string;
  /** CWE IDs */
  cwe?: string[];
  /** OWASP category */
  owasp?: string;
  /** Suggested detection rule IDs from the existing pattern system */
  suggestedDetectionRules: string[];
  /** Scanning priority (0-100, higher = scan first) */
  priority: number;
  /** Whether this threat has been scanned */
  scanned: boolean;
  /** Detection IDs from scanning (filled in Phase 3) */
  findingIds: string[];
}

// ─── Threat Model ─────────────────────────────────────────────────────

/** How the threat model was generated */
export type ThreatModelMethod = 'auto_graph' | 'auto_llm' | 'manual' | 'hybrid';

/** Complete threat model for a codebase/file */
export interface ThreatModel {
  id: string;
  /** File or scope this model covers */
  scope: string;
  /** Timestamp of generation */
  timestamp: number;
  /** Generation method */
  method: ThreatModelMethod;
  /** Trust boundaries identified */
  trustBoundaries: TrustBoundary[];
  /** Attack surfaces identified */
  attackSurfaces: AttackSurface[];
  /** STRIDE-classified threats */
  threats: Threat[];
  /** Coverage: which STRIDE categories have at least one threat */
  strideCoverage: Record<STRIDECategory, boolean>;
  /** Overall risk assessment */
  riskAssessment: {
    overall: number;
    byCategory: Record<STRIDECategory, number>;
    criticalPaths: number;
  };
  /** Graph statistics */
  graphStats?: {
    nodeCount: number;
    edgeCount: number;
    boundaryCount: number;
    surfaceCount: number;
    threatCount: number;
  };
}

// ─── Detection Scheduling (Phase 1 → Phase 2) ────────────────────────

/** Instruction for scheduling a detection pass */
export interface DetectionSchedule {
  /** Threat to scan */
  threatId: string;
  /** Detection rule IDs to apply */
  ruleIds: string[];
  /** Priority (higher = earlier) */
  priority: number;
  /** Context passed to detectors */
  context: {
    entryPoint?: string;
    trustBoundary?: string;
    dataFlowPaths: DataFlowPath[];
  };
}

// ─── Calibration (Phase 3) ────────────────────────────────────────────

/** Feedback action for threat model recalibration */
export interface RecalibrationAction {
  type: 'add_threat' | 'increase_priority' | 'add_surface' | 'expand_boundary' | 'rescan' | 'adjust_sensitivity';
  description: string;
  affectedThreatId?: string;
  reason: string;
}

/** Calibration result: findings mapped back to threats */
export interface CalibrationResult {
  /** Threat model ID */
  threatModelId: string;
  /** Coverage report */
  coverage: {
    threatsScanned: number;
    threatsTotal: number;
    coveragePercent: number;
    unscannedCategories: STRIDECategory[];
  };
  /** Findings mapped to threats */
  threatFindings: Map<string, string[]>;
  /** Recommended recalibration actions */
  recalibration: RecalibrationAction[];
}

// ─── Pipeline Result ──────────────────────────────────────────────────

/** Complete threat-modeling pipeline result */
export interface ThreatModelPipelineResult {
  /** Generated threat model */
  threatModel: ThreatModel;
  /** Detection schedule */
  schedule: DetectionSchedule[];
  /** Plugin pipeline result (existing) */
  pipelineResult: import('../plugin/types.js').PipelineResult;
  /** Calibration results */
  calibration: CalibrationResult;
  /** Total pipeline timing */
  timing: {
    threatModelMs: number;
    schedulingMs: number;
    detectionMs: number;
    calibrationMs: number;
    totalMs: number;
  };
}
