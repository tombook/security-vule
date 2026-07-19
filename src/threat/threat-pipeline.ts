import type { ProgramGraph } from '../engine/program-graph.js';
import type { TaintResult } from '../engine/taint.js';
import type { ParseResult } from '../engine/parser.js';
import type {
  ThreatModel, DetectionSchedule, CalibrationResult,
  ThreatModelPipelineResult, DataFlowPath, STRIDECategory,
} from './types.js';
import { STRIDE_CATEGORIES } from './types.js';
import { generateThreatModel } from './model-generator.js';
import { buildProgramGraph } from '../engine/program-graph.js';
import { buildCFG } from '../engine/cfg.js';
import { analyzeTaint } from '../engine/taint.js';
import { parse, type Language } from '../engine/parser.js';
import type { PipelineResult, PluginId } from '../plugin/types.js';
import { PluginPipeline } from '../plugin/pipeline.js';
import { PluginRegistry } from '../plugin/registry.js';

export interface ThreatPipelineConfig {
  language?: string;
  minConfidence?: number;
  probeIds?: PluginId[];
  detectorIds?: PluginId[];
  generatorIds?: PluginId[];
  skipThreatModel?: boolean;
}

const DEFAULT_THREAT_CONFIG: ThreatPipelineConfig = {
  minConfidence: 0.3,
};

export class ThreatModelPipeline {
  private registry: PluginRegistry;
  private pluginPipeline: PluginPipeline;

  constructor(registry: PluginRegistry) {
    this.registry = registry;
    this.pluginPipeline = new PluginPipeline(registry);
  }

  async run(
    code: string,
    filePath: string,
    userConfig?: Partial<ThreatPipelineConfig>,
  ): Promise<ThreatModelPipelineResult> {
    const config = { ...DEFAULT_THREAT_CONFIG, ...userConfig };
    const totalStart = Date.now();

    const lang: Language = (config.language as Language) || detectLang(filePath);

    // Phase 0: Build program graph + taint analysis
    const tmStart = Date.now();
    const { graph, taintResult, parsed } = this.buildGraphAndTaint(code, lang);
    let threatModel: ThreatModel;

    if (config.skipThreatModel) {
      threatModel = this.emptyThreatModel(filePath, graph);
    } else {
      threatModel = generateThreatModel(graph, taintResult, filePath);
    }
    const threatModelMs = Date.now() - tmStart;

    // Phase 1: Schedule detections from threat model
    const schedStart = Date.now();
    const schedule = this.scheduleDetections(threatModel);
    const schedulingMs = Date.now() - schedStart;

    // Phase 2: Run plugin pipeline with threat model in shared data
    const detectStart = Date.now();
    const pipelineResult = await this.runDetectionPipeline(
      code, filePath, lang, threatModel, schedule, config,
    );
    const detectionMs = Date.now() - detectStart;

    // Phase 3: Calibrate results
    const calibStart = Date.now();
    const calibration = this.calibrate(threatModel, pipelineResult);
    const calibrationMs = Date.now() - calibStart;

    return {
      threatModel,
      schedule,
      pipelineResult,
      calibration,
      timing: {
        threatModelMs,
        schedulingMs,
        detectionMs,
        calibrationMs,
        totalMs: Date.now() - totalStart,
      },
    };
  }

  private buildGraphAndTaint(
    code: string,
    lang: Language,
  ): { graph: ProgramGraph; taintResult: TaintResult; parsed: ParseResult } {
    const parsed = parse(code, lang);
    const cfg = buildCFG(parsed.ast);
    const graph = buildProgramGraph(parsed.ast, cfg ?? undefined, code);
    const taintResult = analyzeTaint(code, 'global');
    return { graph, taintResult, parsed };
  }

  private scheduleDetections(threatModel: ThreatModel): DetectionSchedule[] {
    const schedules: DetectionSchedule[] = [];
    const seen = new Set<string>();

    for (const threat of threatModel.threats) {
      if (threat.scanned) continue;
      if (threat.priority < 20) continue;

      const dedupKey = `${threat.category}:${threat.suggestedDetectionRules.sort().join(',')}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const surface = threatModel.attackSurfaces.find(
        s => s.id === threat.attackSurfaceId,
      );

      schedules.push({
        threatId: threat.id,
        ruleIds: threat.suggestedDetectionRules,
        priority: threat.priority,
        context: {
          entryPoint: surface?.entryPoint,
          trustBoundary: threat.trustBoundaryId,
          dataFlowPaths: surface?.dataFlowPaths ?? [],
        },
      });
    }

    return schedules.sort((a, b) => b.priority - a.priority);
  }

  private async runDetectionPipeline(
    code: string,
    filePath: string,
    language: string | undefined,
    threatModel: ThreatModel,
    schedule: DetectionSchedule[],
    config: ThreatPipelineConfig,
  ): Promise<PipelineResult> {
    const probeConfig: Record<string, Record<string, unknown>> = {};
    for (const s of schedule) {
      for (const ruleId of s.ruleIds) {
        probeConfig[ruleId] = {
          threatId: s.threatId,
          priority: s.priority,
          entryPoint: s.context.entryPoint,
          trustBoundary: s.context.trustBoundary,
        };
      }
    }

    const result = await this.pluginPipeline.run(code, filePath, {
      language,
      probeIds: config.probeIds,
      detectorIds: config.detectorIds,
      generatorIds: config.generatorIds,
      minConfidence: config.minConfidence,
      probeConfig,
    });

    return result;
  }

  private calibrate(threatModel: ThreatModel, pipelineResult: PipelineResult): CalibrationResult {
    const threatsScanned = new Set<string>();
    const threatFindings = new Map<string, string[]>();

    for (const detection of pipelineResult.detections) {
      const matchingThreats = threatModel.threats.filter(t =>
        t.cwe?.some(cwe => detection.cwe?.includes(cwe)) ||
        t.suggestedDetectionRules.some(rule =>
          detection.probeSources.some(ps => ps.includes(rule.toLowerCase())),
        ),
      );

      for (const threat of matchingThreats) {
        threatsScanned.add(threat.id);
        const existing = threatFindings.get(threat.id) ?? [];
        existing.push(detection.source);
        threatFindings.set(threat.id, existing);
      }
    }

    for (const finding of pipelineResult.findings) {
      const matchingThreats = threatModel.threats.filter(t =>
        t.cwe?.some(cwe => finding.cwe?.includes(cwe)),
      );
      for (const threat of matchingThreats) {
        threatsScanned.add(threat.id);
      }
    }

    const scannedCount = threatsScanned.size;
    const totalCount = threatModel.threats.length;
    const coveragePercent = totalCount > 0
      ? Math.round((scannedCount / totalCount) * 100)
      : 0;

    const coveredCategories = new Set<STRIDECategory>();
    for (const threatId of threatsScanned) {
      const threat = threatModel.threats.find(t => t.id === threatId);
      if (threat) coveredCategories.add(threat.category);
    }
    const unscannedCategories = STRIDE_CATEGORIES.filter(
      c => !threatModel.strideCoverage[c] || !coveredCategories.has(c),
    );

    const recalibration = this.computeRecalibration(
      threatModel, pipelineResult, threatsScanned,
    );

    return {
      threatModelId: threatModel.id,
      coverage: {
        threatsScanned: scannedCount,
        threatsTotal: totalCount,
        coveragePercent,
        unscannedCategories,
      },
      threatFindings,
      recalibration,
    };
  }

  private computeRecalibration(
    threatModel: ThreatModel,
    pipelineResult: PipelineResult,
    threatsScanned: Set<string>,
  ): import('./types.js').RecalibrationAction[] {
    const actions: import('./types.js').RecalibrationAction[] = [];

    for (const threat of threatModel.threats) {
      if (!threatsScanned.has(threat.id) && threat.priority >= 50) {
        actions.push({
          type: 'increase_priority',
          description: `High-priority threat "${threat.title}" was not scanned`,
          affectedThreatId: threat.id,
          reason: `Threat priority ${threat.priority} but no matching detections found — may need additional probes`,
        });
      }
    }

    if (pipelineResult.detections.length > threatModel.threats.length * 1.5) {
      actions.push({
        type: 'add_surface',
        description: 'More detections than threats — threat model may be incomplete',
        reason: `${pipelineResult.detections.length} detections vs ${threatModel.threats.length} threats suggests unmodeled attack surfaces`,
      });
    }

    return actions;
  }

  private emptyThreatModel(filePath: string, graph: ProgramGraph): ThreatModel {
    return {
      id: `tm_empty_${Date.now()}`,
      scope: filePath,
      timestamp: Date.now(),
      method: 'auto_graph',
      trustBoundaries: [],
      attackSurfaces: [],
      threats: [],
      strideCoverage: {
        spoofing: false,
        tampering: false,
        repudiation: false,
        information_disclosure: false,
        denial_of_service: false,
        elevation_of_privilege: false,
      },
      riskAssessment: {
        overall: 0,
        byCategory: {
          spoofing: 0, tampering: 0, repudiation: 0,
          information_disclosure: 0, denial_of_service: 0, elevation_of_privilege: 0,
        },
        criticalPaths: 0,
      },
      graphStats: {
        nodeCount: graph.nodeCount,
        edgeCount: graph.edgeCount,
        boundaryCount: 0,
        surfaceCount: 0,
        threatCount: 0,
      },
    };
  }
}

function detectLang(filePath: string): Language {
  const ext = filePath.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'py': return 'python';
    case 'js': case 'jsx': case 'ts': case 'tsx': case 'mjs': case 'cjs': return 'javascript';
    case 'java': return 'java';
    case 'c': case 'h': case 'cpp': case 'hpp': return 'c';
    case 'go': return 'go';
    default: return 'javascript';
  }
}
