import type {
  ThreatModel, CalibrationResult, RecalibrationAction, STRIDECategory,
} from './types.js';
import { STRIDE_CATEGORIES } from './types.js';
import type { PipelineResult } from '../plugin/types.js';
import type { ThreatAgentResult } from './threat-agent.js';

export interface CalibrationInput {
  threatModel: ThreatModel;
  pipelineResult?: PipelineResult;
  agentResult?: ThreatAgentResult;
}

export function calibrateResults(input: CalibrationInput): CalibrationResult {
  const { threatModel, pipelineResult, agentResult } = input;

  const threatsScanned = new Set<string>();
  const threatFindings = new Map<string, string[]>();

  if (pipelineResult) {
    collectFromPipeline(threatModel, pipelineResult, threatsScanned, threatFindings);
  }

  if (agentResult) {
    collectFromAgent(agentResult, threatsScanned, threatFindings);
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

  const recalibration = computeRecalibration(threatModel, pipelineResult, agentResult, threatsScanned);

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

function collectFromPipeline(
  threatModel: ThreatModel,
  pipelineResult: PipelineResult,
  threatsScanned: Set<string>,
  threatFindings: Map<string, string[]>,
): void {
  for (const detection of pipelineResult.detections) {
    const matching = threatModel.threats.filter(t =>
      t.cwe?.some(cwe => detection.cwe?.includes(cwe)) ||
      t.suggestedDetectionRules.some(rule =>
        detection.probeSources.some(ps => ps.includes(rule.toLowerCase())),
      ),
    );
    for (const threat of matching) {
      threatsScanned.add(threat.id);
      const sources = threatFindings.get(threat.id) ?? [];
      sources.push(detection.source);
      threatFindings.set(threat.id, sources);
    }
  }

  for (const finding of pipelineResult.findings) {
    const matching = threatModel.threats.filter(t =>
      t.cwe?.some(cwe => finding.cwe?.includes(cwe)),
    );
    for (const threat of matching) {
      threatsScanned.add(threat.id);
    }
  }
}

function collectFromAgent(
  agentResult: ThreatAgentResult,
  threatsScanned: Set<string>,
  threatFindings: Map<string, string[]>,
): void {
  for (const finding of agentResult.findings) {
    if (finding.threatId) {
      threatsScanned.add(finding.threatId);
      const sources = threatFindings.get(finding.threatId) ?? [];
      sources.push(`agent:${finding.category}:${finding.severity}`);
      threatFindings.set(finding.threatId, sources);
    }
  }

  for (const threatId of agentResult.threatCoverage) {
    threatsScanned.add(threatId);
  }
}

function computeRecalibration(
  threatModel: ThreatModel,
  pipelineResult: PipelineResult | undefined,
  agentResult: ThreatAgentResult | undefined,
  threatsScanned: Set<string>,
): RecalibrationAction[] {
  const actions: RecalibrationAction[] = [];

  for (const threat of threatModel.threats) {
    if (!threatsScanned.has(threat.id) && threat.priority >= 50) {
      actions.push({
        type: 'increase_priority',
        description: `High-priority threat "${threat.title}" was not scanned`,
        affectedThreatId: threat.id,
        reason: `Priority ${threat.priority} but no matching detections — may need additional probes`,
      });
    }
  }

  const detectionCount = (pipelineResult?.detections.length ?? 0) + (agentResult?.findings.length ?? 0);
  if (detectionCount > threatModel.threats.length * 1.5) {
    actions.push({
      type: 'add_surface',
      description: 'More detections than threats — threat model may be incomplete',
      reason: `${detectionCount} detections vs ${threatModel.threats.length} threats suggests unmodeled attack surfaces`,
    });
  }

  if (agentResult && agentResult.findings.some(f => f.exploitationPossible && f.confidence > 0.8)) {
    actions.push({
      type: 'rescan',
      description: 'High-confidence exploitable finding detected — recommend rescan with expanded scope',
      reason: `Agent found ${agentResult.findings.filter(f => f.exploitationPossible).length} exploitable threats`,
    });
  }

  const agentLowConf = agentResult?.findings.filter(f => f.confidence < 0.3) ?? [];
  if (agentLowConf.length > 0) {
    actions.push({
      type: 'adjust_sensitivity',
      description: `${agentLowConf.length} low-confidence agent findings — consider adjusting detection thresholds`,
      reason: 'Low confidence may indicate false positives or insufficient context for verification',
    });
  }

  return actions;
}
