import { describe, test, expect } from 'bun:test';
import { calibrateResults, type CalibrationInput } from '../../../src/threat/calibration.js';
import { STRIDE_CATEGORIES, type ThreatModel, type Threat } from '../../../src/threat/types.js';
import type { Detection, PipelineResult, PluginId, ProbeFinding } from '../../../src/plugin/types.js';
import type { ThreatAgentResult, ThreatAgentFinding } from '../../../src/threat/threat-agent.js';

function makeThreat(over: Partial<Threat> = {}): Threat {
  return {
    id: 't1',
    category: 'injection' as never,
    title: 'Test threat',
    description: 'desc',
    attackSurfaceId: 's1',
    cwe: ['CWE-89'],
    suggestedDetectionRules: ['sql-injection'],
    priority: 50,
    scanned: false,
    findingIds: [],
    ...over,
  };
}

function makeThreatModel(over: Partial<ThreatModel> = {}): ThreatModel {
  const threats = over.threats ?? [
    makeThreat({ id: 't1', category: 'tampering', title: 'SQL injection', cwe: ['CWE-89'], suggestedDetectionRules: ['sql-injection'], priority: 80 }),
    makeThreat({ id: 't2', category: 'information_disclosure', title: 'XSS reflected', cwe: ['CWE-79'], suggestedDetectionRules: ['xss-reflected'], priority: 60 }),
    makeThreat({ id: 't3', category: 'denial_of_service', title: 'ReDoS', cwe: undefined, suggestedDetectionRules: ['redos'], priority: 40 }),
    makeThreat({ id: 't4', category: 'elevation_of_privilege', title: 'Privilege escalation', cwe: ['CWE-269'], suggestedDetectionRules: ['priv-esc'], priority: 90 }),
  ];
  const strideCoverage: Record<string, boolean> = {};
  for (const c of STRIDE_CATEGORIES) strideCoverage[c] = threats.some((t) => t.category === c);
  return {
    id: 'tm-1',
    scope: 'app.py',
    timestamp: 1700000000000,
    method: 'auto_graph',
    trustBoundaries: [],
    attackSurfaces: [],
    threats,
    strideCoverage: strideCoverage as ThreatModel['strideCoverage'],
    riskAssessment: { overall: 50, byCategory: {} as ThreatModel['riskAssessment']['byCategory'], criticalPaths: 0 },
    ...over,
  };
}

function makeDetection(over: Partial<Detection> = {}): Detection {
  return {
    source: 'detector-ensemble' as PluginId,
    probeSources: ['probe-pattern' as PluginId],
    ruleId: 'sql-injection',
    name: 'SQL injection',
    message: 'msg',
    confidence: 0.9,
    severity: 'high',
    cwe: ['CWE-89'],
    scores: {},
    findings: [],
    ...over,
  };
}

function makeProbeFinding(over: Partial<ProbeFinding> = {}): ProbeFinding {
  return {
    source: 'probe-pattern' as PluginId,
    type: 'pattern',
    severity: 'high',
    message: 'msg',
    location: { file: 'app.py', line: 1 },
    metadata: {},
    cwe: ['CWE-89'],
    ...over,
  };
}

function makePipelineResult(over: Partial<PipelineResult> = {}): PipelineResult {
  return {
    findings: [],
    detections: [],
    enhancedDetections: [],
    timing: { probes: 0, detectors: 0, generators: 0, total: 0 },
    errors: [],
    ...over,
  };
}

function makeAgentFinding(over: Partial<ThreatAgentFinding> = {}): ThreatAgentFinding {
  return {
    threatId: 't1',
    category: 'tampering',
    title: 'Agent finding',
    description: 'desc',
    severity: 'high',
    exploitationPossible: false,
    remediation: 'fix',
    confidence: 0.5,
    evidence: 'ev',
    ...over,
  };
}

function makeAgentResult(over: Partial<ThreatAgentResult> = {}): ThreatAgentResult {
  return {
    findings: [],
    threatCoverage: [],
    iterations: 1,
    totalTokens: 0,
    duration: 0,
    ...over,
  };
}

describe('calibration: calibrateResults — happy path', () => {
  test('returns coverage and empty recalibration for empty inputs', () => {
    const tm = makeThreatModel();
    const result = calibrateResults({ threatModel: tm });
    expect(result.threatModelId).toBe('tm-1');
    expect(result.coverage.threatsTotal).toBe(4);
    expect(result.coverage.threatsScanned).toBe(0);
    expect(result.coverage.coveragePercent).toBe(0);
    expect(result.threatFindings.size).toBe(0);
    expect(Array.isArray(result.recalibration)).toBe(true);
  });

  test('matches pipeline detections to threats by CWE and records source', () => {
    const tm = makeThreatModel();
    const det1 = makeDetection({ cwe: ['CWE-89'], ruleId: 'r1', source: 'detector-A' as PluginId, probeSources: ['probe-pattern-r1' as PluginId] });
    const det2 = makeDetection({ cwe: ['CWE-79'], ruleId: 'r2', source: 'detector-B' as PluginId, probeSources: ['probe-pattern-r2' as PluginId] });
    const input: CalibrationInput = {
      threatModel: tm,
      pipelineResult: makePipelineResult({ detections: [det1, det2] }),
    };
    const result = calibrateResults(input);
    expect(result.coverage.threatsScanned).toBe(2);
    expect(result.coverage.coveragePercent).toBe(50);
    expect(result.threatFindings.get('t1')).toContain('detector-A');
    expect(result.threatFindings.get('t2')).toContain('detector-B');
  });

  test('aggregates agent findings into threat findings map and threatCoverage', () => {
    const tm = makeThreatModel();
    const input: CalibrationInput = {
      threatModel: tm,
      agentResult: makeAgentResult({
        findings: [
          makeAgentFinding({ threatId: 't1', category: 'tampering', severity: 'critical', confidence: 0.95 }),
          makeAgentFinding({ threatId: 't1', category: 'tampering', severity: 'high', confidence: 0.7 }),
        ],
        threatCoverage: ['t2', 't3'],
      }),
    };
    const result = calibrateResults(input);
    expect(result.coverage.threatsScanned).toBe(3);
    const t1Sources = result.threatFindings.get('t1') ?? [];
    expect(t1Sources).toHaveLength(2);
    expect(t1Sources[0]).toContain('agent:tampering:critical');
  });
});

describe('calibration: confidence / sensitivity adjustments', () => {
  test('low-confidence agent findings (confidence < 0.3) trigger adjust_sensitivity (likely false positives)', () => {
    const tm = makeThreatModel();
    const input: CalibrationInput = {
      threatModel: tm,
      agentResult: makeAgentResult({
        findings: [
          makeAgentFinding({ threatId: 't2', confidence: 0.1, exploitationPossible: false }),
          makeAgentFinding({ threatId: 't3', confidence: 0.2, exploitationPossible: false }),
        ],
      }),
    };
    const result = calibrateResults(input);
    const adj = result.recalibration.find((a) => a.type === 'adjust_sensitivity');
    expect(adj).toBeDefined();
    expect(adj?.description).toContain('2 low-confidence');
  });

  test('high-confidence exploitable agent finding (confidence > 0.8) triggers rescan action', () => {
    const tm = makeThreatModel();
    const input: CalibrationInput = {
      threatModel: tm,
      agentResult: makeAgentResult({
        findings: [
          makeAgentFinding({ threatId: 't1', confidence: 0.95, exploitationPossible: true }),
        ],
      }),
    };
    const result = calibrateResults(input);
    const rescan = result.recalibration.find((a) => a.type === 'rescan');
    expect(rescan).toBeDefined();
    expect(rescan?.reason).toContain('1 exploitable');
  });

  test('no recalibration action when all agent findings have mid-range confidence (0.3-0.8) and are not exploitable', () => {
    const tm = makeThreatModel();
    const input: CalibrationInput = {
      threatModel: tm,
      agentResult: makeAgentResult({
        findings: [makeAgentFinding({ threatId: 't1', confidence: 0.6, exploitationPossible: false })],
        threatCoverage: ['t1', 't2', 't3', 't4'],
      }),
    };
    const result = calibrateResults(input);
    expect(result.recalibration).toHaveLength(0);
  });
});

describe('calibration: false positive / false negative distinction', () => {
  test('false-negative: high-priority unscanned threat triggers increase_priority', () => {
    const tm = makeThreatModel();
    const input: CalibrationInput = { threatModel: tm };
    const result = calibrateResults(input);
    const inc = result.recalibration.filter((a) => a.type === 'increase_priority');
    const ids = inc.map((a) => a.affectedThreatId);
    expect(ids).toContain('t1');
    expect(ids).toContain('t4');
    expect(ids).not.toContain('t3');
    for (const action of inc) {
      const t = tm.threats.find((x) => x.id === action.affectedThreatId);
      expect(t?.priority).toBeGreaterThanOrEqual(50);
    }
  });

  test('detections far exceeding threat count trigger add_surface (unmodeled surface)', () => {
    const tm = makeThreatModel({ threats: [makeThreat({ id: 'only', priority: 10 })] });
    const manyDetections = Array.from({ length: 5 }, (_, i) =>
      makeDetection({ ruleId: `r${i}`, cwe: undefined, probeSources: [`probe-pattern-${i}` as PluginId] }),
    );
    const input: CalibrationInput = {
      threatModel: tm,
      pipelineResult: makePipelineResult({ detections: manyDetections }),
    };
    const result = calibrateResults(input);
    const addSurface = result.recalibration.find((a) => a.type === 'add_surface');
    expect(addSurface).toBeDefined();
  });

  test('probe findings also tag scanned threats by CWE (additional coverage path)', () => {
    const tm = makeThreatModel();
    const finding = makeProbeFinding({ cwe: ['CWE-269'] });
    const input: CalibrationInput = {
      threatModel: tm,
      pipelineResult: makePipelineResult({ findings: [finding] }),
    };
    const result = calibrateResults(input);
    expect(result.coverage.threatsScanned).toBe(1);
  });

  test('unscanned STRIDE categories are reported in coverage', () => {
    const tm = makeThreatModel();
    delete (tm.strideCoverage as Record<string, boolean>)['repudiation'];
    const result = calibrateResults({ threatModel: tm });
    expect(result.coverage.unscannedCategories).toContain('repudiation');
  });
});
