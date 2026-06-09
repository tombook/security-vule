import type { ProgramGraph } from '../engine/program-graph.js';
import type { TaintResult, TaintSource, TaintSink } from '../engine/taint.js';
import type {
  ThreatModel, TrustBoundary, AttackSurface, Threat, DataFlowPath,
  STRIDECategory, EntryPointType,
} from './types.js';
import { STRIDE_CATEGORIES } from './types.js';
import { GraphQuery } from './graph-query.js';
import { extractTrustBoundaries } from './trust-boundary.js';
import {
  classifySourceSink, computeThreatPriority,
  type STRIDEMapping,
} from './stride-mapper.js';

let modelCounter = 0;

export function generateThreatModel(
  graph: ProgramGraph,
  taintResult: TaintResult,
  filePath: string,
): ThreatModel {
  const query = new GraphQuery(graph);
  const boundaries = extractTrustBoundaries(graph, taintResult, filePath);
  const surfaces = enumerateAttackSurfaces(query, boundaries, taintResult, filePath);
  const threats = generateThreats(surfaces, boundaries, taintResult);

  const strideCoverage = computeStrideCoverage(threats);
  const riskAssessment = computeRiskAssessment(threats);

  return {
    id: `tm_${++modelCounter}_${Date.now()}`,
    scope: filePath,
    timestamp: Date.now(),
    method: 'auto_graph',
    trustBoundaries: boundaries,
    attackSurfaces: surfaces,
    threats,
    strideCoverage,
    riskAssessment,
    graphStats: {
      nodeCount: graph.nodeCount,
      edgeCount: graph.edgeCount,
      boundaryCount: boundaries.length,
      surfaceCount: surfaces.length,
      threatCount: threats.length,
    },
  };
}

function enumerateAttackSurfaces(
  query: GraphQuery,
  boundaries: TrustBoundary[],
  taintResult: TaintResult,
  filePath: string,
): AttackSurface[] {
  const entryPoints = query.findEntryPoints();
  const surfaces: AttackSurface[] = [];
  let surfaceId = 0;

  for (const ep of entryPoints) {
    const reachable = query.bfs(ep.id, ['CFG', 'CFG_TRUE', 'DFG', 'CALL', 'FALLS_TO']);

    const reachableSinks: string[] = [];
    const dfPaths: DataFlowPath[] = [];
    const crossedBoundaries: string[] = [];

    for (const taintPath of taintResult.paths) {
      const sinkNode = query.filterNodes(n =>
        (n.lineStart != null && n.lineStart === taintPath.sink.line) ||
        (n.code != null && n.code.includes(taintPath.sink.name)),
      );
      for (const sn of sinkNode) {
        if (reachable.has(sn.id)) {
          reachableSinks.push(sn.id);
        }
      }

      const sourceNode = query.filterNodes(n =>
        n.lineStart === taintPath.source.line,
      );
      if (sourceNode.length > 0 && reachable.has(sourceNode[0]?.id)) {
        dfPaths.push({
          id: `dfp_${surfaceId}_${dfPaths.length}`,
          source: sourceNode[0].id,
          sink: reachableSinks[reachableSinks.length - 1] ?? sourceNode[0].id,
          intermediaries: [],
          sanitizers: taintPath.sanitizers.map(s => `san_${s.id}`),
          crossBoundary: taintPath.confidence >= 0.6,
          confidence: taintPath.confidence,
        });
      }
    }

    for (const boundary of boundaries) {
      const insideNodes = new Set(boundary.inside.nodes);
      const outsideNodes = new Set(boundary.outside.nodes);
      for (const rn of reachable) {
        if (outsideNodes.has(rn)) {
          crossedBoundaries.push(boundary.id);
          break;
        }
      }
    }

    if (reachableSinks.length > 0 || dfPaths.length > 0) {
      const riskScore = computeSurfaceRisk(reachableSinks, crossedBoundaries, dfPaths);
      surfaces.push({
        id: `as_${++surfaceId}`,
        name: `${ep.properties.get('name') || ep.type} (line ${ep.lineStart ?? '?'})`,
        description: `Entry point at ${ep.type} with ${reachableSinks.length} reachable sink(s) crossing ${crossedBoundaries.length} trust boundary(ies)`,
        entryPoint: ep.id,
        entryType: inferEntryPointType(ep),
        reachableSinks: [...new Set(reachableSinks)],
        boundariesCrossed: [...new Set(crossedBoundaries)],
        dataFlowPaths: dfPaths,
        riskScore,
        location: { file: filePath, line: ep.lineStart },
      });
    }
  }

  return surfaces.sort((a, b) => b.riskScore - a.riskScore);
}

function generateThreats(
  surfaces: AttackSurface[],
  boundaries: TrustBoundary[],
  taintResult: TaintResult,
): Threat[] {
  const threats: Threat[] = [];
  const seen = new Set<string>();
  let threatId = 0;

  for (const surface of surfaces) {
    for (const dfPath of surface.dataFlowPaths) {
      for (const taintPath of taintResult.paths) {
        const strideMappings = classifySourceSink(
          taintPath.source.type as TaintSource['type'],
          taintPath.sink.type as TaintSink['type'],
        );

        for (const mapping of strideMappings) {
          const key = `${surface.id}:${mapping.category}:${taintPath.source.type}:${taintPath.sink.type}`;
          if (seen.has(key)) continue;
          seen.add(key);

          const boundary = boundaries.find(b =>
            b.taintPaths.some(tp => taintPath.path.includes(tp)),
          );

          threats.push({
            id: `threat_${++threatId}`,
            category: mapping.category,
            title: `${mapping.category}: ${taintPath.source.type} → ${taintPath.sink.type}`,
            description: `${taintPath.source.name} (line ${taintPath.source.line}) flows unsanitized to ${taintPath.sink.name} (line ${taintPath.sink.line}), enabling ${mapping.category} via ${mapping.cweIds.join(', ')}`,
            attackSurfaceId: surface.id,
            trustBoundaryId: boundary?.id,
            cwe: mapping.cweIds,
            owasp: mapping.owasp,
            suggestedDetectionRules: mapping.rulePrefixes,
            priority: computeThreatPriority(
              mapping.category,
              taintPath.confidence,
              taintPath.sanitizers.length > 0,
            ),
            scanned: false,
            findingIds: [],
          });
        }
      }
    }
  }

  return threats.sort((a, b) => b.priority - a.priority);
}

function computeStrideCoverage(threats: Threat[]): Record<STRIDECategory, boolean> {
  const coverage: Record<STRIDECategory, boolean> = {
    spoofing: false,
    tampering: false,
    repudiation: false,
    information_disclosure: false,
    denial_of_service: false,
    elevation_of_privilege: false,
  };
  for (const threat of threats) {
    coverage[threat.category] = true;
  }
  return coverage;
}

function computeRiskAssessment(threats: Threat[]): ThreatModel['riskAssessment'] {
  const byCategory: Record<STRIDECategory, number> = {
    spoofing: 0,
    tampering: 0,
    repudiation: 0,
    information_disclosure: 0,
    denial_of_service: 0,
    elevation_of_privilege: 0,
  };

  let totalRisk = 0;
  let criticalPaths = 0;

  for (const threat of threats) {
    byCategory[threat.category] += threat.priority;
    totalRisk += threat.priority;
    if (threat.priority >= 70) criticalPaths++;
  }

  const maxPossible = STRIDE_CATEGORIES.length * 90;
  const overall = Math.min(100, Math.round((totalRisk / maxPossible) * 100));

  for (const cat of STRIDE_CATEGORIES) {
    byCategory[cat] = Math.min(100, byCategory[cat]);
  }

  return { overall, byCategory, criticalPaths };
}

function computeSurfaceRisk(
  sinks: string[],
  boundaries: string[],
  paths: DataFlowPath[],
): number {
  const sinkWeight = Math.min(30, sinks.length * 10);
  const boundaryWeight = Math.min(30, boundaries.length * 15);
  const pathWeight = Math.min(40, paths.filter(p => p.crossBoundary).length * 20);
  return Math.min(100, sinkWeight + boundaryWeight + pathWeight);
}

function inferEntryPointType(node: import('../engine/program-graph.js').PGNode): EntryPointType {
  const name = (node.properties.get('name') as string | undefined) ?? '';
  const code = node.code ?? '';

  if (/^(get|post|put|delete|patch|head|options|all)\b/i.test(name)) return 'http_handler';
  if (/^(handle|process|execute|run|dispatch)\b/i.test(name)) return 'api_endpoint';
  if (/^on[A-Z]/.test(name)) return 'event_handler';
  if (/^(main|cli|parse|command)/i.test(name)) return 'cli_handler';
  if (/read|load|import/i.test(code)) return 'file_input';
  if (/query|find|fetch/i.test(code)) return 'db_query';
  return 'function_export';
}
