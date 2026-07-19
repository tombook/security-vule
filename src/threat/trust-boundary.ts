import type { ProgramGraph } from '../engine/program-graph.js';
import type { TaintResult, TaintPath } from '../engine/taint.js';
import type { TrustBoundary, TrustZone, BoundaryType } from './types.js';
import { GraphQuery } from './graph-query.js';
import { mapBoundaryType } from './stride-mapper.js';

let boundaryId = 0;

export function extractTrustBoundaries(
  graph: ProgramGraph,
  taintResult: TaintResult,
  filePath: string,
): TrustBoundary[] {
  const query = new GraphQuery(graph);
  const boundaries: TrustBoundary[] = [];
  const seen = new Set<string>();

  for (const taintPath of taintResult.paths) {
    if (taintPath.confidence < 0.4) continue;

    const key = `${taintPath.source.type}:${taintPath.sink.type}:${taintPath.source.scope}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const sinkScopeNodes = query.findNodesInScope(taintPath.sink.scope);
    const sourceNodes = findSourceNodes(query, taintPath);

    const inside: TrustZone = {
      id: `zone_in_${++boundaryId}`,
      name: `${taintPath.sink.scope} (trusted processing)`,
      level: 'trusted',
      nodes: sinkScopeNodes,
      scope: taintPath.sink.scope,
    };

    const outside: TrustZone = {
      id: `zone_out_${boundaryId}`,
      name: `${taintPath.source.type} input (untrusted)`,
      level: 'untrusted',
      nodes: sourceNodes,
      scope: taintPath.source.scope,
    };

    const boundaryType = mapBoundaryType(
      taintPath.source.type as import('../engine/taint.js').TaintSource['type'],
      taintPath.sink.type as import('../engine/taint.js').TaintSink['type'],
    );

    boundaries.push({
      id: `tb_${++boundaryId}`,
      name: `${taintPath.source.type} → ${taintPath.sink.type} (${taintPath.source.scope})`,
      description: buildBoundaryDescription(taintPath),
      inside,
      outside,
      type: boundaryType,
      taintPaths: taintPath.path,
      location: { file: filePath, line: taintPath.source.line },
      confidence: taintPath.confidence,
    });
  }

  return deduplicateBoundaries(boundaries);
}

function findSourceNodes(query: GraphQuery, taintPath: TaintPath): string[] {
  const nodes = query.filterNodes(n =>
    n.lineStart === taintPath.source.line ||
    (n.properties.get('scope') as string | undefined) === taintPath.source.scope,
  );
  return nodes.map(n => n.id);
}

function buildBoundaryDescription(taintPath: TaintPath): string {
  const sanitizerNote = taintPath.sanitizers.length > 0
    ? ` (partially sanitized by ${taintPath.sanitizers.map(s => s.name).join(', ')})`
    : '';
  return `Data from ${taintPath.source.type} source "${taintPath.source.name}" (line ${taintPath.source.line}) flows to ${taintPath.sink.type} sink "${taintPath.sink.name}" (line ${taintPath.sink.line})${sanitizerNote}. Confidence: ${(taintPath.confidence * 100).toFixed(0)}%.`;
}

function deduplicateBoundaries(boundaries: TrustBoundary[]): TrustBoundary[] {
  const byKey = new Map<string, TrustBoundary>();
  for (const b of boundaries) {
    const existing = byKey.get(b.name);
    if (!existing || b.confidence > existing.confidence) {
      byKey.set(b.name, b);
    }
  }
  return Array.from(byKey.values()).sort((a, b) => b.confidence - a.confidence);
}
