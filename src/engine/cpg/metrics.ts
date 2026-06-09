/**
 * CPG metrics — pagerank, betweenness centrality, degree statistics.
 * Used by dimension detectors for graph-theoretic risk signals.
 *
 * Spec: §2.3 "图论指标"
 */

import type { CPG } from './types.js';

export interface DegreeStats {
  nodeCount: number;
  edgeCount: number;
  avgDegree: number;
  maxInDegree: number;
  maxOutDegree: number;
  isolatedCount: number;
}

export function computePagerank(cpg: CPG, iterations = 50, damping = 0.85): Map<string, number> {
  const ids = Array.from(cpg.nodes.keys());
  const N = ids.length;
  if (N === 0) return new Map();
  const pr = new Map<string, number>(ids.map(id => [id, 1 / N]));
  const outDegree = new Map<string, number>(ids.map(id => [id, cpg.outEdges(id).length]));
  for (let i = 0; i < iterations; i++) {
    const next = new Map<string, number>();
    let danglingSum = 0;
    for (const id of ids) {
      if (outDegree.get(id) === 0) danglingSum += pr.get(id)!;
    }
    for (const id of ids) {
      let rank = (1 - damping) / N + (damping * danglingSum) / N;
      for (const e of cpg.inEdges(id)) {
        const srcOut = outDegree.get(e.source)!;
        if (srcOut > 0) rank += damping * pr.get(e.source)! / srcOut;
      }
      next.set(id, rank);
    }
    for (const id of ids) pr.set(id, next.get(id)!);
  }
  return pr;
}

export function computeBetweenness(cpg: CPG): Map<string, number> {
  const ids = Array.from(cpg.nodes.keys());
  const bc = new Map<string, number>(ids.map(id => [id, 0]));
  for (const s of ids) {
    const stack: string[] = [];
    const pred = new Map<string, string[]>(ids.map(id => [id, []]));
    const sigma = new Map<string, number>(ids.map(id => [id, 0]));
    sigma.set(s, 1);
    const dist = new Map<string, number>(ids.map(id => [id, -1]));
    dist.set(s, 0);
    const queue: string[] = [s];
    while (queue.length) {
      const v = queue.shift()!;
      stack.push(v);
      for (const e of cpg.outEdges(v)) {
        const w = e.target;
        if (dist.get(w)! < 0) {
          dist.set(w, dist.get(v)! + 1);
          queue.push(w);
        }
        if (dist.get(w)! === dist.get(v)! + 1) {
          sigma.set(w, sigma.get(w)! + sigma.get(v)!);
          pred.get(w)!.push(v);
        }
      }
    }
    const delta = new Map<string, number>(ids.map(id => [id, 0]));
    while (stack.length) {
      const w = stack.pop()!;
      for (const v of pred.get(w)!) {
        delta.set(v, delta.get(v)! + (sigma.get(v)! / sigma.get(w)!) * (1 + delta.get(w)!));
      }
      if (w !== s) bc.set(w, bc.get(w)! + delta.get(w)!);
    }
  }
  const norm = ids.length > 2 ? (ids.length - 1) * (ids.length - 2) : 1;
  for (const id of ids) bc.set(id, bc.get(id)! / norm);
  return bc;
}

export function computeDegreeStats(cpg: CPG): DegreeStats {
  const ids = Array.from(cpg.nodes.keys());
  let maxIn = 0, maxOut = 0, totalDeg = 0, isolated = 0;
  for (const id of ids) {
    const inD = cpg.inDegree(id);
    const outD = cpg.outDegree(id);
    maxIn = Math.max(maxIn, inD);
    maxOut = Math.max(maxOut, outD);
    totalDeg += inD + outD;
    if (inD === 0 && outD === 0) isolated++;
  }
  return {
    nodeCount: ids.length,
    edgeCount: cpg.edges.length,
    avgDegree: ids.length ? totalDeg / ids.length : 0,
    maxInDegree: maxIn,
    maxOutDegree: maxOut,
    isolatedCount: isolated,
  };
}