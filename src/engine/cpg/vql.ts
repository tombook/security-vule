/**
 * VQL — Vule Query Language (declarative CPG query DSL).
 *
 * Inspired by GaloisInc/MATE's MQL and Joern's query language.
 * Provides composable predicates over the CPG (Code Property Graph).
 *
 * Usage:
 * const sinks = query(cpg)
 * .where(node => node.type === 'expr' && node.code.includes('eval'))
 * .reachableFrom('$_GET', { via: ['data'] })
 * .execute();
 *
 * const taint = query(cpg)
 * .source(n => /\\$_GET|\\$_POST/.test(n.code))
 * .sink(n => /eval|system|exec/.test(n.code))
 * .paths({ via: ['data'], maxPaths:50 })
 * .execute();
 *
 * Predicate combinators: and(), or(), not()
 * Built-in: reachableFrom(), sinksOf(), sourcesOf(), callChain()
 */

import type { CPG, CPGNode, CPGEdgeKind } from './types.js';
import { bfs, downstreamNodes, upstreamNodes, allPaths } from './queries.js';

export interface VqlPredicate {
  (node: CPGNode): boolean;
}

export interface VqlOptions {
  via?: CPGEdgeKind[];
  maxDepth?: number;
  maxPaths?: number;
}

export interface VqlPath {
  source: string;
  sink: string;
  nodes: string[];
  via: CPGEdgeKind[];
}

export interface VqlResult {
  nodes: CPGNode[];
  paths: VqlPath[];
  predicateCount: number;
  elapsedMs: number;
}

export class VqlQuery {
  private readonly predicates: Array<{ name: string; fn: VqlPredicate }> = [];
  private readonly pathPredicates: Array<{
    type: 'reachableFrom' | 'sinksOf' | 'sourcesOf' | 'callChain';
    target: string | VqlPredicate;
    options: VqlOptions;
  }> = [];
  private sourcePred: VqlPredicate | null = null;
  private sinkPred: VqlPredicate | null = null;

  constructor(private readonly cpg: CPG) {}

  where(name: string, pred: VqlPredicate): this {
    this.predicates.push({ name, fn: pred });
    return this;
  }

  and(pred: VqlPredicate): this {
    const last = this.predicates[this.predicates.length - 1];
    if (last) {
      const prev = last.fn;
      this.predicates[this.predicates.length - 1] = {
        name: `${last.name}+AND`,
        fn: (n) => prev(n) && pred(n),
      };
    } else {
      this.predicates.push({ name: 'AND', fn: pred });
    }
    return this;
  }

  or(pred: VqlPredicate): this {
    const last = this.predicates[this.predicates.length - 1];
    if (last) {
      const prev = last.fn;
      this.predicates[this.predicates.length - 1] = {
        name: `${last.name}+OR`,
        fn: (n) => prev(n) || pred(n),
      };
    } else {
      this.predicates.push({ name: 'OR', fn: pred });
    }
    return this;
  }

  not(pred: VqlPredicate): this {
    const last = this.predicates[this.predicates.length - 1];
    if (last) {
      const prev = last.fn;
      this.predicates[this.predicates.length - 1] = {
        name: `${last.name}+NOT`,
        fn: (n) => prev(n) && !pred(n),
      };
    } else {
      this.predicates.push({ name: 'NOT', fn: (n) => !pred(n) });
    }
    return this;
  }

  source(pred: VqlPredicate): this {
    this.sourcePred = pred;
    return this;
  }

  sink(pred: VqlPredicate): this {
    this.sinkPred = pred;
    return this;
  }

  reachableFrom(targetIdOrPred: string | VqlPredicate, options: VqlOptions = {}): this {
    this.pathPredicates.push({ type: 'reachableFrom', target: targetIdOrPred, options });
    return this;
  }

  sinksOf(targetIdOrPred: string | VqlPredicate, options: VqlOptions = {}): this {
    this.pathPredicates.push({ type: 'sinksOf', target: targetIdOrPred, options });
    return this;
  }

  sourcesOf(targetIdOrPred: string | VqlPredicate, options: VqlOptions = {}): this {
    this.pathPredicates.push({ type: 'sourcesOf', target: targetIdOrPred, options });
    return this;
  }

  callChain(targetIdOrPred: string | VqlPredicate, options: VqlOptions = {}): this {
    this.pathPredicates.push({ type: 'callChain', target: targetIdOrPred, options });
    return this;
  }

  paths(options: VqlOptions = {}): this {
    if (!this.sourcePred || !this.sinkPred) {
      throw new Error('paths() requires source() and sink() to be set first');
    }
    this.pathPredicates.push({ type: 'sourcesOf', target: this.sinkPred, options });
    return this;
  }

  execute(): VqlResult {
    const start = performance.now();
    const via = this.pathPredicates[0]?.options.via ?? ['data', 'control'];

    let nodes: CPGNode[] = Array.from(this.cpg.nodes.values());
    for (const p of this.predicates) {
      nodes = nodes.filter(p.fn);
    }

    const pathSet = new Set<string>();
    const paths: VqlPath[] = [];

    for (const pp of this.pathPredicates) {
      if (pp.type === 'reachableFrom') {
        const target =
          typeof pp.target === 'string'
            ? [pp.target]
            : Array.from(this.cpg.nodes.values())
                .filter(pp.target)
                .map((n) => n.id);

        for (const startId of target) {
          const downstream = bfs(this.cpg, startId).filter((id) =>
            via.includes(this.cpgEdgeKind(this.cpg, startId, id) ?? 'data')
          );
          for (const id of downstream) {
            pathSet.add(id);
          }
          paths.push({
            source: startId,
            sink: downstream[downstream.length - 1] ?? startId,
            nodes: [startId, ...downstream],
            via,
          });
        }
      } else if (pp.type === 'sinksOf') {
        const sourceIds =
          typeof pp.target === 'string'
            ? [pp.target]
            : Array.from(this.cpg.nodes.values())
                .filter(pp.target)
                .map((n) => n.id);

        for (const sid of sourceIds) {
          for (const reachable of downstreamNodes(this.cpg, sid)) {
            if (nodes.find((n) => n.id === reachable)) {
              paths.push({ source: sid, sink: reachable, nodes: [sid, reachable], via });
              pathSet.add(reachable);
            }
          }
        }
      } else if (pp.type === 'sourcesOf') {
        const sinkIds =
          typeof pp.target === 'string'
            ? [pp.target]
            : Array.from(this.cpg.nodes.values())
                .filter(pp.target)
                .map((n) => n.id);

        for (const tid of sinkIds) {
          for (const upstream of upstreamNodes(this.cpg, tid)) {
            if (nodes.find((n) => n.id === upstream)) {
              paths.push({ source: upstream, sink: tid, nodes: [upstream, tid], via });
              pathSet.add(upstream);
            }
          }
        }
      } else if (pp.type === 'callChain') {
        const callee = typeof pp.target === 'string' ? pp.target : null;
        if (callee) {
          const callers = this.cpg.callGraph(callee);
          paths.push({ source: callers[0] ?? '?', sink: callee, nodes: [...callers, callee], via });
          for (const c of callers) pathSet.add(c);
        }
      }
    }

    if (this.sourcePred && this.sinkPred) {
      const sources = Array.from(this.cpg.nodes.values()).filter(this.sourcePred);
      const sinks = Array.from(this.cpg.nodes.values()).filter(this.sinkPred);
      const maxPaths = this.pathPredicates[0]?.options.maxPaths ?? 50;
      for (const s of sources) {
        for (const t of sinks) {
          const found = allPaths(this.cpg, s.id, t.id, maxPaths);
          for (const p of found) {
            paths.push({ source: s.id, sink: t.id, nodes: p, via });
          }
        }
      }
    }

    const resultNodes = pathSet.size > 0 ? nodes.filter((n) => pathSet.has(n.id)) : nodes;

    return {
      nodes: resultNodes,
      paths,
      predicateCount: this.predicates.length + this.pathPredicates.length,
      elapsedMs: performance.now() - start,
    };
  }

  private cpgEdgeKind(cpg: CPG, from: string, to: string): CPGEdgeKind | null {
    const edge = cpg.edges.find((e) => e.source === from && e.target === to);
    return edge?.kind ?? null;
  }
}

export function query(cpg: CPG): VqlQuery {
  return new VqlQuery(cpg);
}

export const predicates = {
  nodeType:
    (t: CPGNode['type']): VqlPredicate =>
    (n) =>
      n.type === t,
  inFile:
    (file: string): VqlPredicate =>
    (n) =>
      n.file === file,
  codeContains:
    (s: string): VqlPredicate =>
    (n) =>
      n.code.includes(s),
  codeMatches:
    (re: RegExp): VqlPredicate =>
    (n) =>
      re.test(n.code),
  atLine:
    (line: number): VqlPredicate =>
    (n) =>
      n.line === line,
  inRange:
    (start: number, end: number): VqlPredicate =>
    (n) =>
      n.line >= start && n.line <= end,
  isUserInput:
    (lang: 'php' | 'python' | 'js' = 'php'): VqlPredicate =>
    (n) => {
      if (lang === 'php') return /\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER/.test(n.code);
      if (lang === 'python') return /\binput\s*\(|\brequest\./.test(n.code);
      return /\breq\.(body|params|query)|req\.body|process\.argv/.test(n.code);
    },
  isSink:
    (lang: 'php' | 'python' | 'js' = 'php'): VqlPredicate =>
    (n) => {
      if (lang === 'php')
        return /\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|\bfile_get_contents\s*\(|\bmysql_query\s*\(|->query\s*\(/.test(
          n.code
        );
      if (lang === 'python')
        return /\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|subprocess\.(?:call|run|Popen)|pickle\.loads?\s*\(/.test(
          n.code
        );
      return /\beval\s*\(|\bexec\s*\(|\bchild_process\.(?:exec|spawn)|require\s*\(/.test(n.code);
    },
};
