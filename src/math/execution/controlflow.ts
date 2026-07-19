/**
 * execution/controlflow.ts — 控制流分析 (L1 原始数学层)
 *
 * 抽象层次: L1 原始数学层 — 把经典编译器理论的 CFG 形式化为纯函数.
 *
 * 实现:
 *   1. basic block 划分 (leader-based, Aho/Sethi/Ullman)
 *   2. CFG 边构建 (顺序 + 分支 + 循环)
 *   3. 支配关系 (Lengauer-Tarjan 经典 O(N log N) 或迭代法 O(N²) 简化版)
 *   4. 自然循环识别 (back edge 的 header)
 *
 * 真实漏洞检测的应用:
 *   - "循环内未净化" → loop header→body 有 source→sink 路径
 *   - "if 分支内漏检" → branch block 进入条件判断时 control flow 复杂
 *   - "未覆盖的块" → 死代码 (dominance frontier 分析的输入)
 *
 * 数学等价:
 *   - 支配关系: idom[B] = (∩ idom[P]) ∪ {B} for P in pred(B), fixed-point
 *   - 自然循环: back edge (n→h) where h dominates n, loop body = {n | h dominates n, n reaches h}
 *
 * @see docs/math-underneath.md §2.3 (Graph Theory Metrics)
 * @see docs/REDESIGN.md §3 (L1 原始数学层)
 */

/** 块的标识: 用起始行号 */
export type BlockId = number;

/** 一个基本块 */
export interface BasicBlock {
  id: BlockId;          // 起始行号
  startLine: number;    // 1-indexed
  endLine: number;      // 1-indexed
  /** 块内语句数 */
  size: number;
  /** 该块是否以分支/跳转/返回结束 */
  terminator: 'fallthrough' | 'branch' | 'return' | 'throw' | 'continue' | 'break';
  /** 块的入口类型 (用于构造 CFG 时给 succ 加权) */
  entryKind: 'entry' | 'sequential' | 'branch_true' | 'branch_false' | 'loop_header';
}

/** CFG 边 */
export interface CFGEdge {
  from: BlockId;
  to: BlockId;
  kind: 'fallthrough' | 'branch_true' | 'branch_false' | 'loop_back' | 'unconditional';
  /** 边的概率/权重 (用于覆盖率分析), 0-1, 默认为 1.0 */
  weight: number;
}

/** 完整的 CFG */
export interface ControlFlowGraph {
  blocks: Map<BlockId, BasicBlock>;
  edges: CFGEdge[];
  entry: BlockId;
  /** 块数 */
  blockCount: number;
  /** 边数 */
  edgeCount: number;
}

/** 自然循环: header + 循环体块 */
export interface NaturalLoop {
  header: BlockId;
  body: Set<BlockId>;
  /** back edge: 从 body 中的块指向 header */
  backEdges: CFGEdge[];
  /** 循环深度 (嵌套层数) */
  depth: number;
}

/** CFG 分析综合结果 */
export interface ControlFlowAnalysis {
  cfg: ControlFlowGraph;
  /** idom[B] = B 的直接支配者 (0 表示没有, 通常是 entry) */
  immediateDominators: Map<BlockId, BlockId>;
  /** dominatedBy[B] = 被 B 支配的所有块 (包含 B) */
  dominatedBy: Map<BlockId, Set<BlockId>>;
  /** 自然循环 (含嵌套) */
  loops: NaturalLoop[];
  /** 不可达块 (从 entry 反向 BFS 找不到) */
  unreachableBlocks: BlockId[];
  /** 圈复杂度 V(G) = E - N + 2P */
  cyclomaticComplexity: number;
  /** 最大嵌套深度 */
  maxLoopDepth: number;
}

// =====================================================================
// 块识别: leader 算法
// =====================================================================

/** 分支/跳转关键字 */
const BRANCH_RE = /\b(if|else|for|while|do|switch|case|return|throw|break|continue)\b/;

/** 块开始标记的"领导者"识别 */
function isLeader(lines: string[], idx: number): boolean {
  // 第一个语句是 leader
  if (idx === 0) return true;
  const prev = lines[idx - 1];
  const curr = lines[idx];

  // 前一行以 `}` 结束 → 当前是 leader
  if (/^\s*[\}\]]?\s*[\}\]]?\s*$/.test(prev.trim()) && /^\s*[^\s\}\]]/.test(curr)) return true;
  // 前一行是分支/跳转 → 当前是 leader
  if (BRANCH_RE.test(prev) && !/^\s*(\}|\)|;?\s*$)/.test(prev)) return true;
  return false;
}

/** 给一行判 terminator 类型 */
function terminatorOf(line: string): BasicBlock['terminator'] {
  const t = line.trim();
  if (/^\s*return\b/.test(t)) return 'return';
  if (/^\s*throw\b/.test(t)) return 'throw';
  if (/^\s*continue\b/.test(t)) return 'continue';
  if (/^\s*break\b/.test(t)) return 'break';
  if (/\b(if|else\s+if|for|while|switch)\b/.test(t)) return 'branch';
  return 'fallthrough';
}

/** 划分 basic blocks (leader 算法) */
export function buildBlocks(lines: string[]): BasicBlock[] {
  const N = lines.length;
  const leaders = new Set<number>();
  leaders.add(0);

  for (let i = 0; i < N; i++) {
    const line = lines[i];
    if (isLeader(lines, i)) leaders.add(i);
    // 分支的下一行是 leader
    if (BRANCH_RE.test(line) && /(\bif\b|\bfor\b|\bwhile\b|\bcase\b|\bdefault\b)/.test(line)) {
      if (i + 1 < N) leaders.add(i + 1);
    }
  }

  const leaderList = Array.from(leaders).sort((a, b) => a - b);
  const blocks: BasicBlock[] = [];
  for (let i = 0; i < leaderList.length; i++) {
    const start = leaderList[i];
    const end = i + 1 < leaderList.length ? leaderList[i + 1] - 1 : N - 1;
    const blockLines = lines.slice(start, end + 1);
    const lastLine = blockLines[blockLines.length - 1] ?? '';
    blocks.push({
      id: start + 1,
      startLine: start + 1,
      endLine: end + 1,
      size: blockLines.filter(l => l.trim().length > 0).length,
      terminator: terminatorOf(lastLine),
      entryKind: i === 0 ? 'entry' : 'sequential',
    });
  }
  return blocks;
}

// =====================================================================
// CFG 边构建
// =====================================================================

/** 构建 CFG (顺序 + 分支 + 循环) */
export function buildCFG(lines: string[]): ControlFlowGraph {
  const blocks = buildBlocks(lines);
  const blockMap = new Map<BlockId, BasicBlock>();
  for (const b of blocks) blockMap.set(b.id, b);

  const edges: CFGEdge[] = [];
  const blockByStart = new Map<number, BasicBlock>();
  for (const b of blocks) blockByStart.set(b.startLine, b);

  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];
    const lastLine = lines[b.endLine - 1] ?? '';
    const trimmed = lastLine.trim();

    if (b.terminator === 'return' || b.terminator === 'throw') {
      // 不连出边
      continue;
    }
    if (b.terminator === 'continue' || b.terminator === 'break') {
      // 简单处理: 连接到下一个块 (粗略, 真实应解析跳转目标)
      const next = blocks[i + 1];
      if (next) edges.push({ from: b.id, to: next.id, kind: 'unconditional', weight: 1.0 });
      continue;
    }
    if (b.terminator === 'branch') {
      // if/while/for → 两条出边 (true + false)
      // 简化: true 分支到下一块, false 分支跳到 if 结束
      if (/\bif\b/.test(trimmed)) {
        const next = blocks[i + 1];
        const afterIf = blocks[i + 2];
        if (next) edges.push({ from: b.id, to: next.id, kind: 'branch_true', weight: 0.5 });
        if (afterIf) edges.push({ from: b.id, to: afterIf.id, kind: 'branch_false', weight: 0.5 });
      } else if (/\b(for|while)\b/.test(trimmed)) {
        // 循环: body 在下一块, back edge 在 body 末尾
        const body = blocks[i + 1];
        if (body) {
          edges.push({ from: b.id, to: body.id, kind: 'branch_true', weight: 0.9 });
          edges.push({ from: body.id, to: b.id, kind: 'loop_back', weight: 0.9 });
        }
        // 退出循环 = fall through 到 if 之后
        const exit = blocks[i + 2];
        if (exit) edges.push({ from: b.id, to: exit.id, kind: 'branch_false', weight: 0.1 });
      } else {
        // switch/case 简化: 连接到下一块
        const next = blocks[i + 1];
        if (next) edges.push({ from: b.id, to: next.id, kind: 'unconditional', weight: 1.0 });
      }
    } else {
      // fallthrough → 下一块
      const next = blocks[i + 1];
      if (next) edges.push({ from: b.id, to: next.id, kind: 'fallthrough', weight: 1.0 });
    }
  }

  return {
    blocks: blockMap,
    edges,
    entry: blocks.length > 0 ? blocks[0].id : 0,
    blockCount: blocks.length,
    edgeCount: edges.length,
  };
}

// =====================================================================
// 支配关系 (iterative 算法, O(N²) 简化版)
// =====================================================================

/**
 * 计算 immediate dominator:
 *   idom[entry] = entry
 *   idom[B] = intersect(idom[P] for P in pred(B))
 *
 * 迭代至 fixed-point (Cooper, Harvey & Kennedy 2001 简化).
 */
export function immediateDominators(cfg: ControlFlowGraph): Map<BlockId, BlockId> {
  const idom = new Map<BlockId, BlockId>();
  if (cfg.blockCount === 0) return idom;

  const entry = cfg.entry;
  idom.set(entry, entry);

  // pred: from → [to]
  const pred = new Map<BlockId, BlockId[]>();
  for (const e of cfg.edges) {
    if (!pred.has(e.to)) pred.set(e.to, []);
    pred.get(e.to)!.push(e.from);
  }

  // 拓扑序: 简单的 BFS-based reverse postorder
  const rpo: BlockId[] = [];
  const visited = new Set<BlockId>();
  function dfs(b: BlockId) {
    if (visited.has(b)) return;
    visited.add(b);
    for (const e of cfg.edges) {
      if (e.from === b) dfs(e.to);
    }
    rpo.push(b);
  }
  dfs(entry);

  // 迭代
  let changed = true;
  const MAX_ITER = cfg.blockCount * 4;
  let iter = 0;
  while (changed && iter < MAX_ITER) {
    changed = false;
    iter++;
    for (const b of rpo) {
      if (b === entry) continue;
      const preds = pred.get(b) ?? [];
      if (preds.length === 0) continue;
      // intersect: 从第一个 pred 开始, 逐个求交
      let newIdom: BlockId = preds[0];
      for (let i = 1; i < preds.length; i++) {
        newIdom = intersectIdom(idom, newIdom, preds[i]);
      }
      if (newIdom !== 0 && idom.get(b) !== newIdom) {
        idom.set(b, newIdom);
        changed = true;
      }
    }
  }
  return idom;
}

function intersectIdom(idom: Map<BlockId, BlockId>, a: BlockId, b: BlockId): BlockId {
  let finger1 = a;
  let finger2 = b;
  while (finger1 !== finger2) {
    while (finger1 > finger2) {
      const i = idom.get(finger1);
      if (i === undefined) return 0;
      finger1 = i;
    }
    while (finger2 > finger1) {
      const i = idom.get(finger2);
      if (i === undefined) return 0;
      finger2 = i;
    }
  }
  return finger1;
}

/** 计算 dominatedBy[B] = 被 B 支配的所有块 (包含 B) */
export function computeDominatedBy(idom: Map<BlockId, BlockId>, allBlocks: BlockId[]): Map<BlockId, Set<BlockId>> {
  const domBy = new Map<BlockId, Set<BlockId>>();
  for (const b of allBlocks) domBy.set(b, new Set([b]));
  // 自底向上 (按拓扑逆序)
  for (const b of allBlocks.slice().reverse()) {
    const parent = idom.get(b);
    if (parent !== undefined && parent !== b) {
      const parentSet = domBy.get(parent);
      if (parentSet) {
        for (const x of domBy.get(b)!) parentSet.add(x);
      }
    }
  }
  return domBy;
}

// =====================================================================
// 自然循环识别
// =====================================================================

/** 找 back edge + 自然循环 (Aho/Sethi/Ullman 算法) */
export function findNaturalLoops(cfg: ControlFlowGraph, idom: Map<BlockId, BlockId>): NaturalLoop[] {
  const loops: NaturalLoop[] = [];
  // back edge = edge (n→h) where h dominates n
  for (const e of cfg.edges) {
    if (e.kind === 'loop_back' || dominates(idom, e.to, e.from)) {
      // e 是 back edge, header = e.to
      const header = e.to;
      const body = new Set<BlockId>([header]);
      const stack: BlockId[] = [e.from];
      while (stack.length > 0) {
        const b = stack.pop()!;
        if (body.has(b)) continue;
        body.add(b);
        // 找 b 的所有前驱 (入边 from)
        for (const e2 of cfg.edges) {
          if (e2.to === b && !body.has(e2.from)) stack.push(e2.from);
        }
      }
      loops.push({
        header,
        body,
        backEdges: [e],
        depth: 0, // 后面再算
      });
    }
  }
  // 嵌套深度
  for (let i = 0; i < loops.length; i++) {
    let depth = 0;
    for (let j = 0; j < loops.length; j++) {
      if (i === j) continue;
      if (loops[j].body.has(loops[i].header)) depth++;
    }
    loops[i].depth = depth;
  }
  return loops;
}

/** 判断 a 是否支配 b (含等于) */
function dominates(idom: Map<BlockId, BlockId>, a: BlockId, b: BlockId): boolean {
  if (a === b) return true;
  let cur: BlockId = b;
  while (true) {
    const p = idom.get(cur);
    if (p === undefined || p === cur) return false;
    if (p === a) return true;
    cur = p;
  }
}

// =====================================================================
// 综合 API
// =====================================================================

/** 整文件 CFG 分析 (供 application/scanner.ts 调用) */
export function analyzeControlFlow(lines: string[]): ControlFlowAnalysis {
  const cfg = buildCFG(lines);
  const idom = immediateDominators(cfg);
  const allBlocks = Array.from(cfg.blocks.keys());
  const domBy = computeDominatedBy(idom, allBlocks);
  const loops = findNaturalLoops(cfg, idom);
  // 圈复杂度: V(G) = E - N + 2P (P=连通分量=1)
  const cyclomatic = cfg.edgeCount - cfg.blockCount + 2;
  // 不可达: 从 entry 反向 BFS 找不到
  const reachable = new Set<BlockId>();
  const stack: BlockId[] = [cfg.entry];
  while (stack.length > 0) {
    const b = stack.pop()!;
    if (reachable.has(b)) continue;
    reachable.add(b);
    for (const e of cfg.edges) {
      if (e.from === b) stack.push(e.to);
    }
  }
  const unreachable = allBlocks.filter(b => !reachable.has(b));
  // 最大循环嵌套
  const maxDepth = loops.reduce((m, l) => Math.max(m, l.depth + 1), 0);

  return {
    cfg,
    immediateDominators: idom,
    dominatedBy: domBy,
    loops,
    unreachableBlocks: unreachable,
    cyclomaticComplexity: cyclomatic,
    maxLoopDepth: maxDepth,
  };
}

/**
 * 给定行号 L, 返回 L 所在 block + 该 block 是否在某个循环内.
 * 供 application/patterns.ts 的 "loop-internal risk" 加权使用.
 */
export function blockAtLine(cfa: ControlFlowAnalysis, lineIdx: number): {
  block: BasicBlock | undefined;
  inLoop: boolean;
  loopDepth: number;
} {
  let block: BasicBlock | undefined;
  for (const b of cfa.cfg.blocks.values()) {
    if (b.startLine <= lineIdx && lineIdx <= b.endLine) {
      block = b;
      break;
    }
  }
  if (!block) return { block: undefined, inLoop: false, loopDepth: 0 };
  let depth = 0;
  for (const l of cfa.loops) {
    if (l.body.has(block.id)) depth = Math.max(depth, l.depth + 1);
  }
  return { block, inLoop: depth > 0, loopDepth: depth };
}
