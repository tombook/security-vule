/**
 * execution/dataflow.ts — 数据流分析 (L1 原始数学层)
 *
 * 抽象层次: L1 原始数学层 — 把经典编译器理论的 data flow 形式化为纯函数.
 *
 * 实现两种经典数据流分析 (Kildall 工作列表算法):
 *   1. reaching-definitions (前向, may): 程序点 p 之前可能到达的赋值语句
 *   2. live-variables      (后向, may): 程序点 p 之后可能被使用的变量
 *
 * 输出:
 *   - DU 链 (def → use): 哪些赋值语句在哪些行被使用
 *   - per-line 数据流: 每行的"前向到达定义集"和"后向活跃变量集"
 *
 * 真实漏洞检测的应用:
 *   - "x 未初始化就使用" → live(x) 在赋值前为真, 提示 UoU
 *   - "死代码" → live 集为空但仍被调用
 *   - "XSS source 链" → req.body 在 line N 赋值, 在 line M 使用, N→M 是 DU 链
 *
 * 数学等价 (Kildall 经典论文, 1973):
 *   in[B]  = ∪ out[P] for P in pred(B)
 *   out[B] = gen[B] ∪ (in[B] - kill[B])
 *   fixpoint until no change
 *
 * @see docs/math-underneath.md §2.1 (信息熵 + 图论)
 * @see docs/REDESIGN.md §3 (L1 原始数学层)
 */

/** 程序点用 1-indexed 行号标识 */
export type LineIdx = number;

/** 一个赋值定义 (x = ... 在 line L) */
export interface Definition {
  variable: string;
  line: LineIdx;
}

/** 一处变量使用 */
export interface Use {
  variable: string;
  line: LineIdx;
  /** 是读还是写 (后者也算 def) */
  kind: 'read' | 'write';
}

/** def → use 链 */
export interface DefUseChain {
  def: Definition;
  uses: Use[];
}

/** 整文件数据流分析结果 */
export interface DataFlowResult {
  /** 每行的前向 reaching definitions (key=line) */
  reachingDefs: Map<LineIdx, ReadonlySet<Definition>>;
  /** 每行的后向 live variables (key=line) */
  liveVars: Map<LineIdx, ReadonlySet<string>>;
  /** 所有 def → use 链 */
  defUseChains: DefUseChain[];
  /** use 前未赋值的变量 (潜在 UoU) */
  uninitializedUses: Use[];
  /** 死代码 (write 后未 read 的变量) */
  deadStores: Definition[];
  /** 变量使用统计 */
  variableStats: Array<{ name: string; defs: number; uses: number }>;
}

// =====================================================================
// 行级解析: 提取赋值 (def) 和使用 (use)
// =====================================================================

/** 形如 `x = ...` 的赋值, 排除 ==, !=, <=, >= */
const ASSIGN_RE = /\b([A-Za-z_$][\w$]*)\s*=(?!=)/g;

/** 形如 `x.y`, `x[y]`, `x(...)`, `f(x)` 的"读使用" 标识符 (简单提取) */
const IDENT_RE = /\b([A-Za-z_$][\w$]*)\b/g;

/** 关键字黑名单 (这些不是变量) */
const KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
  'return', 'function', 'class', 'new', 'var', 'let', 'const', 'this', 'super',
  'try', 'catch', 'throw', 'finally', 'yield', 'await', 'async', 'of', 'in',
  'typeof', 'instanceof', 'void', 'delete', 'true', 'false', 'null', 'undefined',
  'import', 'export', 'from', 'default', 'as',
  // 常见 API 名 (避免误报)
  'console', 'log', 'error', 'warn', 'info', 'debug',
  'Math', 'Number', 'String', 'Array', 'Object', 'JSON', 'Date',
  'Promise', 'Error', 'RegExp', 'Map', 'Set', 'Symbol',
  'require', 'module', 'exports', 'global', 'globalThis', 'window', 'document',
  'process', 'Buffer', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
  'db', 'app', 'router', 'req', 'res', 'next', 'ctx', 'err', 'error',
]);

/** 形参提取: function foo(x, y) → ['x', 'y'] */
function extractParams(line: string): string[] {
  const m = line.match(/function\s*\w*\s*\(([^)]*)\)/);
  if (!m) return [];
  return m[1].split(',').map(s => s.trim().split(/\s*[:=]\s*/)[0]).filter(Boolean);
}

/** 提取一行中的所有赋值定义 */
export function extractDefs(line: string, lineNumber: LineIdx): Definition[] {
  // 跳过函数声明
  if (/^\s*(function|class|interface|type|enum|namespace|module|export\s+function|export\s+class)/.test(line)) {
    return [];
  }
  const defs: Definition[] = [];
  let m: RegExpExecArray | null;
  ASSIGN_RE.lastIndex = 0;
  while ((m = ASSIGN_RE.exec(line)) !== null) {
    const variable = m[1];
    if (KEYWORDS.has(variable)) continue;
    defs.push({ variable, line: lineNumber });
  }
  return defs;
}

/** 提取一行中的所有使用 (read + write) */
export function extractUses(line: string, lineNumber: LineIdx): Use[] {
  const uses: Use[] = [];
  const defs = extractDefs(line, lineNumber);
  const defSet = new Set(defs.map(d => d.variable));

  IDENT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IDENT_RE.exec(line)) !== null) {
    const name = m[1];
    if (KEYWORDS.has(name)) continue;
    // 跳过被定义为新值的标识符 (那是 write, 不算 read of itself)
    if (defSet.has(name)) continue;
    uses.push({ variable: name, line: lineNumber, kind: 'read' });
  }

  // 形参也算 def (在函数声明行)
  if (/^\s*(function|export\s+function|async\s+function|const\s+\w+\s*=\s*(\(|async))/.test(line)) {
    for (const p of extractParams(line)) {
      uses.push({ variable: p, line: lineNumber, kind: 'write' });
    }
  }
  return uses;
}

// =====================================================================
// Reaching Definitions (前向, may, Kildall)
// =====================================================================

/**
 * 计算 reaching definitions:
 *   in[B]  = ∪ out[P] for P in pred(B)
 *   out[B] = gen[B] ∪ (in[B] - kill[B])
 *
 * 行级简化: pred(L) = L-1 (顺序), 循环处循环前向流动.
 * 迭代至 fixed-point.
 */
export function reachingDefinitions(lines: string[]): Map<LineIdx, ReadonlySet<Definition>> {
  const N = lines.length;
  // gen[L] = 本行的所有 def
  const gen: Definition[][] = lines.map((l, i) => extractDefs(l, i + 1));
  // kill[L] = 同变量在其它行的 def 行号
  const killByLine: Set<Definition>[] = [];
  for (let i = 0; i < N; i++) {
    const thisVar = new Set(gen[i].map(d => d.variable));
    const kills = new Set<Definition>();
    for (let j = 0; j < N; j++) {
      if (j === i) continue;
      for (const d of gen[j]) {
        if (thisVar.has(d.variable)) kills.add(d);
      }
    }
    killByLine.push(kills);
  }

  // in[L] / out[L]
  const inSet: Set<Definition>[] = Array.from({ length: N }, () => new Set());
  const outSet: Set<Definition>[] = Array.from({ length: N }, () => new Set());

  // 初始化: out[0] = gen[0]
  for (const d of gen[0]) outSet[0].add(d);

  // 工作列表迭代
  let changed = true;
  let iter = 0;
  const MAX_ITER = N * 4 + 16;
  while (changed && iter < MAX_ITER) {
    changed = false;
    iter++;
    for (let i = 1; i < N; i++) {
      // in[i] = out[i-1] (单前驱简化)
      inSet[i] = new Set(outSet[i - 1]);
      // out[i] = gen[i] ∪ (in[i] - kill[i])
      const newOut = new Set(gen[i]);
      for (const d of inSet[i]) {
        if (!killByLine[i].has(d)) newOut.add(d);
      }
      if (newOut.size !== outSet[i].size || ![...newOut].every(d => outSet[i].has(d))) {
        outSet[i] = newOut;
        changed = true;
      }
    }
  }

  // 包装为 in[B] (输出 in 而非 out, 语义清晰)
  const result = new Map<LineIdx, ReadonlySet<Definition>>();
  for (let i = 0; i < N; i++) {
    result.set(i + 1, inSet[i]);
  }
  return result;
}

// =====================================================================
// Live Variables (后向, may, Kildall)
// =====================================================================

/**
 * live variables (反向):
 *   out[B] = ∪ in[S] for S in succ(B)
 *   in[B]  = use[B] ∪ (out[B] - def[B])
 */
export function liveVariables(lines: string[]): Map<LineIdx, ReadonlySet<string>> {
  const N = lines.length;
  // use[L] = 本行 read 的变量 (排除本行 def)
  // def[L] = 本行 write 的变量
  const useByLine: Set<string>[] = [];
  const defByLine: Set<string>[] = [];
  for (let i = 0; i < N; i++) {
    const line = lines[i];
    const defs = extractDefs(line, i + 1);
    const uses = extractUses(line, i + 1);
    const defVars = new Set(defs.map(d => d.variable));
    const useVars = new Set<string>();
    for (const u of uses) {
      if (u.kind === 'read' && !defVars.has(u.variable)) useVars.add(u.variable);
    }
    useByLine.push(useVars);
    defByLine.push(defVars);
  }

  const inSet: Set<string>[] = Array.from({ length: N }, () => new Set());
  const outSet: Set<string>[] = Array.from({ length: N }, () => new Set());

  let changed = true;
  let iter = 0;
  const MAX_ITER = N * 4 + 16;
  while (changed && iter < MAX_ITER) {
    changed = false;
    iter++;
    // 反向遍历
    for (let i = N - 1; i >= 0; i--) {
      // out[i] = in[i+1] (单后继简化)
      const newOut = i + 1 < N ? new Set(inSet[i + 1]) : new Set<string>();
      // in[i] = use[i] ∪ (out[i] - def[i])
      const newIn = new Set(useByLine[i]);
      for (const v of newOut) {
        if (!defByLine[i].has(v)) newIn.add(v);
      }
      if (newOut.size !== outSet[i].size || ![...newOut].every(v => outSet[i].has(v))) {
        outSet[i] = newOut;
      }
      if (newIn.size !== inSet[i].size || ![...newIn].every(v => inSet[i].has(v))) {
        inSet[i] = newIn;
        changed = true;
      }
    }
  }

  const result = new Map<LineIdx, ReadonlySet<string>>();
  for (let i = 0; i < N; i++) {
    result.set(i + 1, inSet[i]);
  }
  return result;
}

// =====================================================================
// DU Chains + 死代码 / 未初始化检测
// =====================================================================

/** 提取 DU 链 */
export function buildDefUseChains(lines: string[]): DefUseChain[] {
  const defs: Definition[] = [];
  const uses: Use[] = [];
  for (let i = 0; i < lines.length; i++) {
    defs.push(...extractDefs(lines[i], i + 1));
    uses.push(...extractUses(lines[i], i + 1));
  }

  // 聚合: 每个 def → 所有 line 严格大于 def.line 的同名 read
  const chainMap = new Map<string, DefUseChain>();
  for (const d of defs) {
    const key = `${d.variable}@${d.line}`;
    if (!chainMap.has(key)) chainMap.set(key, { def: d, uses: [] });
  }
  for (const u of uses) {
    if (u.kind !== 'read') continue;
    // 找最近的 def (line < u.line)
    const candidate = defs
      .filter(d => d.variable === u.variable && d.line < u.line)
      .sort((a, b) => b.line - a.line)[0];
    if (!candidate) continue;
    const key = `${candidate.variable}@${candidate.line}`;
    chainMap.get(key)!.uses.push(u);
  }

  return Array.from(chainMap.values());
}

/** 检测"使用前未初始化"的变量 (Use, 在到达 def 集为空的情况下) */
export function findUninitializedUses(
  lines: string[],
  reaching: Map<LineIdx, ReadonlySet<Definition>>,
  uses: Use[]
): Use[] {
  const uninit: Use[] = [];
  for (const u of uses) {
    if (u.kind !== 'read') continue;
    const reached = reaching.get(u.line);
    if (!reached) {
      uninit.push(u);
      continue;
    }
    const hasDef = [...reached].some(d => d.variable === u.variable);
    if (!hasDef) uninit.push(u);
  }
  return uninit;
}

/** 死代码: 写入后从未被读 */
export function findDeadStores(chains: DefUseChain[]): Definition[] {
  return chains.filter(c => c.uses.length === 0).map(c => c.def);
}

/** 变量统计: 名字 → def 数 + use 数 */
export function variableStats(chains: DefUseChain[], uses: Use[]): Array<{ name: string; defs: number; uses: number }> {
  const stat = new Map<string, { name: string; defs: number; uses: number }>();
  for (const c of chains) {
    const s = stat.get(c.def.variable) ?? { name: c.def.variable, defs: 0, uses: 0 };
    s.defs += 1;
    s.uses += c.uses.length;
    stat.set(c.def.variable, s);
  }
  // use only (隐式 globals, 来自 extractUses 中未配对 def)
  for (const u of uses) {
    if (u.kind !== 'read') continue;
    if (stat.has(u.variable)) continue;
    stat.set(u.variable, { name: u.variable, defs: 0, uses: 1 });
  }
  return Array.from(stat.values()).sort((a, b) => b.uses - a.uses);
}

// =====================================================================
// 综合 API
// =====================================================================

/** 整文件数据流分析 (供 application/scanner.ts 调用) */
export function analyzeDataFlow(lines: string[]): DataFlowResult {
  const reaching = reachingDefinitions(lines);
  const live = liveVariables(lines);
  const chains = buildDefUseChains(lines);
  const allUses: Use[] = [];
  for (let i = 0; i < lines.length; i++) allUses.push(...extractUses(lines[i], i + 1));
  const uninit = findUninitializedUses(lines, reaching, allUses);
  const dead = findDeadStores(chains);
  const stats = variableStats(chains, allUses);
  return {
    reachingDefs: reaching,
    liveVars: live,
    defUseChains: chains,
    uninitializedUses: uninit,
    deadStores: dead,
    variableStats: stats,
  };
}

/**
 * 给定行号 L 和变量名 v, 找出 v 在 L 之前最近一次 def 的行号.
 * 用作 application/patterns.ts 规则的 line-level 关联 (跟 taint.ts 配合).
 * 返回 0 表示没找到 def.
 */
export function findDefiningLine(lines: string[], lineIdx: LineIdx, variable: string): LineIdx {
  for (let i = lineIdx - 1; i >= 1; i--) {
    const line = lines[i - 1];
    const defs = extractDefs(line, i);
    if (defs.some(d => d.variable === variable)) return i;
  }
  return 0;
}

/**
 * 给定行号 L, 返回该行所有"上一行/本行定义,在 ≤L 处被使用"的变量集合.
 * 简化的活跃性查询 (给 taint 路径补充"变量传播链"信息).
 */
export function varsUsedAt(lines: string[], lineIdx: LineIdx): string[] {
  if (lineIdx < 1 || lineIdx > lines.length) return [];
  const line = lines[lineIdx - 1];
  return extractUses(line, lineIdx).filter(u => u.kind === 'read').map(u => u.variable);
}
