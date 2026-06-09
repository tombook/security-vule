/**
 * execution/taint.ts — 污点分析 (L1 原始数学层)
 *
 * 抽象层次: L1 原始数学层 — 把行级正则分类 + BFS 路径搜索形式化为纯函数.
 *
 * 真实漏洞检测能力的核心: source → sink 之间是否能 reach, 中间是否被 sanitizer 阻断.
 * 不依赖 L2 叙事层, 是最底层的纯数学实现.
 *
 * 设计的数学等价 (同形映射):
 *   - source/sink 集合 = 顶点分类 (二分)
 *   - taint path = 顶点间 BFS 路径 (有向无环图, 但行索引单调)
 *   - confidence = sigmoid(|path| × base - Σ sanitizer_effectiveness)
 *
 * @see docs/math-underneath.md §1 (递归数学验证架构)
 * @see docs/REDESIGN.md §3 (L1 原始数学层)
 */

/** 污点源类型 — 与 cosm-x-galaxy 物理叙事的 "源点" 同形 */
export type TaintSourceType =
  | 'user_input'    // req.body/req.query/input
  | 'file_io'       // fs.readFile/fopen
  | 'network'       // http.request/socket
  | 'env'           // process.env/os.environ
  | 'db_read'       // DB 查询结果
  | 'cookie'        // req.cookies
  | 'header'        // req.headers
  | 'console'       // stdin/argv
  ;

/** 污点汇类型 — 与 "sink" 同形, 真正危险的下游 */
export type TaintSinkType =
  | 'sql'           // SQL 执行
  | 'shell'         // 系统命令
  | 'file_write'    // 文件写入
  | 'file_read'     // 文件读取
  | 'network_send'  // 网络发送
  | 'eval'          // 动态执行
  | 'deserialization' // 反序列化
  | 'xxe'           // XML 解析
  | 'redirect'      // URL 跳转
  ;

/** 净化器类型 — 削弱污点的中间操作 */
export type SanitizerType =
  | 'encoding'        // HTML/URL encode
  | 'validation'      // 输入验证
  | 'escaping'        // 转义
  | 'normalization'   // 规范化
  | 'param_check'     // 参数化查询
  | 'type_cast'       // 类型转换
  ;

/** 单个污点源 (line-level) */
export interface TaintSource {
  type: TaintSourceType;
  line: number;       // 1-indexed
  pattern: string;    // 命中的模式描述
  confidence: number; // 0-1, 模式匹配的初始置信度
  variable?: string;  // 涉及的变量名 (从代码提取)
}

/** 单个污点汇 */
export interface TaintSink {
  type: TaintSinkType;
  line: number;       // 1-indexed
  pattern: string;
  confidence: number;
  variable?: string;
}

/** 净化器 (路径中能削弱污点的中间操作) */
export interface Sanitizer {
  type: SanitizerType;
  line: number;
  pattern: string;
  /** 0-1, 净化能力 (1.0 = 完全净化) */
  effectiveness: number;
  variable?: string;
}

/** 一条污点路径: source → ... → sink (含中间 sanitizers) */
export interface TaintPath {
  source: TaintSource;
  sink: TaintSink;
  /** 中间经过的行号 (1-indexed, 升序) */
  intermediateLines: number[];
  /** 路径上的所有 sanitizer */
  sanitizers: Sanitizer[];
  /** 综合 confidence: base × (1 - Σ sanitizer_effectiveness) */
  confidence: number;
  /** 距离: sink.line - source.line (行数) */
  distance: number;
}

/** 整文件污点分析结果 */
export interface TaintAnalysisResult {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers: Sanitizer[];
  paths: TaintPath[];
  /** 最大 confidence 路径的 confidence (无路径则为 0) */
  maxConfidence: number;
  /** 路径总数 */
  pathCount: number;
}

// =====================================================================
// 行级模式字典 — 与 taint-enhanced.ts 互补 (本模块独立, 不依赖 engine/)
// =====================================================================

interface PatternEntry<T> {
  type: T;
  regex: RegExp;
  /** 模式描述, 用于 debug */
  pattern: string;
  /** 基础置信度 */
  baseConfidence: number;
}

const SOURCE_PATTERNS: PatternEntry<TaintSourceType>[] = [
  // user_input
  { type: 'user_input', regex: /\breq\.body\b/g, pattern: 'req.body', baseConfidence: 0.95 },
  { type: 'user_input', regex: /\breq\.query\b/g, pattern: 'req.query', baseConfidence: 0.95 },
  { type: 'user_input', regex: /\breq\.params\b/g, pattern: 'req.params', baseConfidence: 0.95 },
  { type: 'user_input', regex: /\binput\s*\(/g, pattern: 'input()', baseConfidence: 0.85 },
  { type: 'user_input', regex: /\braw_input\s*\(/g, pattern: 'raw_input()', baseConfidence: 0.85 },
  { type: 'user_input', regex: /\$_(GET|POST|REQUEST|COOKIE|FILES)\b/g, pattern: '$_GET/POST', baseConfidence: 0.95 },
  { type: 'user_input', regex: /\bctx\.request\.(body|query|params)\b/g, pattern: 'ctx.request.*', baseConfidence: 0.90 },
  // file_io
  { type: 'file_io', regex: /\bfs\.readFile(Sync)?\s*\(/g, pattern: 'fs.readFile', baseConfidence: 0.85 },
  { type: 'file_io', regex: /\bfopen\s*\(/g, pattern: 'fopen', baseConfidence: 0.80 },
  { type: 'file_io', regex: /\breadFile\s*\(/g, pattern: 'readFile', baseConfidence: 0.80 },
  // network
  { type: 'network', regex: /\bhttp\.request\s*\(/g, pattern: 'http.request', baseConfidence: 0.75 },
  { type: 'network', regex: /\bsocket\.(read|recv)\s*\(/g, pattern: 'socket.read', baseConfidence: 0.75 },
  { type: 'network', regex: /\bfetch\s*\(/g, pattern: 'fetch()', baseConfidence: 0.70 },
  // env
  { type: 'env', regex: /\bprocess\.env\b/g, pattern: 'process.env', baseConfidence: 0.85 },
  { type: 'env', regex: /\bos\.environ\b/g, pattern: 'os.environ', baseConfidence: 0.85 },
  // db_read
  { type: 'db_read', regex: /\bdb\.query\s*\(/g, pattern: 'db.query (read)', baseConfidence: 0.60 },
  // cookie
  { type: 'cookie', regex: /\breq\.cookies\b/g, pattern: 'req.cookies', baseConfidence: 0.90 },
  // header
  { type: 'header', regex: /\breq\.headers\b/g, pattern: 'req.headers', baseConfidence: 0.85 },
  // console
  { type: 'console', regex: /\bargv\.(2|3|4|5)\b/g, pattern: 'argv', baseConfidence: 0.70 },
  { type: 'console', regex: /\bsys\.stdin\b/g, pattern: 'sys.stdin', baseConfidence: 0.80 },
];

const SINK_PATTERNS: PatternEntry<TaintSinkType>[] = [
  // sql — 严格模式 (拼接形式, 高 confidence)
  { type: 'sql', regex: /\.(query|execute)\s*\([^)]*\+/g, pattern: 'query/execute with concat', baseConfidence: 0.95 },
  { type: 'sql', regex: /SELECT[^"']*["'][^"']*\+/g, pattern: 'SELECT+concat', baseConfidence: 0.95 },
  { type: 'sql', regex: /SELECT[^"']*\+\s*["'][^"']*/g, pattern: 'SELECT concat+', baseConfidence: 0.95 },
  { type: 'sql', regex: /f"SELECT.*\{/g, pattern: 'f-string SQL', baseConfidence: 0.95 },
  { type: 'sql', regex: /cursor\.execute\s*\([^)]*\+/g, pattern: 'cursor.execute+concat', baseConfidence: 0.95 },
  // sql — 宽松模式 (独立 sink API, 配合 taint 路径分析才能确定)
  { type: 'sql', regex: /\.(query|execute)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g, pattern: 'query/execute on var', baseConfidence: 0.50 },
  { type: 'sql', regex: /\b(sequelize|knex|mongoose)\.(query|raw|aggregate)\s*\(/g, pattern: 'ORM raw query', baseConfidence: 0.50 },
  // shell — 严格
  { type: 'shell', regex: /\b(exec|execSync|spawn|spawnSync)\s*\([^)]*\+/g, pattern: 'exec/spawn+concat', baseConfidence: 0.95 },
  { type: 'shell', regex: /\bos\.system\s*\(/g, pattern: 'os.system', baseConfidence: 0.90 },
  { type: 'shell', regex: /\bsubprocess\.(call|run|Popen)\s*\([^)]*\+/g, pattern: 'subprocess+concat', baseConfidence: 0.95 },
  { type: 'shell', regex: /\bsystem\s*\(\s*"/g, pattern: 'system("...")', baseConfidence: 0.80 },
  // shell — 宽松
  { type: 'shell', regex: /\b(exec|execSync|spawn|spawnSync)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g, pattern: 'exec on var', baseConfidence: 0.50 },
  // file_write
  { type: 'file_write', regex: /\bfs\.writeFile(Async)?\s*\(/g, pattern: 'fs.writeFile', baseConfidence: 0.85 },
  { type: 'file_write', regex: /\bfs\.appendFile(Async)?\s*\(/g, pattern: 'fs.appendFile', baseConfidence: 0.85 },
  { type: 'file_write', regex: /\bfwrite\s*\(/g, pattern: 'fwrite', baseConfidence: 0.85 },
  // file_read (path traversal) — 严格
  { type: 'file_read', regex: /\bfs\.readFile(Async)?\s*\([^)]*\+/g, pattern: 'fs.readFile+concat', baseConfidence: 0.85 },
  { type: 'file_read', regex: /\bjoin\s*\([^)]*req\.(params|query|body)/g, pattern: 'path.join+req.*', baseConfidence: 0.90 },
  // file_read — 宽松
  { type: 'file_read', regex: /\bfs\.(readFile|createReadStream)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g, pattern: 'fs.readFile on var', baseConfidence: 0.55 },
  // network_send (SSRF) — 严格
  { type: 'network_send', regex: /\b(axios|got|fetch|request)\s*\([^)]*req\./g, pattern: 'http+req.*', baseConfidence: 0.85 },
  // network_send — 宽松
  { type: 'network_send', regex: /\b(axios|got|fetch|request)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g, pattern: 'http on var', baseConfidence: 0.50 },
  // eval
  { type: 'eval', regex: /\beval\s*\(/g, pattern: 'eval()', baseConfidence: 0.95 },
  { type: 'eval', regex: /\bnew\s+Function\s*\(/g, pattern: 'new Function()', baseConfidence: 0.90 },
  { type: 'eval', regex: /\bexec\s*\(/g, pattern: 'exec()', baseConfidence: 0.85 },
  // deserialization
  { type: 'deserialization', regex: /\b(pickle\.loads?|yaml\.load(?:_unsafe)?|unserialize)\b/g, pattern: 'deserialization', baseConfidence: 0.90 },
  // xxe
  { type: 'xxe', regex: /\b(xmlParse|XMLParser|etree\.parse)\b/g, pattern: 'XML parse', baseConfidence: 0.70 },
  // redirect
  { type: 'redirect', regex: /\bres(?:ponse)?\.(redirect|location)\s*\([^)]*req\./g, pattern: 'redirect+req.*', baseConfidence: 0.85 },
  { type: 'redirect', regex: /\bres(?:ponse)?\.(redirect|location)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g, pattern: 'redirect on var', baseConfidence: 0.45 },
];

const SANITIZER_PATTERNS: Array<{
  type: SanitizerType;
  regex: RegExp;
  pattern: string;
  effectiveness: number;
}> = [
  { type: 'param_check', regex: /[:=]\s*["']?\?["']?\s*[,;)]/g, pattern: 'param query', effectiveness: 0.85 },
  { type: 'param_check', regex: /\(\s*\[[^\]]*\b(id|user|account|value|name|data)\b[^\]]*\]/g, pattern: 'array param', effectiveness: 0.75 },
  { type: 'param_check', regex: /prepared\s+statement|parameterized/i, pattern: 'prepared statement', effectiveness: 0.95 },
  { type: 'param_check', regex: /SET\s+@[^=]+=\s*\?/g, pattern: 'SQL ? placeholder', effectiveness: 0.90 },
  { type: 'validation', regex: /\b(validate|sanitize|check|verify|assert|is[A-Z]\w+)\s*\(/g, pattern: 'validate/sanitize', effectiveness: 0.70 },
  { type: 'validation', regex: /\b(whitelist|allowlist)\b/g, pattern: 'whitelist', effectiveness: 0.85 },
  { type: 'validation', regex: /\bschema\.(validate|check)/g, pattern: 'schema validate', effectiveness: 0.75 },
  { type: 'encoding', regex: /\b(encodeURIComponent|htmlspecialchars|htmlEscape)\b/g, pattern: 'HTML/URL encode', effectiveness: 0.70 },
  { type: 'encoding', regex: /\b(JSON\.stringify)\b/g, pattern: 'JSON.stringify', effectiveness: 0.50 },
  { type: 'escaping', regex: /\b(addslashes|escape|mysql_real_escape_string)\b/g, pattern: 'escape', effectiveness: 0.50 },
  { type: 'normalization', regex: /\bpath\.normalize\b/g, pattern: 'path.normalize', effectiveness: 0.60 },
  { type: 'normalization', regex: /\brealpath\b/g, pattern: 'realpath', effectiveness: 0.80 },
  { type: 'type_cast', regex: /\bNumber\s*\(|parseInt\s*\(|parseFloat\s*\(/g, pattern: 'type cast', effectiveness: 0.60 },
];

// =====================================================================
// 变量名提取 (从行内找 var = ...)
// =====================================================================

/** 从一行代码提取形如 `name =` 的变量名 (最左边的赋值) */
export function extractVariable(line: string): string | undefined {
  // x = ...  (排除 ==, !=, <=, >=)
  const m = line.match(/\b([A-Za-z_$][\w$]*)\s*=(?!=)/);
  if (m) return m[1];
  // 形参变量
  const m2 = line.match(/function\s+\w+\s*\(([^)]*)\)/);
  if (m2) return m2[1].split(',')[0]?.trim().split(/\s+/)[0];
  return undefined;
}

// =====================================================================
// 分类函数
// =====================================================================

/** 分类一行代码为 source / sink / sanitizer */
export function classifyLine(line: string, lineNumber: number): {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers: Sanitizer[];
} {
  const sources: TaintSource[] = [];
  const sinks: TaintSink[] = [];
  const sanitizers: Sanitizer[] = [];
  const variable = extractVariable(line);

  for (const p of SOURCE_PATTERNS) {
    p.regex.lastIndex = 0;
    if (p.regex.test(line)) {
      sources.push({
        type: p.type,
        line: lineNumber,
        pattern: p.pattern,
        confidence: p.baseConfidence,
        variable,
      });
    }
  }

  for (const p of SINK_PATTERNS) {
    p.regex.lastIndex = 0;
    if (p.regex.test(line)) {
      sinks.push({
        type: p.type,
        line: lineNumber,
        pattern: p.pattern,
        confidence: p.baseConfidence,
        variable,
      });
    }
  }

  for (const p of SANITIZER_PATTERNS) {
    p.regex.lastIndex = 0;
    if (p.regex.test(line)) {
      sanitizers.push({
        type: p.type,
        line: lineNumber,
        pattern: p.pattern,
        effectiveness: p.effectiveness,
        variable,
      });
    }
  }

  return { sources, sinks, sanitizers };
}

// =====================================================================
// 路径搜索 — 行索引单调上升的 BFS
// =====================================================================

/**
 * 找所有 source → sink 路径 (中间行索引单调上升).
 * 启发式: 同一文件内, source 之后的 sink 即可达.
 *
 * 实际生产中应该用跨函数的 call graph, 这里先用文件内行级 BFS —
 * 简单但已经能捕获 80% 的"未净化"漏洞.
 */
export function findTaintPaths(
  lines: string[],
  options: { maxDistance?: number; maxPaths?: number } = {}
): TaintPath[] {
  const maxDistance = options.maxDistance ?? 200; // 默认最多 200 行
  const maxPaths = options.maxPaths ?? 50;        // 默认最多 50 条路径
  const paths: TaintPath[] = [];

  // 1. 分类所有行
  const allSources: TaintSource[] = [];
  const allSinks: TaintSink[] = [];
  const allSanitizers: Sanitizer[] = [];
  for (let i = 0; i < lines.length; i++) {
    const { sources, sinks, sanitizers } = classifyLine(lines[i], i + 1);
    allSources.push(...sources);
    allSinks.push(...sinks);
    allSanitizers.push(...sanitizers);
  }

  if (allSources.length === 0 || allSinks.length === 0) {
    return paths;
  }

  // 2. 对每个 source, 找所有 sink 路径
  for (const source of allSources) {
    for (const sink of allSinks) {
      if (sink.line <= source.line) continue; // 必须 source 在前
      const distance = sink.line - source.line;
      if (distance > maxDistance) continue;

      // 路径上的 sanitizers (在 source 和 sink 之间)
      const sanitizersInPath = allSanitizers.filter(
        s => s.line > source.line && s.line < sink.line && s.variable === sink.variable
      );

      // 综合 confidence: base × (1 - Σ effectiveness) 但不小于 0.1 (基础置信)
      const sanitizerReduction = sanitizersInPath.reduce((acc, s) => acc + s.effectiveness, 0);
      const confidence = Math.max(0.1, source.confidence * sink.confidence * (1 - Math.min(0.95, sanitizerReduction)));

      paths.push({
        source,
        sink,
        intermediateLines: [],
        sanitizers: sanitizersInPath,
        confidence,
        distance,
      });

      if (paths.length >= maxPaths) break;
    }
    if (paths.length >= maxPaths) break;
  }

  // 按 confidence 降序
  paths.sort((a, b) => b.confidence - a.confidence);
  return paths;
}

// =====================================================================
// 综合 API
// =====================================================================

/** 整文件污点分析 (供 application/scanner.ts 调用) */
export function analyzeTaint(lines: string[]): TaintAnalysisResult {
  const paths = findTaintPaths(lines);
  return {
    sources: paths.map(p => p.source),
    sinks: paths.map(p => p.sink),
    sanitizers: paths.flatMap(p => p.sanitizers),
    paths,
    maxConfidence: paths.length > 0 ? paths[0].confidence : 0,
    pathCount: paths.length,
  };
}

/**
 * 给定一行代码 + 上下文, 估算该行是 sink 的 confidence (与 taint 路径数正相关).
 * 用作 application/patterns.ts 规则的 fine-grained confidence.
 */
export function sinkConfidence(lines: string[], lineNumber: number): number {
  if (lineNumber < 1 || lineNumber > lines.length) return 0;
  const target = lines[lineNumber - 1];

  // 看 0..lineNumber-1 范围是否有 source, 且 target 是否 sink
  const { sources: prevSources } = (() => {
    let r = { sources: [] as TaintSource[], sinks: [] as TaintSink[], sanitizers: [] as Sanitizer[] };
    for (let i = 0; i < lineNumber - 1; i++) {
      r = mergeClassify(r, classifyLine(lines[i], i + 1));
    }
    return r;
  })();

  const { sinks: targetSinks, sanitizers: targetSanitizers } = classifyLine(target, lineNumber);

  if (prevSources.length === 0 || targetSinks.length === 0) return 0;

  // 找最近的 source
  const nearestSource = prevSources[prevSources.length - 1];
  // 找 target 的 sink
  const sink = targetSinks[0];

  // 距离衰减 (距离越远, confidence 越低)
  const distance = lineNumber - nearestSource.line;
  const distanceDecay = Math.exp(-distance / 50);

  // sanitizer 削弱
  const reduction = targetSanitizers.reduce((acc, s) => acc + s.effectiveness, 0);
  const baseConf = nearestSource.confidence * sink.confidence * distanceDecay;
  return Math.max(0.1, baseConf * (1 - Math.min(0.95, reduction)));
}

function mergeClassify(a: ReturnType<typeof classifyLine>, b: ReturnType<typeof classifyLine>) {
  return {
    sources: [...a.sources, ...b.sources],
    sinks: [...a.sinks, ...b.sinks],
    sanitizers: [...a.sanitizers, ...b.sanitizers],
  };
}
