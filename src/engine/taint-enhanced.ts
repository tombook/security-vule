/**
 * Enhanced Taint Analysis
 * Inter-procedural taint tracking with sanitizer awareness
 * Inspired by Joern, Angora, VUzzer data-driven approaches
 */

export interface TaintSource {
  id: string;
  type: 'user_input' | 'file_io' | 'network' | 'env' | 'db' | 'cookie' | 'header' | 'console';
  name: string;
  line: number;
  scope: string;
  confidence: number;
  value?: string;
}

export interface TaintSink {
  id: string;
  type: 'sql' | 'shell' | 'file_write' | 'file_read' | 'network_send' | 'eval' | 'dynamic_code' | 'deserialization' | '反射' | 'xxe';
  name: string;
  line: number;
  scope: string;
  confidence: number;
}

export interface Sanitizer {
  id: string;
  type: 'encoding' | 'validation' | 'escaping' | 'normalization' | 'sanitization' | 'param_check' | 'type_cast';
  name: string;
  line: number;
  scope: string;
  effectiveness: number; // 0-1
}

export interface TaintPath {
  source: TaintSource;
  sink: TaintSink;
  path: string[];
  confidence: number;
  sanitizers: Sanitizer[];
  isInterProcedural: boolean;
  callStack: string[];
}

export interface TaintResult {
  isTainted: boolean;
  sources: TaintSource[];
  sinks: TaintSink[];
  paths: TaintPath[];
  confidence: number;
  interProceduralPaths: TaintPath[];
}

// Enhanced source patterns (more comprehensive than baseline)
const ENHANCED_SOURCE_PATTERNS: Array<{
  type: TaintSource['type'];
  patterns: RegExp[];
  confidence: number;
}> = [
  {
    type: 'user_input',
    patterns: [
      /\binput\s*\(/gi,
      /\breadline\s*\(/gi,
      /\bgets\s*\(/gi,
      /\braw_input\s*\(/gi,
      /request\.body/gi,
      /request\.query/gi,
      /request\.params/gi,
      /request\.form/gi,
      /\$\_(GET|POST|REQUEST|COOKIE|FILES)\b/gi,
      /ctx\.request\.body/gi,
      /event\.body/gi,
      /event\.query/gi,
    ],
    confidence: 0.95
  },
  {
    type: 'network',
    patterns: [
      /http\.get\s*\(/gi,
      /http\.post\s*\(/gi,
      /https?\.(get|post|request)\s*\(/gi,
      /fetch\s*\(/gi,
      /axios\.(get|post|http)/gi,
      /requests?\.(get|post)\s*\(/gi,
      /urllib\.(request|urlopen)/gi,
      /rpc_(call|send)\s*\(/gi,
    ],
    confidence: 0.9
  },
  {
    type: 'file_io',
    patterns: [
      /\breadFile\s*\(/gi,
      /\breadFileSync\s*\(/gi,
      /fopen\s*\(/gi,
      /stdin/gi,
      /open\s*\([^)]*['"]r/gi,
      /file_get_contents\s*\(/gi,
    ],
    confidence: 0.85
  },
  {
    type: 'env',
    patterns: [
      /process\.env/gi,
      /os\.environ/gi,
      /getenv\s*\(/gi,
      /putenv\s*\(/gi,
      /env\[['"`]/gi,
    ],
    confidence: 0.9
  },
  {
    type: 'db',
    patterns: [
      /\.query\s*\(/gi,
      /\.execute\s*\(/gi,
      /\.find\s*\(/gi,
      /\.findOne\s*\(/gi,
      /\.fetchall\s*\(/gi,
      /cursor\.execute\s*\(/gi,
    ],
    confidence: 0.8
  },
  {
    type: 'cookie',
    patterns: [
      /request\.cookies/gi,
      /cookie\.parse/gi,
      /req\.cookies/gi,
      /\$_COOKIE/gi,
    ],
    confidence: 0.85
  },
  {
    type: 'header',
    patterns: [
      /request\.headers/gi,
      /getallheaders\s*\(/gi,
      /req\.getHeader/gi,
      /x-forwarded-for/gi,
    ],
    confidence: 0.7
  }
];

// Enhanced sink patterns
const ENHANCED_SINK_PATTERNS: Array<{
  type: TaintSink['type'];
  patterns: RegExp[];
  confidence: number;
  cwe: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}> = [
  {
    type: 'sql',
    patterns: [
      /\.query\s*\(/gi,
      /\.execute\s*\(/gi,
      /\.exec\s*\(/gi,
      /SELECT\s+/gi,
      /INSERT\s+INTO/gi,
      /UPDATE\s+\w+\s+SET/gi,
      /DELETE\s+FROM/gi,
      /executeQuery\s*\(/gi,
      /raw\s*\(\s*\)/gi,
      /db\.raw\s*\(/gi,
    ],
    confidence: 0.95,
    cwe: 'CWE-89',
    severity: 'CRITICAL'
  },
  {
    type: 'shell',
    patterns: [
      /exec\s*\(/gi,
      /execSync\s*\(/gi,
      /spawn\s*\(/gi,
      /spawnSync\s*\(/gi,
      /system\s*\(/gi,
      /shell_exec\s*\(/gi,
      /popen\s*\(/gi,
      /proc_open\s*\(/gi,
      /os\.system\s*\(/gi,
      /os\.popen\s*\(/gi,
      /subprocess\.(call|run|Popen)/gi,
    ],
    confidence: 0.95,
    cwe: 'CWE-78',
    severity: 'CRITICAL'
  },
  {
    type: 'eval',
    patterns: [
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /setTimeout\s*\([^,]+,\s*0\s*\)/gi,
      /setInterval\s*\([^,]+,\s*0\s*\)/gi,
      /execScript\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /compile\s*\(/gi,
    ],
    confidence: 0.95,
    cwe: 'CWE-95',
    severity: 'CRITICAL'
  },
  {
    type: 'file_write',
    patterns: [
      /writeFile\s*\(/gi,
      /writeFileSync\s*\(/gi,
      /appendFile\s*\(/gi,
      /fwrite\s*\(/gi,
      /file_put_contents\s*\(/gi,
      /open\s*\([^)]*['"]w/gi,
    ],
    confidence: 0.9,
    cwe: 'CWE-73',
    severity: 'HIGH'
  },
  {
    type: 'file_read',
    patterns: [
      /readFile\s*\(/gi,
      /include\s*\(/gi,
      /require\s*\(/gi,
      /import\s*\(/gi,
      /open\s*\([^)]*['"]r/gi,
    ],
    confidence: 0.75,
    cwe: 'CWE-22',
    severity: 'MEDIUM'
  },
  {
    type: 'network_send',
    patterns: [
      /http\.post\s*\(/gi,
      /http\.put\s*\(/gi,
      /requests?\.post\s*\(/gi,
      /requests?\.put\s*\(/gi,
      /fetch\s*\(/gi,
      /urllib\.request\.urlopen\s*\(/gi,
    ],
    confidence: 0.8,
    cwe: 'CWE-20',
    severity: 'MEDIUM'
  },
  {
    type: 'deserialization',
    patterns: [
      /unserialize\s*\(/gi,
      /pickle\.loads\s*\(/gi,
      /json\.loads\s*\(/gi,
      /yaml\.load\s*\(/gi,
      /marshal\.loads\s*\(/gi,
      /ObjectInputStream/gi,
    ],
    confidence: 0.9,
    cwe: 'CWE-502',
    severity: 'HIGH'
  },
  {
    type: 'dynamic_code',
    patterns: [
      /compile\s*\(/gi,
      /py_compile\s*\(/gi,
      /runtime\.exec\s*\(/gi,
      /ScriptEngine/gi,
    ],
    confidence: 0.85,
    cwe: 'CWE-94',
    severity: 'HIGH'
  }
];

// Sanitizer patterns
const SANITIZER_PATTERNS: Array<{
  type: Sanitizer['type'];
  patterns: RegExp[];
  effectiveness: number;
}> = [
  {
    type: 'encoding',
    patterns: [
      /htmlspecialchars\s*\(/gi,
      /htmlentities\s*\(/gi,
      /urlencode\s*\(/gi,
      /escape\s*\(/gi,
      /encodeURI\s*\(/gi,
      /encodeURIComponent\s*\(/gi,
      /entityencode/gi,
      /escapeHtml/gi,
    ],
    effectiveness: 0.9
  },
  {
    type: 'validation',
    patterns: [
      /validate\s*\(/gi,
      /isValid[^\s]*\(/gi,
      /check\s*\(/gi,
      /sanitize\s*\(/gi,
      /assert\s*\(/gi,
      /preg_match\s*\(/gi,
      /matches\s*\(/gi,
      /checkValid/gi,
    ],
    effectiveness: 0.8
  },
  {
    type: 'escaping',
    patterns: [
      /addslashes\s*\(/gi,
      /mysqli_escape_string\s*\(/gi,
      /pg_escape_string\s*\(/gi,
      /sqlite_escape_string\s*\(/gi,
      /real_escape_string\s*\(/gi,
    ],
    effectiveness: 0.85
  },
  {
    type: 'param_check',
    patterns: [
      /isset\s*\(/gi,
      /!empty\s*\(/gi,
      /!is_null\s*\(/gi,
      /defined\s*\(/gi,
      /array_key_exists\s*\(/gi,
    ],
    effectiveness: 0.5
  },
  {
    type: 'type_cast',
    patterns: [
      /intval\s*\(/gi,
      /floatval\s*\(/gi,
      /strval\s*\(/gi,
      /\(int\)\s*/gi,
      /\(float\)\s*/gi,
      /parseInt\s*\(/gi,
      /parseFloat\s*\(/gi,
      /Number\s*\(/gi,
    ],
    effectiveness: 0.7
  }
];

export function detectEnhancedSources(code: string, scope: string): TaintSource[] {
  const sources: TaintSource[] = [];
  let sourceId = 0;
  
  for (const sourceGroup of ENHANCED_SOURCE_PATTERNS) {
    for (const pattern of sourceGroup.patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = code.substring(0, match.index).split('\n').length;
          sources.push({
            id: `src_${sourceId++}`,
            type: sourceGroup.type,
            name: match[0],
            line,
            scope,
            confidence: sourceGroup.confidence
          });
        }
      }
    }
  }
  
  return sources;
}

export function detectEnhancedSinks(code: string, scope: string): TaintSink[] {
  const sinks: TaintSink[] = [];
  let sinkId = 0;
  
  for (const sinkGroup of ENHANCED_SINK_PATTERNS) {
    for (const pattern of sinkGroup.patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = code.substring(0, match.index).split('\n').length;
          sinks.push({
            id: `sink_${sinkId++}`,
            type: sinkGroup.type,
            name: match[0],
            line,
            scope,
            confidence: sinkGroup.confidence
          });
        }
      }
    }
  }
  
  return sinks;
}

export function detectEnhancedSanitizers(code: string, scope: string): Sanitizer[] {
  const sanitizers: Sanitizer[] = [];
  let sanId = 0;
  
  for (const sanGroup of SANITIZER_PATTERNS) {
    for (const pattern of sanGroup.patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = code.substring(0, match.index).split('\n').length;
          sanitizers.push({
            id: `san_${sanId++}`,
            type: sanGroup.type,
            name: match[0],
            line,
            scope,
            effectiveness: sanGroup.effectiveness
          });
        }
      }
    }
  }
  
  return sanitizers;
}

// Inter-procedural taint analysis
export function analyzeTaintInterProcedural(
  code: string,
  scope: string,
  callGraph?: Map<string, string[]>
): TaintResult {
  const sources = detectEnhancedSources(code, scope);
  const sinks = detectEnhancedSinks(code, scope);
  const sanitizers = detectEnhancedSanitizers(code, scope);
  const paths = findTaintPathsWithSanitizers(sources, sinks, sanitizers, scope);
  
  // Find inter-procedural paths if call graph available
  const interProceduralPaths: TaintPath[] = [];
  if (callGraph) {
    for (const path of paths) {
      if (path.path.length > 5) { // Long paths suggest inter-procedural flow
        path.isInterProcedural = true;
        path.callStack = reconstructCallStack(path.path, callGraph);
        interProceduralPaths.push(path);
      }
    }
  }
  
  const avgConfidence = paths.length > 0
    ? paths.reduce((s, p) => s + p.confidence, 0) / paths.length
    : 0;
  
  return {
    isTainted: paths.length > 0,
    sources,
    sinks,
    paths,
    confidence: avgConfidence,
    interProceduralPaths
  };
}

function findTaintPathsWithSanitizers(
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: Sanitizer[],
  scope: string
): TaintPath[] {
  const paths: TaintPath[] = [];
  
  for (const source of sources) {
    for (const sink of sinks) {
      if (source.scope !== sink.scope) continue;
      
      // Find sanitizers between source and sink
      const blockingSans = sanitizers.filter(s =>
        s.scope === source.scope &&
        s.line > source.line &&
        s.line < sink.line
      );
      
      // Calculate effective confidence after sanitizers
      let effectiveConfidence = source.confidence * sink.confidence;
      for (const san of blockingSans) {
        effectiveConfidence *= (1 - san.effectiveness);
      }
      
      // Only report if confidence above threshold
      if (effectiveConfidence > 0.3) {
        const path = reconstructSimplePath(source, sink);
        paths.push({
          source,
          sink,
          path,
          confidence: effectiveConfidence,
          sanitizers: blockingSans,
          isInterProcedural: false,
          callStack: []
        });
      }
    }
  }
  
  return paths;
}

function reconstructSimplePath(source: TaintSource, sink: TaintSink): string[] {
  // Simple linear path assumption
  const path: string[] = [source.id];
  const midPoint = Math.floor((source.line + sink.line) / 2);
  if (midPoint > source.line + 1) {
    path.push(`intermediate_${midPoint}`);
  }
  path.push(sink.id);
  return path;
}

function reconstructCallStack(path: string[], callGraph: Map<string, string[]>): string[] {
  const callStack: string[] = [];
  for (const nodeId of path) {
    if (nodeId.startsWith('func_') || nodeId.startsWith('call_')) {
      callStack.push(nodeId);
    }
  }
  return callStack;
}

// Backward compatibility alias
export function analyzeTaint(code: string, scope: string): TaintResult {
  return analyzeTaintInterProcedural(code, scope);
}

// Get severity for a sink type
export function getSinkSeverity(sinkType: TaintSink['type']): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const map: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = {
    sql: 'CRITICAL',
    shell: 'CRITICAL',
    eval: 'CRITICAL',
    deserialization: 'HIGH',
    dynamic_code: 'HIGH',
    file_write: 'HIGH',
    network_send: 'MEDIUM',
    file_read: 'MEDIUM',
    xxe: 'HIGH'
  };
  return map[sinkType] || 'MEDIUM';
}

// Get CWE for a sink type
export function getSinkCWE(sinkType: TaintSink['type']): string {
  const map: Record<string, string> = {
    sql: 'CWE-89',
    shell: 'CWE-78',
    eval: 'CWE-95',
    file_write: 'CWE-73',
    file_read: 'CWE-22',
    network_send: 'CWE-20',
    deserialization: 'CWE-502',
    dynamic_code: 'CWE-94',
    xxe: 'CWE-611',
    反射: 'CWE-470'
  };
  return map[sinkType] || 'CWE-707';
}
