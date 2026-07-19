/**
 * Line-Level Vulnerability Locator
 *
 * Downgrades function-level detections to precise line ranges by:
 * 1. Keyword scoring — dangerous API names near the detection
 * 2. Taint sink matching — source→sink data flow lines
 * 3. Context window — lines around the match weighted by relevance
 *
 * Inspired by LineVul (ICSE 2023) line-level prediction approach.
 */

export interface LineLocation {
  file: string;
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  confidence: number;
  reason: string;
}

export interface FunctionDetection {
  ruleId: string;
  name: string;
  severity: string;
  confidence: number;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  cwe?: string[];
  message: string;
}

export interface LineLocatorConfig {
  contextWindow: number;
  keywordBoost: number;
  sinkPatterns: Record<string, string[]>;
}

const DEFAULT_CONFIG: LineLocatorConfig = {
  contextWindow: 3,
  keywordBoost: 0.2,
  sinkPatterns: {
    'INJ-001': ['query', 'execute', 'exec', 'raw', 'sql', 'cursor', 'prepare'],
    'INJ-002': ['exec', 'system', 'popen', 'spawn', 'execSync', 'execFile', 'shell'],
    'INJ-005': ['innerHTML', 'outerHTML', 'document.write', 'eval', 'Function'],
    'INJ-006': ['open', 'readFile', 'writeFile', 'include', 'require', 'fopen', 'createReadStream'],
    'AUTH-002': ['password', 'secret', 'api_key', 'token', 'credential', 'private_key'],
    'AUTH-005': ['jwt', 'verify', 'decode', 'sign', 'JsonWebToken'],
    'CRYPTO-001': ['md5', 'sha1', 'des', 'rc4', 'createCipher', 'createHash'],
    'CRYPTO-002': ['Math.random', 'random'],
    'MEM-001': ['strcpy', 'sprintf', 'gets', 'strcat', 'scanf'],
    'MEM-002': ['free', 'delete', 'realloc'],
  },
};

export class LineLocator {
  private config: LineLocatorConfig;

  constructor(config?: Partial<LineLocatorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  locate(detection: FunctionDetection, code: string, filePath?: string): LineLocation | null {
    const lines = code.split('\n');
    const startLine = detection.startLine ?? 1;
    const endLine = detection.endLine ?? lines.length;

    const funcLines = lines.slice(startLine - 1, endLine);
    if (funcLines.length === 0) return null;

    const sinkKeywords = this.config.sinkPatterns[detection.ruleId] ?? this.inferKeywords(detection);

    const scoredLines: Array<{ line: number; score: number; reason: string }> = [];

    for (let i = 0; i < funcLines.length; i++) {
      const lineNum = startLine + i;
      const line = funcLines[i];
      let score = 0;
      const reasons: string[] = [];

      for (const keyword of sinkKeywords) {
        const idx = line.toLowerCase().indexOf(keyword.toLowerCase());
        if (idx >= 0) {
          score += this.config.keywordBoost;
          reasons.push(`keyword:${keyword}`);
        }
      }

      const sourcePatterns = /request|input|user|params|query|body|formData|argv|args/i;
      if (sourcePatterns.test(line)) {
        score += 0.1;
        reasons.push('source-pattern');
      }

      const assignmentMatch = line.match(/(\w+)\s*[=+]=\s*(.*)/);
      if (assignmentMatch) {
        const rhs = assignmentMatch[2];
        for (const keyword of sinkKeywords) {
          if (rhs.toLowerCase().includes(keyword.toLowerCase())) {
            score += 0.15;
            reasons.push(`tainted-assign:${keyword}`);
          }
        }
      }

      if (score > 0) {
        scoredLines.push({ line: lineNum, score, reason: reasons.join(', ') });
      }
    }

    if (scoredLines.length === 0) {
      const bestGuess = this.guessByPattern(funcLines, detection, startLine);
      if (bestGuess) return bestGuess;
      return {
        file: filePath ?? detection.filePath ?? '',
        startLine,
        endLine: Math.min(startLine + 2, endLine),
        confidence: detection.confidence * 0.5,
        reason: 'function-level (no precise line found)',
      };
    }

    scoredLines.sort((a, b) => b.score - a.score);
    const best = scoredLines[0];
    const contextStart = Math.max(startLine, best.line - this.config.contextWindow);
    const contextEnd = Math.min(endLine, best.line + this.config.contextWindow);

    return {
      file: filePath ?? detection.filePath ?? '',
      startLine: contextStart,
      endLine: contextEnd,
      confidence: Math.min(detection.confidence + best.score, 1),
      reason: best.reason,
    };
  }

  locateBatch(detections: FunctionDetection[], code: string, filePath?: string): Array<FunctionDetection & { lineLocation?: LineLocation }> {
    return detections.map(d => ({
      ...d,
      lineLocation: this.locate(d, code, filePath),
    }));
  }

  private inferKeywords(detection: FunctionDetection): string[] {
    const nameLower = detection.name.toLowerCase();
    const keywords: string[] = [];

    if (nameLower.includes('sql')) keywords.push('query', 'execute', 'sql');
    if (nameLower.includes('command') || nameLower.includes('cmd')) keywords.push('exec', 'system', 'spawn');
    if (nameLower.includes('xss') || nameLower.includes('script')) keywords.push('innerHTML', 'eval', 'document.write');
    if (nameLower.includes('path') || nameLower.includes('traversal')) keywords.push('open', 'read', 'write', 'include');
    if (nameLower.includes('password') || nameLower.includes('credential')) keywords.push('password', 'secret', 'token');
    if (nameLower.includes('crypto') || nameLower.includes('hash')) keywords.push('md5', 'sha1', 'encrypt', 'hash');
    if (nameLower.includes('buffer') || nameLower.includes('overflow')) keywords.push('strcpy', 'sprintf', 'malloc');
    if (keywords.length === 0) keywords.push('unsafe', 'dangerous', 'vulnerable');

    return keywords;
  }

  private guessByPattern(
    funcLines: string[],
    detection: FunctionDetection,
    startLine: number,
  ): LineLocation | null {
    for (let i = 0; i < funcLines.length; i++) {
      const line = funcLines[i];
      if (detection.cwe?.some(c => c.includes('89')) && /\b(query|execute|exec|sql)\b/i.test(line)) {
        return {
          file: detection.filePath ?? '',
          startLine: startLine + i,
          endLine: startLine + i,
          confidence: detection.confidence * 0.7,
          reason: 'pattern-matched-sink',
        };
      }
      if (detection.cwe?.some(c => c.includes('78')) && /\b(exec|system|spawn|popen)\b/i.test(line)) {
        return {
          file: detection.filePath ?? '',
          startLine: startLine + i,
          endLine: startLine + i,
          confidence: detection.confidence * 0.7,
          reason: 'pattern-matched-sink',
        };
      }
    }
    return null;
  }
}

export function locateLines(
  detections: FunctionDetection[],
  code: string,
  filePath?: string,
): Array<FunctionDetection & { lineLocation?: LineLocation }> {
  const locator = new LineLocator();
  return locator.locateBatch(detections, code, filePath);
}
