/**
 * Pattern-Based Detection Rules
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface PatternRule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  source?: string[];
  transform?: string[];
  sink?: string[];
  pattern?: RegExp;
  confidence: number;
  languages?: string[];
  cwe?: string[];
}
export interface PatternMatch {
  rule_id: string;
  name: string;
  severity: Severity;
  confidence: number;
  location: { file?: string; line: number; column?: number };
  code_snippet?: string;
  message: string;
  cwe?: string[];
}
export const ALL_RULES: PatternRule[] = [
  { rule_id: 'INJ-001', name: 'SQL Injection', description: 'Potentially unsafe SQL query', severity: 'critical', source: ['request', 'input', 'user'], sink: ['query', 'execute', 'exec'], confidence: 0.9, languages: ['python', 'javascript', 'java'], cwe: ['CWE-89'] },
  { rule_id: 'INJ-002', name: 'Command Injection', description: 'Potentially unsafe command execution', severity: 'critical', source: ['request', 'input', 'user'], sink: ['exec', 'system', 'popen'], confidence: 0.95, languages: ['python', 'javascript', 'java', 'c', 'go'], cwe: ['CWE-78'] },
  { rule_id: 'INJ-003', name: 'LDAP Injection', description: 'Potentially unsafe LDAP query', severity: 'high', source: ['request', 'input', 'user'], sink: ['search', 'query'], confidence: 0.85, languages: ['python', 'javascript', 'java'], cwe: ['CWE-90'] },
  { rule_id: 'INJ-004', name: 'XML Injection', description: 'Potentially unsafe XML parsing', severity: 'medium', source: ['request', 'input', 'user'], sink: ['parse', 'loadXML'], confidence: 0.8, languages: ['python', 'javascript', 'java'], cwe: ['CWE-91'] },
  { rule_id: 'INJ-005', name: 'XSS', description: 'Potentially unsafe HTML/JS injection', severity: 'high', source: ['request', 'input', 'user'], sink: ['innerHTML', 'eval'], confidence: 0.85, languages: ['javascript', 'typescript'], cwe: ['CWE-79'] },
  { rule_id: 'INJ-006', name: 'Path Traversal', description: 'Potentially unsafe file path', severity: 'high', source: ['request', 'input', 'user', 'filename'], sink: ['open', 'readFile', 'include'], confidence: 0.85, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-22'] },
  { rule_id: 'AUTH-001', name: 'Weak Password Hash', description: 'Using weak hashing algorithm', severity: 'high', pattern: /md5|sha1|des|crypt/i, confidence: 0.9, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-327'] },
  { rule_id: 'AUTH-002', name: 'Hardcoded Credentials', description: 'Hardcoded password or API key', severity: 'critical', pattern: /password|secret|api_key|token/i, confidence: 0.95, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-798'] },
  { rule_id: 'AUTH-003', name: 'Missing Authentication', description: 'Endpoint may be missing auth', severity: 'high', pattern: /@(route|get|post)/i, confidence: 0.75, languages: ['python', 'javascript', 'java'], cwe: ['CWE-306'] },
  { rule_id: 'AUTH-004', name: 'Insecure Session', description: 'Session cookies lack security flags', severity: 'medium', pattern: /cookie/i, confidence: 0.8, languages: ['javascript', 'typescript'], cwe: ['CWE-614'] },
  { rule_id: 'AUTH-005', name: 'JWT Without Verification', description: 'JWT without signature verification', severity: 'critical', pattern: /jwt/i, confidence: 0.85, languages: ['javascript', 'typescript', 'python'], cwe: ['CWE-347'] },
  { rule_id: 'CRYPTO-001', name: 'Weak Crypto', description: 'Using weak cryptographic algorithm', severity: 'high', pattern: /md4|md5|sha1|des|rc4/i, confidence: 0.95, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-327'] },
  { rule_id: 'CRYPTO-002', name: 'Insecure Random', description: 'Using Math.random for security', severity: 'high', pattern: /Math/i, confidence: 0.9, languages: ['javascript', 'typescript'], cwe: ['CWE-338'] },
  { rule_id: 'CRYPTO-003', name: 'Hardcoded IV', description: 'Hardcoded IV or nonce', severity: 'high', pattern: /iv|nonce|seed/i, confidence: 0.85, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-329'] },
  { rule_id: 'CRYPTO-004', name: 'ECB Mode', description: 'Using ECB mode', severity: 'medium', pattern: /AES|ECB/i, confidence: 0.9, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-696'] },
  { rule_id: 'RACE-001', name: 'TOCTOU', description: 'Time-of-check-time-of-use race', severity: 'high', pattern: /stat|access|isFile/i, confidence: 0.85, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-367'] },
  { rule_id: 'RACE-002', name: 'Concurrent Modification', description: 'Shared resource without sync', severity: 'medium', pattern: /shared|global|static/i, confidence: 0.7, languages: ['python', 'javascript', 'java', 'c'], cwe: ['CWE-665'] },
  { rule_id: 'MEM-001', name: 'Buffer Overflow', description: 'Potentially unsafe buffer', severity: 'critical', pattern: /strcpy|sprintf|gets/i, confidence: 0.95, languages: ['c', 'c++'], cwe: ['CWE-119'] },
  { rule_id: 'MEM-002', name: 'Use After Free', description: 'Memory accessed after free', severity: 'critical', pattern: /free/i, confidence: 0.9, languages: ['c', 'c++'], cwe: ['CWE-416'] },
  { rule_id: 'MEM-003', name: 'Null Pointer', description: 'Potential null pointer', severity: 'high', pattern: /null/i, confidence: 0.8, languages: ['c', 'c++', 'java'], cwe: ['CWE-476'] },
  { rule_id: 'MEM-004', name: 'Uninitialized Memory', description: 'Using uninitialized variable', severity: 'medium', pattern: /uninitialized/i, confidence: 0.7, languages: ['c', 'c++'], cwe: ['CWE-457'] },
  { rule_id: 'MEM-005', name: 'Integer Overflow', description: 'Potential integer overflow', severity: 'high', pattern: /malloc/i, confidence: 0.85, languages: ['c', 'c++'], cwe: ['CWE-190'] }
];
export function detectPattern(code: string, filePath?: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const lines = code.split('\n');
  for (const rule of ALL_RULES) {
    if (!rule.pattern) continue;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = rule.pattern.exec(line);
      if (match) {
        matches.push({
          rule_id: rule.rule_id,
          name: rule.name,
          severity: rule.severity,
          confidence: rule.confidence,
          location: { file: filePath, line: i + 1, column: match.index },
          code_snippet: line.trim(),
          message: rule.name + ': ' + rule.description,
          cwe: rule.cwe
        });
      }
    }
  }
  return matches;
}
export function getRulesByCategory(category: string): PatternRule[] {
  const prefix = category === 'injection' ? 'INJ' : category === 'auth' ? 'AUTH' : category === 'crypto' ? 'CRYPTO' : category === 'race' ? 'RACE' : 'MEM';
  return ALL_RULES.filter(r => r.rule_id.startsWith(prefix));
}
export function getRulesBySeverity(severity: Severity): PatternRule[] {
  return ALL_RULES.filter(r => r.severity === severity);
}
export function validateRule(rule: PatternRule): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!rule.rule_id) errors.push('Missing rule_id');
  if (!rule.name) errors.push('Missing name');
  if (!rule.description) errors.push('Missing description');
  if (rule.confidence < 0 || rule.confidence > 1) errors.push('Confidence must be 0-1');
  if (!rule.pattern && !rule.source && !rule.sink) errors.push('Rule needs pattern or source/sink');
  return { valid: errors.length === 0, errors };
}