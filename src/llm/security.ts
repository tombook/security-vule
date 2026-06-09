/**
 * AI security utilities for security-vule's LLM integration.
 *
 * 1. redactSecrets()        — strip API keys, JWTs, private keys before sending to LLM
 * 2. detectPromptInjection() — flag code that contains prompt-injection attempts
 * 3. validateFinding()      — sanity-check LLM output before trust
 * 4. RateLimiter             — token/cost cap to prevent Cost-DoS
 */

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', pattern: /aws_secret_access_key\s*=\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g },
  { name: 'Slack Token', pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Stripe Live Key', pattern: /sk_live_[0-9a-zA-Z]{24}/g },
  { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24}/g },
  { name: 'OpenAI API Key', pattern: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: 'Anthropic API Key', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'Generic JWT', pattern: /eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+/g },
  { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g },
  { name: 'EC Private Key', pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g },
  { name: 'OpenSSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g },
  { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g },
  { name: 'Generic Private Key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: 'Password in URL', pattern: /[a-z]+:\/\/[^/\s:]+:([^@\s]+)@/gi },
  { name: 'Password assignment', pattern: /(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["']([^"']{4,})["']/gi },
];

const REDACTED = '***REDACTED***';

export interface RedactionResult {
  text: string;
  redactions: Array<{ type: string; count: number }>;
}

export function redactSecrets(input: string): RedactionResult {
  let text = input;
  const redactions: Array<{ type: string; count: number }> = [];
  for (const { name, pattern } of SECRET_PATTERNS) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      redactions.push({ type: name, count: matches.length });
      text = text.replace(pattern, REDACTED);
    }
  }
  return { text, redactions };
}

const PROMPT_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: 'low' | 'medium' | 'high' }> = [
  { name: 'ignore previous instructions', pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)/gi, severity: 'high' },
  { name: 'disregard system prompt', pattern: /disregard\s+(?:the\s+)?(?:system|above|previous)\s+(?:prompt|instructions?)/gi, severity: 'high' },
  { name: 'you are now', pattern: /you\s+are\s+now\s+(?:a|an)\s+/gi, severity: 'high' },
  { name: 'forget everything', pattern: /forget\s+(?:everything|all)\s+(?:you|above|prior)/gi, severity: 'high' },
  { name: 'no vulnerabilities', pattern: /no\s+vulnerabilities?\s+(?:found|present|exist|detected)/gi, severity: 'medium' },
  { name: 'output only', pattern: /output\s+(?:only|just)\s*[:=]?\s*["']?(?:safe|secure|clean|none)/gi, severity: 'medium' },
  { name: 'system prompt', pattern: /system\s+prompt\s*[:=]/gi, severity: 'medium' },
  { name: 'ignore above', pattern: /ignore\s+(?:the\s+)?above/gi, severity: 'high' },
  { name: 'mark as safe', pattern: /mark\s+(?:this\s+|as\s+)?(?:as\s+)?(?:safe|secure|clean|approved)/gi, severity: 'medium' },
  { name: 'DAN jailbreak', pattern: /\bDAN\b|do\s+anything\s+now/gi, severity: 'high' },
  { name: 'no restrictions', pattern: /no\s+restrictions?|bypass\s+(?:safety|filter)/gi, severity: 'high' },
  { name: 'pretend to', pattern: /pretend\s+(?:to\s+be|you\s+(?:are|have))/gi, severity: 'medium' },
];

export interface InjectionDetection {
  isInjection: boolean;
  matches: Array<{ name: string; severity: 'low' | 'medium' | 'high'; sample: string }>;
  riskScore: number;
}

export function detectPromptInjection(input: string): InjectionDetection {
  const matches: Array<{ name: string; severity: 'low' | 'medium' | 'high'; sample: string }> = [];
  let riskScore = 0;
  for (const { name, pattern, severity } of PROMPT_INJECTION_PATTERNS) {
    const m = input.match(pattern);
    if (m) {
      matches.push({ name, severity, sample: m[0].slice(0, 100) });
      riskScore += severity === 'high' ? 3 : severity === 'medium' ? 2 : 1;
    }
  }
  return { isInjection: matches.length > 0, matches, riskScore };
}

const ALLOWED_TYPES = new Set([
  'SQL Injection',
  'Command Injection',
  'Cross-Site Scripting (XSS)',
  'Path Traversal',
  'File Inclusion',
  'Local File Inclusion',
  'Remote File Inclusion',
  'Local File Inclusion / Remote File Inclusion',
  'Server-Side Request Forgery',
  'Unrestricted File Upload',
  'Cross-Site Request Forgery (CSRF)',
  'Insecure Cryptography',
  'Weak Randomness',
  'Hardcoded Secret',
  'Authentication Bypass',
  'Insecure Deserialization',
  'XML External Entity',
  'LDAP Injection',
  'XPath Injection',
  'Open Redirect',
  'Information Exposure',
  'Code Injection',
]);

const TYPE_NORMALIZE: Record<string, string> = {
  'Local File Inclusion': 'File Inclusion',
  'Remote File Inclusion': 'File Inclusion',
  'Local File Inclusion / Remote File Inclusion': 'File Inclusion',
  'LFI': 'File Inclusion',
  'RFI': 'File Inclusion',
  'Path Traversal / Local File Inclusion': 'File Inclusion',
  'Local File Inclusion (LFI)': 'File Inclusion',
  'Remote File Inclusion (RFI)': 'File Inclusion',
  'SQLi': 'SQL Injection',
  'XSS': 'Cross-Site Scripting (XSS)',
  'Reflected XSS': 'Cross-Site Scripting (XSS)',
  'Stored XSS': 'Cross-Site Scripting (XSS)',
  'DOM XSS': 'Cross-Site Scripting (XSS)',
  'DOM-based XSS': 'Cross-Site Scripting (XSS)',
  'SSRF': 'Server-Side Request Forgery',
  'CSRF': 'Cross-Site Request Forgery (CSRF)',
  'RCE': 'Command Injection',
  'Remote Code Execution': 'Command Injection',
  'OS Command Injection': 'Command Injection',
  'Command Injection (RCE)': 'Command Injection',
  'Directory Traversal': 'Path Traversal',
  'Path Traversal / Directory Traversal': 'Path Traversal',
  'Path/Directory Traversal': 'Path Traversal',
  'Arbitrary File Upload': 'Unrestricted File Upload',
  'Unsafe Deserialization': 'Insecure Deserialization',
  'XXE': 'XML External Entity',
  'Info Disclosure': 'Information Exposure',
  'Information Disclosure': 'Information Exposure',
  'Hardcoded Credential': 'Hardcoded Secret',
  'Hardcoded Password': 'Hardcoded Secret',
  'Dynamic Code Execution': 'Code Injection',
  'Eval Injection': 'Code Injection',
};

const ALLOWED_SEVERITY = new Set(['critical', 'high', 'medium', 'low', 'info']);

export interface ValidatedFinding {
  type: string;
  severity: string;
  line: number;
  description: string;
  remediation: string;
  codeSnippet: string;
  cwe?: string;
  owasp?: string;
  confidence: number;
}

export interface ValidationResult {
  valid: boolean;
  reason?: string;
  finding?: ValidatedFinding;
  riskScore: number;
}

const SUSPICIOUS_OUTPUT_PATTERNS: RegExp[] = [
  /\bignore\s+(?:all\s+)?previous\b/i,
  /\bdisregard\s+(?:the\s+)?system\b/i,
  /\byou\s+are\s+now\s+/i,
  /\bno\s+vulnerabilities?\b/i,
  /\bsafe\s+(?:code|file)\b/i,
  /\<\|.*?\|\>/,
];

export function validateFinding(raw: unknown, sourceCode: string): ValidationResult {
  if (typeof raw !== 'object' || raw === null) {
    return { valid: false, reason: 'not an object', riskScore: 0 };
  }
  const f = raw as Record<string, unknown>;
  const rawType = String(f.type || '');
  let type = TYPE_NORMALIZE[rawType] || rawType;
  if (!ALLOWED_TYPES.has(type)) {
    const lower = rawType.toLowerCase();
    for (const allowed of ALLOWED_TYPES) {
      if (lower.includes(allowed.toLowerCase()) || allowed.toLowerCase().includes(lower)) {
        type = allowed;
        break;
      }
    }
  }
  const severity = String(f.severity || '').toLowerCase();
  const line = Number(f.line || 0);
  const description = String(f.description || '');
  const codeSnippet = String(f.codeSnippet || '');
  const remediation = String(f.remediation || '');
  const confidence = Math.min(1, Math.max(0, Number(f.confidence ?? 0.5)));
  if (!ALLOWED_TYPES.has(type)) {
    return { valid: false, reason: `unknown type: ${type}`, riskScore: 0 };
  }
  if (!ALLOWED_SEVERITY.has(severity)) {
    return { valid: false, reason: `unknown severity: ${severity}`, riskScore: 0 };
  }
  if (line < 0 || line > 100000) {
    return { valid: false, reason: `out-of-range line: ${line}`, riskScore: 0 };
  }
  if (line > 0) {
    const totalLines = sourceCode.split('\n').length;
    if (line > totalLines) {
      return { valid: false, reason: `line ${line} exceeds file length ${totalLines}`, riskScore: 0 };
    }
  }
  let riskScore = 0;
  for (const p of SUSPICIOUS_OUTPUT_PATTERNS) {
    if (p.test(description) || p.test(remediation)) {
      riskScore += 5;
    }
  }
  if (confidence > 0.95 && severity === 'critical') {
    riskScore += 1;
  }
  if (description.length > 0 && description.length < 10) {
    riskScore += 2;
  }
  if (riskScore >= 5) {
    return { valid: false, reason: 'suspicious LLM output (possible prompt injection echo)', riskScore };
  }
  return {
    valid: true,
    finding: {
      type,
      severity,
      line,
      description,
      remediation,
      codeSnippet,
      cwe: f.cwe ? String(f.cwe) : undefined,
      owasp: f.owasp ? String(f.owasp) : undefined,
      confidence,
    },
    riskScore,
  };
}

export class RateLimiter {
  private promptTokens = 0;
  private completionTokens = 0;
  private totalCostUsd = 0;
  private callCount = 0;
  private readonly maxTokens: number;
  private readonly maxCostUsd: number;
  private readonly maxCalls: number;

  constructor(opts: { maxTokens?: number; maxCostUsd?: number; maxCalls?: number } = {}) {
    this.maxTokens = opts.maxTokens ?? 1_000_000;
    this.maxCostUsd = opts.maxCostUsd ?? 5.0;
    this.maxCalls = opts.maxCalls ?? 10_000;
  }

  record(promptTokens: number, completionTokens: number, costUsd: number): void {
    if (this.promptTokens + promptTokens + this.completionTokens + completionTokens > this.maxTokens) {
      throw new Error(`Rate limit exceeded: tokens would be ${this.promptTokens + promptTokens + this.completionTokens + completionTokens} > ${this.maxTokens}`);
    }
    if (this.totalCostUsd + costUsd > this.maxCostUsd) {
      throw new Error(`Rate limit exceeded: cost would be $${(this.totalCostUsd + costUsd).toFixed(2)} > $${this.maxCostUsd}`);
    }
    if (this.callCount + 1 > this.maxCalls) {
      throw new Error(`Rate limit exceeded: calls would be ${this.callCount + 1} > ${this.maxCalls}`);
    }
    this.promptTokens += promptTokens;
    this.completionTokens += completionTokens;
    this.totalCostUsd += costUsd;
    this.callCount += 1;
  }

  stats(): { promptTokens: number; completionTokens: number; totalCostUsd: number; callCount: number } {
    return {
      promptTokens: this.promptTokens,
      completionTokens: this.completionTokens,
      totalCostUsd: this.totalCostUsd,
      callCount: this.callCount,
    };
  }
}

const COST_PER_1K_TOKENS: Record<string, { input: number; output: number }> = {
  'glm-5.1': { input: 0.0001, output: 0.0001 },
  'claude-sonnet-4-5': { input: 0.003, output: 0.015 },
  'gpt-4o': { input: 0.005, output: 0.015 },
  'gpt-4o-mini': { input: 0.00015, output: 0.0006 },
  'deepseek-chat': { input: 0.00014, output: 0.00028 },
};

export function estimateCostUsd(model: string, promptTokens: number, completionTokens: number): number {
  const rates = COST_PER_1K_TOKENS[model] || COST_PER_1K_TOKENS['glm-5.1'];
  return (promptTokens / 1000) * rates.input + (completionTokens / 1000) * rates.output;
}
