/**
 * SKILL.md / Claude Code plugin scanner.
 *
 * Inspired by theinfosecguy/razin and suchithnarayan/ai-skill-scanner.
 *
 * SKILL.md format (YAML frontmatter + Markdown body):
 * ---
 * name: my-skill
 * description: ...
 * allowed-tools: Read, Bash, WebFetch
 * ---
 * # skill body in markdown
 *
 * Detected threats:
 * - Untrusted remote includes (WebFetch with attacker-controlled URL)
 * - Dangerous shell patterns (curl | sh, rm -rf, chmod +x)
 * - Overly permissive allowed-tools (Bash + Write + WebFetch + WebSearch)
 * - Hidden Unicode / prompt-injection markers
 * - Excessive data exfiltration (curl POST with file contents)
 * - Typosquatted commands (curl disguised as wget, etc.)
 */

import { redactSecrets } from '../llm/security.js';
import { detectPromptInjection } from '../llm/security.js';

export interface SkillFrontmatter {
  name: string;
  description: string;
  'allowed-tools'?: string;
  [key: string]: string | undefined;
}

export interface SkillFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category:
    | 'tool-misuse'
    | 'shell-injection'
    | 'data-exfil'
    | 'injection'
    | 'secret-leak'
    | 'overreach';
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

export interface SkillScanResult {
  filePath: string;
  frontmatter: SkillFrontmatter | null;
  bodyLength: number;
  findings: SkillFinding[];
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

export function parseSkill(content: string): {
  frontmatter: SkillFrontmatter | null;
  body: string;
} {
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!fmMatch) return { frontmatter: null, body: content };

  const fm: Record<string, string> = {};
  const lines = (fmMatch[1] ?? '').split('\n');
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line
      .slice(idx + 1)
      .trim()
      .replace(/^["']|["']$/g, '');
    fm[k] = v;
  }

  return { frontmatter: fm as SkillFrontmatter, body: fmMatch[2] ?? '' };
}

const TOOL_PERMISSIONS: Record<string, number> = {
  Read: 1,
  Glob: 1,
  Grep: 1,
  Bash: 3,
  Edit: 2,
  Write: 3,
  NotebookEdit: 2,
  WebFetch: 4,
  WebSearch: 3,
  Task: 5,
  Agent: 5,
};

const DANGEROUS_PATTERNS: Array<{
  id: string;
  category: SkillFinding['category'];
  severity: SkillFinding['severity'];
  pattern: RegExp;
  description: string;
  remediation: string;
}> = [
  {
    id: 'curl-pipe-sh',
    category: 'shell-injection',
    severity: 'critical',
    pattern: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|sudo|zsh|fish)\b/gi,
    description: 'Remote code execution: pipe remote script directly to shell',
    remediation: 'Download to file first, verify checksum, then execute',
  },
  {
    id: 'rm-rf-root',
    category: 'shell-injection',
    severity: 'critical',
    pattern: /\brm\s+(?:-\w*r\w*\s+)*\/\s*(?:\*|\.\s*\*)?/gi,
    description: 'Recursive delete of root filesystem',
    remediation: 'Restrict to specific paths; require user confirmation',
  },
  {
    id: 'chmod-exec',
    category: 'shell-injection',
    severity: 'high',
    pattern: /\bchmod\s+\+x\s+[^\s;|&;]+\s*(?:&&|\|\||;)/gi,
    description: 'Execute downloaded file immediately after chmod',
    remediation: 'Never auto-execute downloaded files; require explicit user approval',
  },
  {
    id: 'curl-post-data',
    category: 'data-exfil',
    severity: 'high',
    pattern: /\b(?:curl|wget)\b[^|\n]*--data[^|\n]*@/gi,
    description: 'Upload file contents to remote server (potential data exfiltration)',
    remediation: 'Whitelist allowed upload destinations; redact secrets',
  },
  {
    id: 'remote-webfetch',
    category: 'tool-misuse',
    severity: 'medium',
    pattern:
      /WebFetch.*https?:\/\/(?!github\.com\/anthropics|raw\.githubusercontent\.com\/anthropics)/gi,
    description: 'WebFetch from non-Anthropic-verified domain',
    remediation: 'Restrict WebFetch to known-safe allowlist',
  },
  {
    id: 'eval-backticks',
    category: 'shell-injection',
    severity: 'critical',
    pattern: /`[^`]*\$\([^)]*\)[^`]*`|\beval\s*\(/gi,
    description: 'Dynamic code evaluation (shell or JS)',
    remediation: 'Replace with static logic or sandboxed evaluator',
  },
  {
    id: 'base64-decode',
    category: 'shell-injection',
    severity: 'high',
    pattern: /\bbase64\s+-d\b[^|\n]*\|\s*(?:sh|bash)/gi,
    description: 'Pipe base64-decoded content to shell (obfuscated RCE)',
    remediation: 'Decode to inspect first, never pipe to shell',
  },
  {
    id: 'sudo-no-prompt',
    category: 'tool-misuse',
    severity: 'high',
    pattern: /\bsudo\s+(?!-k)[^|\n]*/gi,
    description: 'Sudo without -k flag (caches credentials)',
    remediation: 'Use sudo -k to invalidate cached credentials; require user prompt',
  },
  {
    id: 'ssh-injection',
    category: 'shell-injection',
    severity: 'high',
    pattern: /\bssh[^|\n]*-o\s+StrictHostKeyChecking=no/gi,
    description: 'SSH with StrictHostKeyChecking=no (MITM vulnerability)',
    remediation: 'Always verify host keys',
  },
  {
    id: 'nc-listen',
    category: 'tool-misuse',
    severity: 'medium',
    pattern: /\bnc\s+(?:-l\s+|--listen)/gi,
    description: 'netcat listening mode (potential reverse shell)',
    remediation: 'Avoid netcat listening; use authenticated channels',
  },
];

export function scanSkill(filePath: string, content: string): SkillScanResult {
  const { frontmatter, body } = parseSkill(content);

  const lines = content.split('\n');
  const findings: SkillFinding[] = [];

  for (const rule of DANGEROUS_PATTERNS) {
    rule.pattern.lastIndex = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (rule.pattern.test(line)) {
        rule.pattern.lastIndex = 0;
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: rule.category,
          line: i + 1,
          snippet: line.trim().slice(0, 160),
          description: rule.description,
          remediation: rule.remediation,
        });
      }
    }
  }

  if (frontmatter?.['allowed-tools']) {
    const tools = frontmatter['allowed-tools'].split(/[,\s]+/).filter(Boolean);
    const permScore = tools.reduce((s, t) => s + (TOOL_PERMISSIONS[t] ?? 2), 0);
    if (permScore >= 8) {
      findings.push({
        id: 'excessive-tool-permissions',
        severity: 'high',
        category: 'overreach',
        line: 0,
        snippet: frontmatter['allowed-tools'],
        description: `allowed-tools grants ${permScore} permission points (Bash+Write+WebFetch+Task combination)`,
        remediation: 'Apply least-privilege: split into separate skills, narrow each',
      });
    }
    if (tools.includes('Bash') && tools.includes('WebFetch')) {
      findings.push({
        id: 'bash-plus-webfetch',
        severity: 'medium',
        category: 'overreach',
        line: 0,
        snippet: frontmatter['allowed-tools'],
        description: 'Bash + WebFetch combination can fetch + execute arbitrary code',
        remediation: 'Do not combine remote fetch and shell execution in same skill',
      });
    }
  }

  if (body.length > 0) {
    const inj = detectPromptInjection(body);
    if (inj.isInjection && inj.riskScore >= 3) {
      findings.push({
        id: 'prompt-injection-body',
        severity: 'high',
        category: 'injection',
        line: 0,
        snippet: body.slice(0, 160),
        description: `Prompt injection detected (riskScore=${inj.riskScore})`,
        remediation: 'Remove adversarial content; use trusted sources only',
      });
    }

    const red = redactSecrets(body);
    for (const r of red.redactions) {
      findings.push({
        id: 'secret-in-body',
        severity: 'high',
        category: 'secret-leak',
        line: 0,
        snippet: `${r.type} × ${r.count}`,
        description: `${r.count} secret(s) of type "${r.type}" present in skill body`,
        remediation: 'Use environment variables or secret manager; never inline secrets',
      });
    }
  }

  if (body.includes('\u200B') || body.includes('\u200C') || body.includes('\u200D')) {
    findings.push({
      id: 'hidden-unicode',
      severity: 'high',
      category: 'injection',
      line: 0,
      snippet: 'zero-width characters detected',
      description:
        'Hidden Unicode (zero-width) characters in body — possible prompt injection vector',
      remediation: 'Strip zero-width chars; sanitize input',
    });
  }

  const score = computeRiskScore(findings);
  return {
    filePath,
    frontmatter,
    bodyLength: body.length,
    findings,
    riskScore: score,
    riskLevel: scoreToLevel(score),
  };
}

function computeRiskScore(findings: SkillFinding[]): number {
  const weights: Record<SkillFinding['severity'], number> = {
    critical: 1.0,
    high: 0.6,
    medium: 0.3,
    low: 0.1,
    info: 0.0,
  };
  const raw = findings.reduce((s, f) => s + weights[f.severity], 0);
  return Math.min(1, raw);
}

function scoreToLevel(score: number): SkillScanResult['riskLevel'] {
  if (score >= 0.85) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.3) return 'medium';
  if (score > 0) return 'low';
  return 'safe';
}
