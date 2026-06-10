/**
 * OWASP Agentic AI Top 10 (2026) mapping.
 *
 * Source: OWASP GenAI Security Project — Agentic Security Initiative (ASI)
 *   https://genai.owasp.org/agentic-ai/
 *
 * Each entry maps the agentic-specific threat to:
 *  - security-vule dimensions that detect it
 *  - detection patterns (regex / AST heuristics)
 *  - severity
 *  - remediation guidance
 *
 * Use `evaluateOwaspAgenticTop10(source, language)` to scan any source string
 * and return a list of matches keyed by ASI01..ASI10.
 */

export type OwaspAgenticId =
  | 'ASI01'
  | 'ASI02'
  | 'ASI03'
  | 'ASI04'
  | 'ASI05'
  | 'ASI06'
  | 'ASI07'
  | 'ASI08'
  | 'ASI09'
  | 'ASI10';

export type OwaspSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface OwaspAgenticEntry {
  id: OwaspAgenticId;
  title: string;
  description: string;
  severity: OwaspSeverity;
  dimensions: string[];
  patterns: Array<{ name: string; regex: RegExp; weight: number }>;
  remediation: string;
  cwe: string;
  cveExample?: string;
}

export interface OwaspAgenticMatch {
  entry: OwaspAgenticEntry;
  matches: Array<{ pattern: string; line: number; snippet: string; weight: number }>;
  totalScore: number;
  normalizedScore: number;
}

export const OWASP_AGENTIC_TOP_10: Record<OwaspAgenticId, OwaspAgenticEntry> = {
  ASI01: {
    id: 'ASI01',
    title: 'Agent Goal Hijack / Prompt Injection',
    description:
      'Attacker manipulates agent goals or system prompts via untrusted input (tools, RAG, user messages) to subvert the intended objective.',
    severity: 'critical',
    dimensions: ['gravity', 'kepler', 'information'],
    patterns: [
      {
        name: 'system-prompt-override',
        regex: /ignore\s+(previous|all|above)\s+(instructions?|prompts?)/gi,
        weight: 1.0,
      },
      {
        name: 'role-injection',
        regex: /you\s+are\s+(now|actually)\s+(a|an)\s+/gi,
        weight: 0.8,
      },
      {
        name: 'jailbreak-prefix',
        regex: /developer\s+mode|dan\s+mode|jailbreak/gi,
        weight: 0.9,
      },
    ],
    remediation:
      'Sandbox agent inputs. Use XML isolation tags. Validate prompt with canonical intent. Apply 4-layer defense (system pre-amble + XML + strict JSON schema + post-hoc validateFinding).',
    cwe: 'CWE-1427',
  },
  ASI02: {
    id: 'ASI02',
    title: 'Tool Misuse / Excessive Agency',
    description:
      'Agent invokes tools (Bash, HTTP, file I/O) with unchecked parameters or excessive privileges, leading to RCE/SSRF/data exfiltration.',
    severity: 'critical',
    dimensions: ['gravity', 'tidal', 'gameTheory'],
    patterns: [
      {
        name: 'unbounded-shell-exec-direct',
        regex:
          /(?:^|\s|;)(?:exec|system|shell_exec|passthru|os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*\$?(?:_GET|_POST|_REQUEST|_SERVER|argv|args|input|user|req|param)/gi,
        weight: 1.0,
      },
      {
        name: 'exec-with-variable',
        regex: /(?:exec|system|shell_exec|passthru)\s*\(\s*\$\w+/gi,
        weight: 0.7,
      },
      {
        name: 'unbounded-http-fetch',
        regex:
          /(?:fetch|axios|requests\.(?:get|post|put|delete)|curl_exec|file_get_contents|urllib\.request\.urlopen)\s*\(\s*\$?(?:_GET|_POST|_REQUEST|argv|args|input|user|req|param)/gi,
        weight: 0.9,
      },
      {
        name: 'subprocess-shell-true',
        regex: /subprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True/gi,
        weight: 0.8,
      },
      {
        name: 'write-to-user-controlled-path',
        regex: /(writeFile|saveFile|file_put_contents|open\s*\([^)]*['"]w)/gi,
        weight: 0.5,
      },
    ],
    remediation:
      'Apply least-privilege tool policy. Sandbox tool execution (Docker/firejail). Require human-in-the-loop for sensitive operations (file delete, network egress).',
    cwe: 'CWE-77',
  },
  ASI03: {
    id: 'ASI03',
    title: 'Identity & Privilege Abuse',
    description:
      'Agent inherits or escalates identity/credentials beyond intended scope, leading to unauthorized actions.',
    severity: 'high',
    dimensions: ['gravity', 'darkMatter', 'relativistic'],
    patterns: [
      {
        name: 'hardcoded-credential',
        regex: /(api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"']{8,}["']/gi,
        weight: 1.0,
      },
      {
        name: 'role-assumption',
        regex: /assume[_ ]?role|grant[_ ]?admin|bypass[_ ]?auth/gi,
        weight: 0.9,
      },
    ],
    remediation:
      'Use OAuth scopes with least privilege. Rotate credentials. Apply zero-trust identity model. Audit all credential usage in agent tool chains.',
    cwe: 'CWE-798',
  },
  ASI04: {
    id: 'ASI04',
    title: 'Agentic Supply Chain',
    description:
      'Compromised agent dependencies (MCP servers, plugins, models, datasets) lead to silent backdoors or data exfiltration.',
    severity: 'high',
    dimensions: ['topology', 'transfer', 'information'],
    patterns: [
      {
        name: 'dynamic-require-remote',
        regex: /require\s*\(\s*["']https?:\/\//gi,
        weight: 1.0,
      },
      {
        name: 'eval-of-remote',
        regex: /eval\s*\(\s*(await\s+)?(fetch|requests\.|axios)/gi,
        weight: 1.0,
      },
      {
        name: 'pip-install-without-pin',
        regex: /pip\s+install\s+(?!.*==)([a-zA-Z0-9_-]+)/gi,
        weight: 0.5,
      },
    ],
    remediation:
      'Pin all dependencies with hash verification. Use SBOM (CycloneDX). Verify MCP server identities. Apply dependency review on every PR.',
    cwe: 'CWE-1357',
  },
  ASI05: {
    id: 'ASI05',
    title: 'Unexpected Code Execution (RCE)',
    description:
      'Agent generates and/or executes code (eval, dynamic import, exec) on untrusted input, leading to RCE.',
    severity: 'critical',
    dimensions: ['gravity', 'kepler', 'chaos'],
    patterns: [
      {
        name: 'eval-on-input',
        regex: /eval\s*\(\s*\$?(?:_GET|_POST|_REQUEST|argv|args|input|user|req|param)\b/gi,
        weight: 1.0,
      },
      {
        name: 'eval-with-variable',
        regex: /eval\s*\(\s*\$\w+/gi,
        weight: 0.7,
      },
      {
        name: 'subprocess-input',
        regex:
          /subprocess\.(?:call|run|Popen|check_output)\s*\(\s*[^)]*\b(?:input|args|argv|shell\s*=\s*True)/gi,
        weight: 1.0,
      },
      {
        name: 'pickle-deserialize',
        regex: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)/gi,
        weight: 0.9,
      },
    ],
    remediation:
      'Never eval/exec untrusted input. Use ast.literal_eval, yaml.safe_load, json. Sandboxing via gVisor/Firecracker. Disable shell=True in subprocess.',
    cwe: 'CWE-94',
  },
  ASI06: {
    id: 'ASI06',
    title: 'Memory & Context Poisoning',
    description:
      'Attacker poisons agent long-term memory / RAG context store, causing persistent backdoor behavior across sessions.',
    severity: 'high',
    dimensions: ['entropy', 'darkMatter', 'topology'],
    patterns: [
      {
        name: 'untrusted-rag-source',
        regex: /(load|read|fetch)_?(?:rag|memory|context)\s*\(\s*["']https?:\/\/[^"']+["']/gi,
        weight: 0.8,
      },
      {
        name: 'memory-write-from-input',
        regex: /(memory|context|history)\.append\s*\(\s*[^)]*input/gi,
        weight: 0.7,
      },
    ],
    remediation:
      'Cryptographically sign memory entries. Apply read-only context for untrusted sources. Implement memory integrity verification (Merkle tree / hash chain).',
    cwe: 'CWE-501',
  },
  ASI07: {
    id: 'ASI07',
    title: 'Insecure Inter-Agent Communication',
    description:
      'Agents in a multi-agent system trust messages from peers without authentication, enabling spoofing or injection.',
    severity: 'medium',
    dimensions: ['information', 'relativistic', 'gameTheory'],
    patterns: [
      {
        name: 'unauthenticated-channel',
        regex: /agent\.send\s*\(\s*[^,]+\s*,\s*[^,]+\s*\)\s*(?:#.*no.*auth)?/gi,
        weight: 0.5,
      },
      {
        name: 'shared-memory-no-isolation',
        regex: /shared_(?:state|memory|store)\s*=\s*\{/gi,
        weight: 0.4,
      },
    ],
    remediation:
      'Sign all inter-agent messages (HMAC or mTLS). Use isolated memory per agent. Apply zero-trust: every message authenticated and rate-limited.',
    cwe: 'CWE-345',
  },
  ASI08: {
    id: 'ASI08',
    title: 'Cascading Failures / DoS',
    description:
      'Single agent failure propagates across the agent graph, leading to amplification attacks or system-wide outage.',
    severity: 'medium',
    dimensions: ['chaos', 'nonEquilibrium', 'transfer'],
    patterns: [
      {
        name: 'unbounded-recursion',
        regex: /def\s+\w+\([^)]*\):[^}]*\1\s*\(/g,
        weight: 0.7,
      },
      {
        name: 'no-rate-limit',
        regex: /while\s+True\s*:[\s\n]*.*?(?:call|fetch|invoke|send)/gi,
        weight: 0.6,
      },
    ],
    remediation:
      'Apply circuit breakers. Rate-limit per agent. Cap recursion depth. Use timeout on all tool invocations. Implement blast-radius isolation.',
    cwe: 'CWE-400',
  },
  ASI09: {
    id: 'ASI09',
    title: 'Human-in-the-Loop Bypass',
    description:
      'Agent circumvents human approval flows (e.g., skips confirmation on sensitive actions).',
    severity: 'high',
    dimensions: ['gameTheory', 'information', 'kepler'],
    patterns: [
      {
        name: 'auto-approve-flag',
        regex: /(auto_?approve|skip_?confirm|bypass_?review|force)\s*=\s*True/gi,
        weight: 0.9,
      },
      {
        name: 'silent-tool-call',
        regex: /(tool_?call|execute_?tool|invoke_?action)\s*\([^)]*\)\s*#\s*no.*confirm/gi,
        weight: 0.6,
      },
    ],
    remediation:
      'Enforce HITL for all sensitive actions (delete, send, pay). Audit HITL bypass attempts. Apply policy engine (e.g., OPA) on every tool invocation.',
    cwe: 'CWE-862',
  },
  ASI10: {
    id: 'ASI10',
    title: 'Model & Weights Exfiltration',
    description:
      'Attacker exfiltrates proprietary LLM weights, prompts, or fine-tuning data through agent tool chains.',
    severity: 'high',
    dimensions: ['information', 'darkMatter', 'relativistic'],
    patterns: [
      {
        name: 'weight-dump',
        regex: /(model\.save_pretrained|torch\.save|state_dict\(\)|export_onnx)/gi,
        weight: 0.7,
      },
      {
        name: 'egress-to-unknown-host',
        regex:
          /(requests\.(?:post|put)|urllib\.request\.urlopen)\s*\([^)]*,\s*data\s*=.*?(?<!["'])(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
        weight: 0.8,
      },
    ],
    remediation:
      'Air-gap model weights from agent runtime. Egress allowlist. Watermark model outputs to detect exfiltration. Apply DLP on outbound traffic.',
    cwe: 'CWE-200',
  },
};

export interface OwaspScanResult {
  matches: OwaspAgenticMatch[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  coverage: number;
  language: string;
}

export function evaluateOwaspAgenticTop10(source: string, language: string): OwaspScanResult {
  const lines = source.split('\n');
  const matches: OwaspAgenticMatch[] = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const entry of Object.values(OWASP_AGENTIC_TOP_10)) {
    const entryMatches: OwaspAgenticMatch['matches'] = [];
    let totalScore = 0;

    for (const pat of entry.patterns) {
      pat.regex.lastIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (pat.regex.test(line)) {
          pat.regex.lastIndex = 0;
          entryMatches.push({
            pattern: pat.name,
            line: i + 1,
            snippet: line.trim().slice(0, 120),
            weight: pat.weight,
          });
          totalScore += pat.weight;
        }
      }
    }

    if (entryMatches.length > 0) {
      const normalized = Math.min(1, totalScore / 3);
      matches.push({ entry, matches: entryMatches, totalScore, normalizedScore: normalized });
      counts[entry.severity]++;
    }
  }

  matches.sort((a, b) => b.normalizedScore - a.normalizedScore);
  const totalFindings = matches.reduce((s, m) => s + m.matches.length, 0);

  return {
    matches,
    totalFindings,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    coverage: matches.length / 10,
    language,
  };
}

export function listOwaspAgenticTop10(): OwaspAgenticEntry[] {
  return Object.values(OWASP_AGENTIC_TOP_10);
}
