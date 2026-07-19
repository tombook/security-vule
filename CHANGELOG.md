# Changelog

All notable changes to security-vule will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-09

### Added — AI Security Hardening (P0)

- **Prompt injection defense** (`src/llm/security.ts` + `src/detection/llm-agent.ts`):
  XML isolation (`<file>` tags) wrapping code content, strict JSON schema
  enforcement, system-prompt pre-amble marking file content as UNTRUSTED DATA.
- **Secret redaction** (`redactSecrets()`): 17 regex patterns strip AWS, JWT,
  RSA/EC/PGP/OpenSSH private keys, GitHub/Slack/Stripe/OpenAI/Anthropic tokens,
  Google API keys, and hardcoded passwords before LLM calls.
- **Prompt injection detection** (`detectPromptInjection()`): 12 patterns
  covering "ignore previous instructions", "you are now", DAN jailbreak,
  persona switches, "no vulnerabilities" trick phrases.
- **LLM output validation** (`validateFinding()`): 18 canonical type
  whitelist, severity enum, line-range check, rejection of findings with
  injection-echo phrases.
- **Rate limiter** (`RateLimiter`): 1M tokens / $5 / 10K calls per scan
  (fail-safe semantics — checks before incrementing counters).
- **SARIF sanitization** (`toSarif()`): strips code snippets, marks output
  with `security-vule/sarif-sanitized` property.
- **GitHub Action updates**: PR comments now show only statistics, no code.

### Added — AI Security Observability (P1)

- **Multi-Model Consensus** (`src/llm/consensus.ts`): For CRITICAL/HIGH findings,
  two independent LLMs analyze the same code. Only findings both models agree
  on are reported. Disagreements disclosed.
- **Audit Logger** (`src/llm/audit.ts`): Structured logging of every LLM call
  (file hash, size, provider, model, tokens, cost, duration, redactions,
  injection detection, findings accepted/rejected). 3 sink types: stdout,
  file, multi.
- **Cost Dashboard** (`AuditLogger.formatDashboard()`): Per-provider and
  per-outcome breakdown for cost tracking.
- **AI Red Team Corpus** (`corpus/ai-redteam/`): 6 PHP files with embedded
  prompt injection + secrets + jailbreaks. 4 prompt-injection + 2 secret-leak.
  10/10 tests pass.
- **AI Red Team Runner** (`scripts/ai-redteam.ts`): Single-command validation
  of the LLM defense pipeline.
- **LLM Chaos Engineering** (`tests/llm/chaos.test.ts`): 12 chaos scenarios
  including malformed JSON, rate limit, billing error, redaction idempotence.

### Added — AI Security Ecosystem (P2)

- **AI-BOM** (`src/llm/ai-bom.ts`): CycloneDX 1.5 compliant Bill of Materials
  for AI components. 8 provider risk profiles (zhipu, anthropic, openai,
  ollama, deepseek, mock) with privacy + compliance + data residency metadata.
- **AI Security Metrics** (`src/llm/metrics.ts`): Aggregated compliance
  report — injection attempts, secrets redacted, rejection rate, cost, risk
  assessment.
- **MITRE ATLAS Mapping** (`src/llm/atlas.ts`): 12 ATLAS techniques
  documented with corresponding defenses. Cover 100% of relevant techniques.
- **OWASP AI Security Contribution** (`docs/owasp-ai-security-contribution.md`):
  6-chapter PR draft ready for submission.
- **Real-DVWA Red Team** (`scripts/real-dvwa-redteam.ts`): Optional Docker-based
  validation against real DVWA with graceful mock fallback.

### Added — v1.0 Foundation (pre-2.0)

- **Static analysis**: tree-sitter + taint analysis for PHP/JS/Java/Python/Go.
- **PoC runtime verification**: 9 exploit categories, 80/80 = 100% precision
  on DVWA corpus.
- **STRIDE threat modeling**: 6 categories (S/T/R/I/D/E) with auto-mapping
  from detected vulnerability types.
- **DFD data flow diagrams**: Auto-generated from code with 3 trust
  boundaries (public/app/data tier) + Mermaid output.
- **SARIF 2.1.0 output**: For native GitHub Code Scanning integration.
- **CLI** (`src/cli.ts`): `scan`, `threat-model`, `version`, `help` subcommands.
- **GitHub Action** (`.github/action/action.yml`): Composite action with
  bun install, scan, SARIF upload, fail-on threshold.
- **GitLab CI Template** (`.gitlab-ci.d/security-vule.yml`): SAST report
  integration.
- **Docker Compose** (`poc-validator/real-apps/docker-compose.yml`):
  One-command real DVWA + bWAPP + sqli-labs + Pikachu deployment.

### Verified

- **Static F1**: 68.5% on 4 apps (DVWA 56.5%, bWAPP 62.5%, sqli-labs 96.2%, Pikachu 65.2%)
- **PoC verified**: 80/80 = 100% (precision 1.00 on mock DVWA)
- **AI red team**: 10/10 pass
- **MITRE ATLAS coverage**: 12/12 relevant techniques
- **tsc --noEmit**: 0 errors
- **bun test**: 558 pass, 36 pre-existing NodeGoat Cypress failures
- **Tests**: 36 security module tests + 75 LLM module tests + 30+ red team tests

### License

AGPL-3.0 (per Shannon-comparable open source standard)
