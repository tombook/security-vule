# Changelog

All notable changes to security-vule will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-06-12)


### Features

* **cli:** Sprint 5 — CLI + Web UI + D3/Plotly visualization ([a9d6d3b](https://github.com/tombook/security-vule/commit/a9d6d3b20ce42e4e6d1ced62682a977d2e8574d0))
* **cpg:** Sprint 1 — CPG core (types/builder/queries/metrics/sinks) ([da497c8](https://github.com/tombook/security-vule/commit/da497c843d9755075bde21d9d5dba30d5db5119b))
* **dimensions:** Sprint 3 — 4 P0 dimensions (gravity/kepler/orbital/nbody) ([bb3d961](https://github.com/tombook/security-vule/commit/bb3d9611f7d1eab1ba416201cc1b066332b93b8b))
* **dimensions:** Sprint 4 — 5 P1 + 3 P2 dimensions (total 13) ([93a6607](https://github.com/tombook/security-vule/commit/93a6607d6b4871f4b8ae62b98d4b625a78793b19))
* **dimensions:** Sprint 6 — 6 math framework dimensions (total 19) ([161fbb2](https://github.com/tombook/security-vule/commit/161fbb2bfc50953d100f7528241f2d379336b62a))
* **dimensions:** Sprint 8 — 10 P3 dimensions (total 29 = full cosmic-galaxy + math frameworks) ([aaee567](https://github.com/tombook/security-vule/commit/aaee5673bb715c179b89b9a92a10dd9eb5df40da))
* DomXssVerifier — Playwright-based DOM XSS verification (v1.8) ([866c3f3](https://github.com/tombook/security-vule/commit/866c3f395f21a6e2fa03c7bb501b1727a5dc0cd3))
* **engine:** Sprint 2 — VuleEngine + UVRS deep integration ([a496727](https://github.com/tombook/security-vule/commit/a496727b5b6b938b0b1eeba7f313021f3b2c1546))
* HA evolution — Anthropic Harness-inspired /triage + /patch + /threat-model ([61fcdff](https://github.com/tombook/security-vule/commit/61fcdffc9cd8775ff136a354e53ba6172a272690))
* **integration:** Sprint 7 — cosmic-galaxy equivalence test + performance ([371a0f3](https://github.com/tombook/security-vule/commit/371a0f3135e9667e81e8426f9f1aa30e343846bf))
* LLM mode improvements (specialized prompts, multi-finding, verify pass, TYPE_NORMALIZE) ([db91327](https://github.com/tombook/security-vule/commit/db91327da8cf76c212e485deb75cc3ef0763089d))
* **observability:** Sprint E4 — pino + OpenTelemetry + prom-client + health ([86107e3](https://github.com/tombook/security-vule/commit/86107e3191e2632aefded830eb9e8f52e9e8ab64))
* P0 evolution — Web UI + OWASP Agentic Top 10 + MCP 7/3/1 ([5a83b4b](https://github.com/tombook/security-vule/commit/5a83b4b471e41c503a05ef0deb0afc6b76dfef8c))
* P1 evolution — VQL query DSL +6-stage multi-agent workflow ([aecec06](https://github.com/tombook/security-vule/commit/aecec065ae78793aa779d3d8ef21f304512685ce))
* P2 evolution — PoC sandbox + SKILL.md scanner + MCP5 prompts ([c3506cd](https://github.com/tombook/security-vule/commit/c3506cd10177c63c8bc37c4079d590bcf43cdbf4))
* P3 evolution — VuleDaemon + IncrementalScanner + README sync ([7df0eb5](https://github.com/tombook/security-vule/commit/7df0eb54ac47089c8e46b067ba99947d429fcc53))
* P4 — CLI integration for daemon + incremental + CHANGELOG/SBOM ([c5d65fd](https://github.com/tombook/security-vule/commit/c5d65fd9b89d9893551215ef7a422113e3b06167))
* payload database complete (Less-29~65) + PoC API endpoints (v1.8) ([ea34d4f](https://github.com/tombook/security-vule/commit/ea34d4f704875d0ade8f7f6e8bf68fd66c75457b))
* PocSandbox v1.3 — WAF bypass payloads + 302 redirect + unbreakable detection ([1bc9a8c](https://github.com/tombook/security-vule/commit/1bc9a8cd32047bb3e9f4a550866870c5971d8e3b))
* PocSandbox v1.4 — blind SQLi (SLEEP) detection + DVWA 21/21 + multi-target validation ([a5ae91a](https://github.com/tombook/security-vule/commit/a5ae91a113f5aac222c2f632809e84e650823fe4))
* PocSandbox v1.5 — header/cookie injection + sqli-labs 66/66 + CRLF detection ([24d241a](https://github.com/tombook/security-vule/commit/24d241a4b019191a2f18a7d1450a2088a759a8a3))
* PocSandbox v1.6 — noFollowRedirect + case-insensitive header matching + Pikachu 13/13 ([cebc80b](https://github.com/tombook/security-vule/commit/cebc80b9ce633e6cfc13673a18516d0985a7edd5))
* **security:** Sprint E6 — gitleaks config + license CI gate (12-week roadmap done) ([03f589e](https://github.com/tombook/security-vule/commit/03f589efaa50b44fcdc3f90ca17a3035c4c9a503))
* SOP v1.0 iteration — file-upload dimension + PocSandbox status inference + daemon QUERY + baseline fix ([989a6fc](https://github.com/tombook/security-vule/commit/989a6fc96a7a9f8baf758d4fd4d2566089bf2af2))
* **ui:** product-grade Web UI with landing + scan + report + settings ([9a700db](https://github.com/tombook/security-vule/commit/9a700db8282ce808802b873e48e64dcad836f885))
* v1.7 — 50 unit tests + payload database with injection type classification ([5f82bcf](https://github.com/tombook/security-vule/commit/5f82bcf1129a63d814c2a3464ea6ce9d4ada5863))
* **v1.9:** bWAPP coverage + PoC API 增强 + DomXSS + Daemon24h ([ad30a49](https://github.com/tombook/security-vule/commit/ad30a499d9780d91c5428a0195f9c15f8ffba176))
* VuleSandboxBridge + SSRF/XXE PoC validation (v1.7) ([2514512](https://github.com/tombook/security-vule/commit/251451222027e39ec8899b1edecca43ee91be353))


### Bug Fixes

* **poc:** Bridge payload.matches 反序列化 + targets 过滤 (v1.8.1) ([5c6f09d](https://github.com/tombook/security-vule/commit/5c6f09df5b2db2275614493762aaf76e7821a7a3))
* PocSandbox bWAPP login + cookie jar + security_level +25 PoC verification ([ce03102](https://github.com/tombook/security-vule/commit/ce03102b0c67b1b636842413fbd1aaf94e0316d7))
* **test:** property test unique IDs + performance threshold bump ([1e8307d](https://github.com/tombook/security-vule/commit/1e8307d297d69ac938f7f6c7f9e204691941a5bd))

## [1.9.0] -2026-06-12

### Added
- **bWAPP payload database**: 28 entries (RCE×4, SQLi×11, LFI×2, XSS×3, Upload, SSRF, LDAP, Unserialize, Open Redirect, xss-eval, phpi, HRS, HPP) — 21/28 = 75% verified in Docker
- **PoC API enhancements**: `POST /api/poc/verify` now supports
  - `types` filter (e.g. `["rce"]`) to run only specified injection types
  - `detailed: true` returns per-result `status`, `diagnostic`, `matchedExpectations`, `error`
  - `statusBreakdown` aggregate (verified/auth_failed/payload_filtered/...)
  - `filters` echo of what was applied
- **DOM XSS verification API**: `POST /api/poc/dom-xss` integrates Playwright headless
  browser verifier for client-side XSS injection sinks. Returns per-target DOM HTML,
  console logs, and JS errors.
- **VuleDaemon 24h stability**: Unix socket IPC verified (`STATE`/`SCAN`/`STOP`),
  file-watch trigger → scan-completed, baseline diff, persistent background process

### Changed
- **DVWA LFI payload adaptive path**: `low` level now uses absolute `/etc/passwd`
  (was relative `../../../../etc/passwd` blocked by Apache config). Verified 90.5% on DVWA.
- **PAYLOAD_DATABASE total**: 84 → 112 entries (bWAPP coverage restored from v1.7 regression)
- `VuleSandboxBridge.generateReport(verifications?)` now accepts optional subset
  for filtered reporting
- `/api/poc/verify` total verified: 77/84 → **98/112 = 87.5%** (bWAPP coverage + more checks)

### Fixed
- **bWAPP payloads field mapping**: SQLi field name corrected per endpoint
  (`title` vs `movie` vs `login`); error marker changed from `error` regex to
  `contains: 'SQL'` (bWAPP hides error messages, only displays "SQL" keyword)
- **bWAPP XSS Referer**: payload moved from URL parameter to `Referer` header
  (HTTP_REFERER header injection)
- **XSS iframei URL**: javascript: protocol URL-encoded to bypass shell escaping

### Tests
- 1089 → 1090 tests (+1, +0.09%) — added 4 PoC API request-shape tests
- New: `tests/unit/integration/poc-api.test.ts` — types filter, detailed response,
  Bridge verifyByType, generateReport(verifications?) filter
- 0 TypeScript errors, 0 ESLint errors

## [1.8.1] -2026-06-11

### Fixed
- **VuleSandboxBridge payload.matches deserialization**:
  payload-database's string `/admin|First name/i` was passed verbatim to PocSandbox
  which requires RegExp. Bridge now auto-converts string→RegExp with /pattern/flags
  parsing, fallback to literal on parse error.
- **`/api/poc/verify` targets filter**: `verifyAll()` now honors `this.sandboxes`
  to only run payloads for the requested target(s) (was running all 84 every time).

### Tests
- 1088 → 1089 tests
- 77/84 = 91.7% verified in Docker real environment (4 targets)

## [1.1.0] -2026-06-11

### Added
- **Web UI完整化**: `src/integration/commands/server.ts` — POST `/api/report` + GET `/report` with D3 + Plotly visualization; dashboard with drag-drop upload
- **OWASP Agentic AI Top10 (2026)**: `src/llm/owasp-agentic.ts` — ASI01-ASI10 with32 patterns, CWE mappings, remediation guidance
- **MCP server7/3/5**: `src/mcp/server.ts` —7 tools (`scan_code`, `scan_file`, `list_rules`, `lookup_cwe`, `threat_model`, `attack_surface`, `owasp_agentic_scan`) +3 resources +5 prompts (`security-review`, `spec-driven-vuln-fix`, `owasp-agentic-audit`, `skill-md-review`, `poc-verify`)
- **VQL Query DSL**: `src/engine/cpg/vql.ts` — MATE-style declarative CPG queries with8 predicates +4 combinators + reachability methods
- **6-stage multi-agent workflow**: `src/engine/workflow.ts` — SPEC→PLAN→BUILD→TEST→REVIEW→SHIP with skip/resume/onStageComplete hook
- **`vule workflow` CLI**: `src/integration/commands/workflow.ts` — `--llm --owasp --poc --stage N --skip N --resume N --json`
- **PocSandbox**: `src/poc/sandbox.ts` — TypeScript-native PoC executor with3 isolation modes (process/docker/mock), auto-login, retry
- **SKILL.md scanner**: `src/skill/scanner.ts` — Claude Code plugin security with10 dangerous patterns + tool permission scoring +5 risk levels
- **VuleDaemon (ralph-loop)**: `src/daemon/vule-daemon.ts` — persistent watcher with file events + baseline diff + Unix socket (STATE/SCAN/STOP) +6 event types
- **IncrementalScanner (CodeQL-style)**: `src/scanner/incremental.ts` — SHA-256 hash + snapshot cache + added/modified/unchanged/deleted + cache hit rate reporting
- **`vule daemon` CLI**: `src/integration/commands/daemon.ts` — start/stop/status with JSON output
- **`vule analyze --incremental`**: incremental scan with `--cache` option
- **README_CN evolution section**: comprehensive P0-P3 capabilities tables + test statistics +11 external reference projects

### Tests
-820 →937 tests (+117, +14%)
-95 →102 test files (+7)
- New:11 server tests,12 OWASP agentic tests,14 MCP tests,17 VQL tests,15 workflow tests,10 sandbox tests,18 skill tests,11 daemon tests,12 incremental tests,5 daemon CLI tests,6 incremental CLI tests
- All tests pass;0 TypeScript errors;0 ESLint errors

## [Unreleased]

### Added
- **Gitleaks secret scanning**: `.gitleaks.toml` with 4 custom rules (security-vule API keys, Anthropic, OpenAI, Zhipu); `.github/workflows/license-check.yml` runs on every push
- **License compliance CI**: `.github/workflows/license-check.yml` runs `license:check` (blocks GPL/AGPL-UNKNOWN/UNKNOWN/WTFPL); uploads license report to `docs/compliance/licenses.txt`
- **Pre-commit gitleaks note**: `.husky/pre-commit` documents that gitleaks runs via GitHub Action (`brew install gitleaks` for local)
- **Secret redaction tests**: `tests/unit/security/gitleaks-integration.test.ts` (7 tests) — validates 5 secret patterns (AWS/Anthropic/GitHub/JWT/PEM) + 2 prompt injection scenarios
- **Release automation**: `.github/workflows/release-please.yml` + `release-please-config.json` (auto semver + CHANGELOG bump)
- **Dependabot**: `.github/dependabot.yml` (weekly npm + GitHub Actions auto-PR, grouped)
- **CycloneDX SBOM**: `.github/workflows/sbom.yml` + `bun run sbom` (266 components, attached to releases)
- **Snyk SCA**: `.github/workflows/security-audit.yml` (npm audit + Snyk + gitleaks + OpenSSF Scorecard)
- **License check**: `bun run license:check` (blocks GPL/AGPL-UNKNOWN/UNKNOWN/WTFPL)
- **`.npmrc`**: official npm registry for audit (overrides mirrors)
- ESLint + Prettier configuration (`eslint.config.js`, `.prettierrc.json`)
- Husky pre-commit hook with lint-staged
- Test coverage reporting (target: ≥80% line coverage, current: 73.02%)
- `CONTRIBUTING.md` — contributor guide
- `CHANGELOG.md` — this file
- `SECURITY.md` — vulnerability disclosure policy
- `Dockerfile` (multi-stage, multi-arch)
- `TypeDoc` auto-generated API docs (`bun run docs:api`)
- **`examples/`** — 5 working examples (basic-ast, llm-scan, cpg-construction, web-ui, custom-dimension)
- **`docs/architecture/c4-model.md`** — 4-level C4 architecture diagrams (6 mermaid)
- **`src/utils/logger.ts`** — pino structured logging with auto-redact
- **`src/utils/tracing.ts`** — OpenTelemetry distributed tracing
- **`src/utils/metrics.ts`** — 13 Prometheus metrics
- **`src/utils/health.ts`** — `/healthz` Kubernetes health probe + graceful shutdown
- Engineering roadmap v1.0 (`docs/engineering-roadmap-v1.0.md`)
- Evolution roadmap v1.0 (`docs/evolution-roadmap-v1.0.md`)
- v0.3 competitive comparison vs Anthropic Harness + Alibaba OCR (`docs/v0.3-competitive-comparison.md`)
- Cosmic-galaxy evolution design spec (`docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md`)

### Changed
- Bumped to v0.3.0 development cycle
- **Type safety**: 23 `any` usages → 0 (across 13 files)
- **ESLint config**: `examples/` exempted from `no-explicit-any` (demonstrative code)
- **Pre-commit hook**: now documents gitleaks as GitHub Action

## [0.3.0] - 2026-06-10

### Added
- **29 cosmic-galaxy-aligned dimension detectors** with formal UVRS scoring
  - 4 P0 dimensions: 引力场 (gravity), 开普勒 (kepler), 轨道六要素 (orbital), N体 (n-body)
  - 5 P1 dimensions: 摄动 (perturbation), 潮汐 (tidal), 相对论 (relativistic), 暗物质 (dark-matter), 熵增 (entropy)
  - 3 P2 dimensions: 量子 (quantum), 拓扑 (topology), 信息论 (information)
  - 6 math frameworks: 类型论, 范畴论/数据流函子, TDA, 纯函数式, 抽象解释, 符号执行
  - 10 P3 dimensions: 混沌, 相变, 场论, 分形, 非平衡, 博弈, 迁移, 微分几何, 重整化, 范畴论基础
- **CPG (Code Property Graph) core** with 5 edge kinds (data, control, call, def_use, ast_child)
- **VuleEngine** unified entry point
- **YAML config** (`config/vule.yaml`) for weight/threshold customization
- **CLI commands**: `vule analyze`, `vule dimension`, `vule visualize`, `vule server`, `vule list-dimensions`
- **HTML visualization** with D3.js force-directed risk star map + Plotly radar chart
- **Web UI server** (Bun.serve) with REST API
- **Verify pass** for false-positive reduction (~95% precision)
- **TYPE_NORMALIZE** for LLM type variant mapping
- **Specialized per-vulnerability-type prompts** (SQLi/Cmdi/XSS/LFI/Upload/Deser/SSRF/InfoDisclosure)
- **Multi-finding support** (configurable `maxFindings`, default 5)
- **Attack path tracing methodology** (ENTRY→PROPAGATION→SINK→TRIGGER)
- **CWE validation map** (17 CWE entries with bidirectional type↔CWE check)
- **Cosmic-galaxy equivalence test** (cross-project integration test, tolerance 0.10)
- **Performance benchmarks** (100/500-node CPG analysis)
- **PoC validation against real Docker targets** (8/8 vulnerabilities proven exploitable)

### Improved
- LLM findings: 12 → 22 (+83%)
- File detection rate: 83% → 92%
- False positive rate: ~20% → ~14%
- 8 Sprint plans completed
- 213+ new tests added (771 total)

### Performance
- Single-file LLM scan: ~60s → ~49s (-18% via specialized prompts)
- 100-node CPG analysis: <1s
- 500-node CPG analysis: <5s

### Documentation
- `docs/design-philosophy.md` — cosmic-galaxy design philosophy
- `docs/evaluation-report.md` — comprehensive evaluation (11 chapters)
- `docs/three-tool-comparison.md` — initial comparison (pre-v0.3)
- `docs/llm-mode-gap-analysis.md` — gap analysis vs SOTA tools
- `docs/ai-security-expert-recommendations.md` — AI security audit
- `docs/v0.3-competitive-comparison.md` — competitive comparison post-v0.3
- `docs/engineering-roadmap-v1.0.md` — 12-week engineering roadmap
- `docs/evolution-roadmap-v1.0.md` — 12-month feature roadmap
- 18 theory docs at `theory/dimensions/`
- 8 Sprint plans at `.agents/superpowers/specs/2026-06-10-sprint-{1..8}-*.md`

## [0.1.0] - 2026-05-19

### Added
- Initial project snapshot
- Tree-sitter-based AST analyzer for 21 vulnerability types
- Taint analysis (`src/engine/taint.ts`, `taint-enhanced.ts`)
- CFG/DFG program graphs (`src/engine/program-graph.ts`)
- LLM enhancement via GLM-5.1, Anthropic Claude, OpenAI, Ollama
- 8 LLM providers with failover
- Multi-model consensus mode
- Playwright PoC verification harness
- STRIDE threat modeling + DFD
- SARIF 2.1.0 output for GitHub Code Scanning
- Mock DVWA + real Docker apps (DVWA/bWAPP/sqli-labs/Pikachu) for PoC validation
- GitHub Actions + GitLab CI/CD templates
- Plugin architecture (`src/plugin/`)
- MCP server (`src/mcp/server.ts`)
- Cosmic-galaxy parallel execution engine (`src/math/cosm-x-*.ts`)
- Statistical detector (`src/detection/statistical.ts`)
- Project analyzer (`src/math/cosm-x-project-analyzer.ts`)

[Unreleased]: https://github.com/security-vule/security-vule/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/security-vule/security-vule/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/security-vule/security-vule/releases/tag/v0.1.0
