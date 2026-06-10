# Changelog

All notable changes to security-vule will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
