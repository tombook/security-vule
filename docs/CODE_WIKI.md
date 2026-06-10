# security-vule · Code Wiki

> A structured guide to the `security-vule` codebase — data-driven white-box vulnerability mining with deterministic static analysis, optional LLM enhancement, and runtime PoC verification.

This Wiki is auto-generated from inspection of the repository. It mirrors the layout of `src/` and explains module responsibilities, key types, public APIs, and how the pieces fit together.

---

## 1. Project Overview

`security-vule` (current package version `1.0.0`, CLI semantic version `0.1.0`) is an **open-source static + runtime vulnerability scanner for web applications**, distributed under AGPL-3.0.

**Core value proposition (from `README.md`):**

- Deterministic static analysis using **tree-sitter AST + taint analysis** (PHP, JS/TS, Java, C/C++, Go, Rust, Python).
- Optional **LLM enhancement** (Anthropic, OpenAI, Google, Ollama, DeepSeek, GLM, Qwen, Moonshot, etc.) for higher recall.
- **Runtime PoC verification** that actually executes exploits against a target (mock or real DVWA/bWAPP/Pikachu/sqli-labs).
- **STRIDE threat modeling** with auto-generated Data Flow Diagrams (Mermaid format).
- **SARIF 2.1.0** output for native GitHub Code Scanning / GitLab SAST integration.
- A **plugin pipeline** (`probe → detector → generator`) inspired by `garak`.
- A **cosmic-galaxy theoretical framework** (`VuleEngine` + 13 "dimension" detectors) that scores every CPG node with a UVRS (Unified Vulnerability Risk Score).

Reported headline metrics (from `README.md`): F1 = 68.5% on a 4-app benchmark (with LLM), 100% PoC precision (80/80 verified), ~1 second per scan.

---

## 2. High-Level Architecture

```
                ┌────────────────────────────────────┐
                │   Source code (CLI / MCP / Plugin) │
                └───────────────┬────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │                  Engine / Analyzer           │
        │   parser → cfg → dfg → program-graph → CPG   │
        │   taint analysis → metrics → findings        │
        └──────────┬──────────────────────────┬────────┘
                   │                          │
   ┌───────────────▼─────────────┐ ┌───────────▼──────────────┐
   │  Detection / Dimensions     │ │  Threat Modeling (STRIDE)│
   │  patterns + statistical +   │ │  stride-mapper, trust-   │
   │  ml + llm-agent + rag-index │ │  boundary, model-gen,    │
   │  → VuleEngine (UVRS)        │ │  DFD                     │
   └───────────────┬─────────────┘ └───────────┬──────────────┘
                   │                           │
                   └────────────┬──────────────┘
                                │
                ┌───────────────▼────────────────┐
                │  Output: SARIF / JSON /       │
                │  Markdown report (with mermaid DFD) │
                │  + PoC verification (Python)   │
                └────────────────────────────────┘
```

Three layers, mapped onto the `src/` tree:

| Layer | Module | Role |
|---|---|---|
| **L1 — Math / Execution** | `src/math/execution/*`, `src/engine/*` | Pure math + parsing + graph analysis |
| **L2 — Application** | `src/math/application/*`, `src/detection/*` | Calibration, GNN classifier, scanner, dedup |
| **L3 — Theory** | `src/math/theory/*` | 23-D cosmic-galaxy theory, UVRS engine, physics dimensions |

The "cosmic-galaxy" design (`docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md`) treats the CPG as a galaxy of vulnerability "bodies" and computes risk by analogy to gravitational / orbital physics.

---

## 3. Directory Structure

```
security-vule/
├── README.md                 # main user-facing docs
├── package.json              # bun project, ESM, exports plugin/benchmark/mcp
├── tsconfig.json
├── bun.lock
├── LICENSE                   # AGPL-3.0
├── CHANGELOG.md
├── config/
│   ├── cpg-sinks.yaml        # sinks catalog used by CPG builder
│   └── vule.yaml             # VuleEngine configuration template
├── docs/                     # design + benchmark + threat-model reports
├── poc-validator/            # runtime PoC verification tooling
│   ├── mock_dvwa.py          # zero-dep Python DVWA mock server
│   ├── verify_poc.py         # PoC driver that consumes findings JSON
│   ├── vuln_db.json
│   └── real-apps/docker-compose.yml
├── scripts/                  # dvwa_test, full_poc_verify, llm-scan, ai-redteam
├── test-targets/php-vulns/   # intentionally vulnerable PHP samples
├── tests/                    # bun test suite (unit + integration)
├── theory/dimensions/        # markdown theory for each cosmic-galaxy dim
└── src/                      # all source code
    ├── cli.ts                # production CLI (scan, threat-model, sarif)
    ├── engine/               # parsing, CFG, DFG, taint, CPG, dimensions
    ├── detection/            # patterns, statistical, ml, combiner, llm-agent
    ├── llm/                  # router + providers + security + consensus
    ├── threat/               # threat model pipeline + STRIDE mapper
    ├── threatmodel/          # legacy STRIDE + DFD
    ├── plugin/               # garak-style probe/detector/generator
    ├── mcp/                  # Model Context Protocol stdio server
    ├── benchmark/            # precision/recall/F1 evaluator + synthetic data
    ├── evolution/            # 10,000-round evolver + GA + CosmX
    ├── math/                 # L1 (execution) + L2 (application) + L3 (theory)
    ├── integration/          # cli, benchmark-harness, celestial-viz, validate-theory
    └── utils/rng.ts          # deterministic RNG
```

---

## 4. Entry Points & Build / Run

### 4.1 `package.json` scripts

| Script | Command | Purpose |
|---|---|---|
| `analyze` | `bun --bun src/engine/analyzer.ts` | Run the analyzer directly on code |
| `cli` | `bun --bun src/integration/cli.ts` | Multi-command CLI (analyze, evolve, status, reset, init, config, benchmark, evaluate, export, mcp, plugin-list, plugin-scan) |
| `mcp` | `bun --bun src/mcp/server.ts` | Start the MCP stdio server |
| `evolve` | `bun --bun src/evolution/evolver.ts` | 10,000-round evolution loop |
| `evolve-enhanced` | `bun --bun src/evolution/run-evolution-enhanced.ts` | Enhanced evolution runner |
| `test` | `bun test` | Run the full test suite (`tests/**`) |
| `bench` | `bun --bun src/integration/benchmark.ts` | Benchmark harness |
| `benchmark:eval` | `bun --bun -e "import …" ` | One-liner synthetic-dataset eval |

The package's `exports` field exposes the public API:

- `security-vule/plugin` → `src/plugin/index.js`
- `security-vule/benchmark` → `src/benchmark/index.js`
- `security-vule/mcp` → `src/mcp/server.js`
- `security-vule/line-locator` → `src/detection/line-locator.js`
- `security-vule/program-graph` → `src/engine/program-graph.js`

### 4.2 Production CLI (`src/cli.ts`)

Subcommands:

- `scan <path>` — recursive static analysis with optional flags:
  - `--sarif` — emit SARIF 2.1.0
  - `--baseline FILE` + `--diff` — incremental CI
  - `--output FILE` / `-o FILE`
  - `--min-confidence N` — filter
- `threat-model <path> [--with-dfd] [--output FILE]` — STRIDE + optional Mermaid DFD
- `version`, `help`

Exit code is non-zero if any `CRITICAL` finding is shown.

### 4.3 Wider CLI (`src/integration/cli.ts`)

A second, more research-oriented CLI with commands `analyze`, `evolve`, `status`, `reset`, `init`, `config`, `benchmark`, `evaluate`, `export`, `mcp`, `plugin-list`, `plugin-scan`.

### 4.4 Quick-start

```bash
# install
curl -fsSL https://bun.sh/install | bash
git clone https://github.com/security-vule/security-vule.git
cd security-vule
bun install

# scan
bun run src/cli.ts scan ./src
bun run src/cli.ts scan ./src --sarif --output results.sarif

# threat model
bun run src/cli.ts threat-model ./src --with-dfd --output threat-model.json

# PoC verification
nohup python3 poc-validator/mock_dvwa.py 8080 > /tmp/mock.log 2>&1 &
bun run src/cli.ts scan ./src --output /tmp/sv_findings.json
python3 poc-validator/verify_poc.py \
  --target dvwa \
  --findings /tmp/sv_findings.json \
  --output /tmp/sv_poc_verified.json
```

---

## 5. Core Modules

### 5.1 `src/engine/` — Static analysis core

The engine is the deterministic backbone. It produces the structured `AnalysisResult` that every downstream consumer (detection ensemble, threat modeling, MCP, CLI) depends on.

#### `src/engine/analyzer.ts`

**`analyzeFile(filePath, sourceCode, language?) → Promise<AnalysisResult>`** is the single most important function in the project. It orchestrates:

1. **`parse(sourceCode, lang)`** (from `parser.ts`) — tree-sitter parsing into a normalized `ASTNode` tree.
2. **CPG construction** — `CPGBuilder` (from `src/math/cpg.ts` re-exporting `src/math/execution/cpg.ts`) collects file/function/statement/expression nodes, attaches `is_sink` features via `isSinkFunction`.
3. **`buildCFG(ast)`** — control-flow graph (`cfg.ts`).
4. **`buildDFG(cpg, fnName)`** — intra-procedural data-flow graph (`dfg.ts`).
5. **`analyzeTaint(code, filePath, ast)`** — pattern-based taint analysis (`taint.ts`).
6. **Metrics** — cyclomatic complexity, nesting depth, LOC, function count, anomaly score.
7. **Findings generation** — `generateFindings(taint, metrics, file, code)`:
   - per-path with confidence adjustment (`adjustConfidenceForSafety` — recognises `htmlspecialchars`, `intval`, `is_numeric`, `mysql_real_escape_string`, etc.)
   - anomaly-based finding when complexity/depth are abnormal
   - regex-based weak-pattern catalogue (`WEAK_PATTERNS`) for `md5/sha1/DES/xor/Math.random/mt_rand/...`
   - dedup by `(file, type)` keeping highest confidence

Exports helper functions: `parse`, `findNodesByType`, `buildCFG`, `buildDFG`, `analyzeTaint`, `CPGBuilder`.

#### `src/engine/parser.ts`

- Languages: `'python' | 'javascript' | 'typescript' | 'java' | 'c' | 'go' | 'rust' | 'php'`.
- Lazy-loads `tree-sitter` + grammar packages: `tree-sitter-python`, `tree-sitter-java`, `tree-sitter-c`, `tree-sitter-go`, `tree-sitter-php`.
- Falls back to a lightweight custom recursive parser when tree-sitter bindings aren't available (so the analyzer still runs in minimal environments).
- Exports `parse(code, lang)`, `detectLanguage(filename)`, `findNodesByType(ast, type)`.

#### `src/engine/cfg.ts` · `src/engine/dfg.ts` · `src/engine/program-graph.ts`

- **`buildCFG(ast)`** — basic blocks + intra-procedural control flow (`CFG_TRUE`, `CFG_FALSE`).
- **`buildDFG(graph, fnName)`** — per-function data-flow with `def → use` edges.
- **`buildProgramGraph(ast, cfg?, code?)`** — combines AST, CFG, DFG into a 7-edge-type graph:
  - `AST`, `CFG`, `CFG_TRUE`, `CFG_FALSE`, `DFG`, `CALL`, `FALLS_TO`.
  - Inspired by FUNDED_NISL GGNN (ICSE TIFS 2021).

#### `src/engine/taint.ts`

Regex-based taint analysis with:

- **Source patterns**: `read`, `input`, `request.body`, `$_GET`, `$_POST`, `HttpServletRequest`, `getenv`, `document.cookie`, etc.
- **Sink patterns**: SQL injection, NoSQL injection, shell injection, file write/read/include, SSRF, deserialization, weak crypto, weak randomness, LDAP, XPath, XXE, eval/dynamic code, secure cookie, trust-boundary violations.
- **Sanitizer patterns**: `htmlspecialchars`, `htmlentities`, `intval`, `filter_var`, `mysql_real_escape_string`, `is_numeric`, ESAPI encoder.
- **Path propagation** across functions (inter-procedural) with confidence calculation.

Key types: `TaintSource`, `TaintSink`, `Sanitizer`, `TaintPath`, `TaintResult`.

#### `src/engine/cpg/` — Cosmic-galaxy CPG

This sub-tree is the "new" (v3) CPG aligned with the cosmic-galaxy theory. Distinct from the older CPG builder under `src/math/execution/cpg.ts`.

- **`builder.ts`** — `CPGBuilder` converts `ProgramGraph` → `CPG` with five edge kinds (`ast_child`, `control`, `data`, `call`, `control` for `FALLS_TO`). Adds sink-detection features.
- **`types.ts`** — `CPG`, `CPGNode`, `CPGEdge`, `CPGEdgeKind`, `CPGLanguage`.
- **`sinks.ts`** — language-aware catalog of dangerous sink functions.
- **`metrics.ts`** — pagerank, degree, betweenness.
- **`queries.ts`** — query helpers (sink neighbours, shortest paths).
- **`index.ts`** — barrel export.

#### `src/engine/dimensions/` — Cosmic-galaxy dimension detectors

Each dimension is a `BaseDimension` subclass with `name`, `weight`, and `compute(node, cpg) → number ∈ [0, 1]`. The registry composes them per VuleEngine call.

| Dimension | File | Physical analogy | Weight |
|---|---|---|---|
| `ast` | `registry.ts` (placeholder) | AST complexity | 0.15 |
| `gravity` | `gravity.ts` | `F = Γ·Wsrc·Wsink / d²` — pull between sources & sinks | 0.20 |
| `kepler` | `kepler.ts` | `r(θ) = a(1-e²)/(1+e·cosθ)` — orbital distance stats | 0.15 |
| `orbital` | `orbital.ts` | eccentricity / inclination | varies |
| `nbody` | `nbody.ts` | many-body interactions | varies |
| `perturbation` | `perturbation.ts` | perturbations in 23D graph | P1 |
| `tidal` | `tidal.ts` | `1/d³` coupling between sinks | 0.10 |
| `relativistic` | `relativistic.ts` | mass-energy effects | P1 |
| `darkMatter` | `dark-matter.ts` | unobserved but influential mass | P1 |
| `entropy` | `entropy.ts` | information entropy of node neighborhoods | P1 |
| `quantum` | `quantum.ts` | probabilistic superposition | P2 |
| `topology` | `topology.ts` | Betti numbers / connectedness | P2 |
| `information` | `information.ts` | mutual information | P2 |

#### `src/engine/uvrs.ts` — Unified Vulnerability Risk Score

`S_VULE(v) = σ(Σᵢ wᵢ · Rᵢ(v))` with sigmoid output, default weights summing to 1, and thresholds at `0.25 / 0.5 / 0.75 / 0.85`. Tracks `RiskLevel` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and `dominantDimension`.

#### `src/engine/vule-engine.ts`

**`VuleEngine`** is the unified entry point for cosmic-galaxy analysis:

- Constructor `new VuleEngine(cpg, sinks, securityAPIs, config?)`.
- **`computeUVRS(nodeId)`** — returns `{ score, level, dominant, contributions }`.
- **`analyze()`** — returns a full `VuleReport` (top-K risky nodes, risk distribution).
- **`topRiskNodes(k?)`**, **`exportReport(path?)`**.

#### `src/engine/vule-config.ts` · `vule-report.ts`

- YAML-driven `VuleConfig` (`uvrs.weights`, `thresholds`, `dimensions.enabled`, `llm`, `cache`, `report`).
- `defaultConfig()` and `loadConfig(source, defaults?)` (path or string).

#### `src/engine/taint-enhanced.ts`

Layered on top of `taint.ts` with deeper inter-procedural propagation.

---

### 5.2 `src/detection/` — Detection ensemble

The "L2" application layer that turns raw analysis into scored vulnerability findings.

#### `detector.ts`

`Detector` class orchestrating three signals:

- **Pattern** — `patterns.ts` `ALL_RULES` (22 rules grouped into INJ / AUTH / CRYPTO / RACE / MEM, each with `source`, `sink`, `pattern`, `confidence`, `cwe`).
- **Statistical** — `statistical.ts` `detectStatisticalAnomaly` / `computeAnomalyScore` over `CodeComplexityFeatures`.
- **ML** — `ml-classifier.ts` `computeGraphEmbedding`, `computeTokenEmbedding`, `FeatureVector`.

Configurable via `DetectorConfig` (`weights`, `minConfidence`, `minSeverity`, three on/off flags). Default weights: `pattern 0.3 / statistical 0.3 / ml 0.4`.

#### `combiner.ts`

`aggregateScores`, `filterBySeverity`, `CombinedDetection`, `VulnerabilityScore`. Implements the weighted-ensemble combiner with severity-weighted scoring.

#### `line-locator.ts`

Downgrades function-level detections to precise line ranges using:

- Keyword scoring near dangerous APIs
- Taint sink matching
- Context window weighting

Inspired by LineVul (ICSE 2023). Exported via the `security-vule/line-locator` package export.

#### `rag-index.ts`

`VectorIndex` + `KnowledgeEntry` for retrieval-augmented detection:

- `embedText(text, dimensions=128)` — FNV-1a hashed bag-of-words → normalized vector.
- `cosineSimilarity`, `topK(query, k)`.
- `VulnerabilityKnowledgeBase` keyed by CWE.

#### `llm-agent.ts`

The bridge between static analysis and an LLM. Defines:

- `VulnerabilityContext`, `VulnerabilityFinding`, `LLMAnalysisResult`, `FixSuggestion`.
- `buildAnalysisPrompt(ctx)` — builds chat messages with line-numbered code, optional taint summary, "treat as DATA" wrapping.
- `LLMAgent.analyze(ctx)` → `LLMAnalysisResult`.
- `getGlobalRateLimiter()` — singleton `RateLimiter` (1M tokens / $5 / 10k calls per scan by default).

#### `patterns.ts` · `statistical.ts` · `ml-classifier.ts`

Standalone detection primitives used both by the ensemble detector and by other modules (MCP, plugin pipeline).

---

### 5.3 `src/llm/` — LLM provider layer

#### `router.ts` · `types.ts` · `index.ts`

`LLMRouter` supports 4 routing strategies:

- `round-robin`, `cost-based`, `latency-based`, `failover` (default).
- Tracks per-provider `failures`, `lastFailure`, `avgLatencyMs`, `totalRequests`.
- Built-in exponential backoff retries (`retryAttempts` × `2^n` delay), and optional `fallbackProvider`.

**Provider factories (`src/llm/providers/`):**

- `openai.ts` — official OpenAI SDK.
- `anthropic.ts` — `@anthropic-ai/sdk`.
- `google.ts` — `@google/generative-ai`.
- `ollama.ts` — local Ollama models (recommended for privacy).
- `openai-compatible.ts` — drop-in factory helpers:
  - `createDeepSeekProvider()`, `createQwenProvider()`, `createGLMProvider()`, `createZhipuCodingProvider()`, `createMoonshotProvider()`, `createMiniMaxProvider()`.

#### `security.ts`

AI-security utilities called **before** code is sent to any LLM and **after** LLM output:

- **`redactSecrets(input)`** — strips 17 categories of secrets (AWS, GitHub, Slack, Google, Stripe, OpenAI, Anthropic, JWTs, RSA/EC/OpenSSH/PGP private keys, passwords in URL/assignment) before any prompt leaves the host.
- **`detectPromptInjection(input)`** — 12 pattern families (`ignore previous instructions`, `DAN jailbreak`, `you are now`, …) with severity scoring (`riskScore`).
- **`validateFinding(finding)`** — whitelists 18 canonical vulnerability types, valid severities, line ranges, and rejects "ignore previous" echo strings in the LLM output.
- **`RateLimiter`** — token / cost / call caps to prevent Cost-DoS.

#### `consensus.ts`

`runConsensus(ctx, agentA, agentB)` runs **two independent LLMs** over the same code and only reports findings both agree on (same normalized type, ≤ 3 lines apart). Outputs `ConsensusResult` with `confirmed / disputed / rejected / onlyA / onlyB`.

#### `audit.ts`

Audit logger — captures timestamp, file hash, file size, provider, model, token usage, cost, duration per LLM call. **File content is never logged.**

#### `ai-bom.ts` · `atlas.ts` · `metrics.ts`

- **`ai-bom`** — AI Bill-of-Materials generator (which LLM features are used where).
- **`atlas`** — capability atlas mapping vulnerabilities to AI capabilities required to find them.
- **`metrics`** — token / cost / latency tracking.

---

### 5.4 `src/threat/` — STRIDE threat modeling

#### `types.ts`

`STRIDECategory`, `TrustLevel`, `BoundaryType`, `TrustZone`, `TrustBoundary`, `EntryPointType`, `DataFlowPath`, `AttackSurface`, `Threat`, `ThreatModel`, `DetectionSchedule`, `RecalibrationAction`, `CalibrationResult`, `ThreatModelPipelineResult`.

#### `stride-mapper.ts`

`STRIDE_MAPPINGS`, `classifySourceSink`, `getCategoriesForSourceSink`, `computeThreatPriority`, `mapBoundaryType`. Maps vulnerability source/sink pairs to STRIDE letters.

#### `model-generator.ts`

`generateThreatModel(graph, taintResult, filePath)` → `ThreatModel`. Composes the program graph with taint paths to produce a structured threat list.

#### `threat-pipeline.ts`

`ThreatModelPipeline` is the unified pipeline:

```
program graph + taint  →  PluginPipeline (probes → detectors → generators)
                       →  generateThreatModel
                       →  recalibrate (optional)
                       →  ThreatModelPipelineResult
```

#### `graph-query.ts` · `trust-boundary.ts` · `threat-agent.ts` · `calibration.ts` · `index.ts`

Helpers for graph queries, trust-boundary extraction, agent-based threat synthesis (LLM-enhanced), and confidence calibration.

### 5.5 `src/threatmodel/` — Legacy STRIDE + DFD

A simpler, scan-oriented STRIDE mapping (`stride.ts`) and a `Dfd` generator (`dfd.ts`) producing Mermaid diagrams. Used directly by `src/cli.ts threat-model`.

Components are `EE` (external entity), `P` (process), `DS` (data store). Trust boundaries are inferred from HTTP entry points, DB calls, and external HTTP calls.

---

### 5.6 `src/plugin/` — Plugin pipeline (garak-style)

Three plugin phases:

- **`probe`** — pattern + statistical observation.
- **`detector`** — ensemble scoring.
- **`generator`** — LLM-based enhancement (e.g. remediation text).

Files:

- **`types.ts`** — `PluginId`, `PluginPhase`, `PluginState`, `Severity`, `ProbeFinding`, `Detection`, `PluginMeta`, `ProbePlugin`, `DetectorPlugin`, `GeneratorPlugin`, `RegistryEntry`, `PipelineResult`.
- **`registry.ts`** — `PluginRegistry`: `register`, `unregister`, `load`, `loadAll`, `getProbe/Detector/Generator`.
- **`pipeline.ts`** — `PluginPipeline.run(code, filePath?, userConfig?)` executes phases in order, accumulating `findings → detections → enhancedDetections` and timing info.
- **`builtins/index.ts`** — registers the built-ins:
  - `PatternProbe`, `StatisticalProbe` (probe phase)
  - `EnsembleDetector` (detector phase)
- **Public surface**: `security-vule/plugin`.

---

### 5.7 `src/mcp/` — Model Context Protocol server

`src/mcp/server.ts` exposes:

- **`scan_code`** — analyze source code passed as a string.
- **`scan_file`** — analyze a file on disk.
- **`list_rules`** — list all pattern rules (filterable by category / severity).
- **`lookup_cwe`** — CWE knowledge base lookup.
- **`threat_model`** — STRIDE threat model from code.

Transports via stdio (`JSON-RPC 2.0`). Used by AI agents that want to call `security-vule` as a tool. Public export: `security-vule/mcp`.

---

### 5.8 `src/benchmark/` — Evaluator + synthetic dataset

- **`evaluator.ts`** — `computeMetrics(tp, fp, fn, tn)`, `evaluate(samples, detections, config?)`, `formatReport(result)`. Reports Precision, Recall, F1, FPR, FNR, Accuracy, per-CWE breakdown.
- **`synthetic-dataset.ts`** — `SYNTHETIC_DATASET` for the `benchmark:eval` npm script.
- **`index.ts`** — barrel export.

Public export: `security-vule/benchmark`.

---

### 5.9 `src/evolution/` — 10,000-round iteration + GA

- **`evolver.ts`** — primary loop. Tracks `EvolutionState` (`round, bestF1, bestPrecision, bestRecall, lastImprovement, mutationsApplied`), 5 focus areas (`parser, cpg, controlflow, dataflow, detection`), and ~30 mutation templates. State is persisted under `data/evolution/state.json`.
- **`ga-evolver.ts`** — genetic algorithm variant with `populationSize`, `eliteCount`, `tournamentSize`, `crossoverRate`, `mutationRate`, etc. (`DEFAULT_GA_CONFIG`).
- **`cosm-x-evolver.ts`** — evolutionary optimizer over `CosmXParams` (a multi-parameter physics configuration).
- **`evolver-enhanced.ts`** · **`run-evolution-enhanced.ts`** — extended runners with richer instrumentation.
- **`state.json`** — persisted state sample.

---

### 5.10 `src/math/` — L1/L2/L3 mathematical core

Layered per `docs/REDESIGN.md`:

- **`execution/`** — L1 primitives:
  - `cpg.ts` — older CPG builder (re-exported by `src/math/cpg.ts`).
  - `graph-metrics.ts` — pagerank, betweenness, closeness.
  - `entropy.ts` — information entropy.
  - `anomaly.ts` — z-score, Mahalanobis, isolation forest.
  - `taint.ts` — inter-procedural taint propagation.
  - `dataflow.ts` — reaching defs, live variables, DU chains.
  - `controlflow.ts` — basic blocks, CFG, dominators, loops.
- **`application/`** — L2 use-cases:
  - `calibration.ts` — calibrate confidence outputs.
  - `dedup.ts` — finding deduplication.
  - `matching.ts` — finding ↔ ground-truth matching.
  - `gnn-classifier.ts` — GNN vulnerability classifier.
  - `training-pipeline.ts` — training driver.
  - `patterns.ts` — additional patterns.
  - `scanner.ts` — top-level scan orchestration.
- **`theory/`** — L3 theory:
  - `physics/` — gravitational, orbital, n-body, perturbation, tidal, saturation modules.
  - `23d/` — 23-dimensional UVRS calculator and graph builder.
- **`compat/`** — backward-compatible re-exports of pre-v3.0 module paths.

---

### 5.11 `src/integration/` — Integration glue

- **`cli.ts`** — research CLI (see §4.3).
- **`benchmark-harness.ts`** — runs the analyzer against test corpora.
- **`celestial-viz.ts`** — visualization of cosmic-galaxy results.
- **`validate-theory.ts`** — validate cosmic-galaxy theory against ground truth.

### 5.12 `src/utils/rng.ts`

Deterministic RNG used across evolution, GA, and tests: `createRng(seed)`, `rngInt`, `rngBool`, `rngUniform`.

---

## 6. Key Classes & Functions (Quick Reference)

| Name | File | Purpose |
|---|---|---|
| `analyzeFile` | `src/engine/analyzer.ts` | Top-level static analysis entry point |
| `VuleEngine` | `src/engine/vule-engine.ts` | Cosmic-galaxy UVRS analyzer |
| `UVRS.compute` | `src/engine/uvrs.ts` | σ(Σ wᵢ·Rᵢ) scoring |
| `Detector` | `src/detection/detector.ts` | Ensemble of pattern + statistical + ML |
| `LLMAgent` | `src/detection/llm-agent.ts` | LLM-backed vulnerability analyzer |
| `LLMRouter` | `src/llm/router.ts` | Multi-provider LLM routing |
| `redactSecrets` / `detectPromptInjection` / `validateFinding` | `src/llm/security.ts` | AI-security primitives |
| `runConsensus` | `src/llm/consensus.ts` | Two-model consensus |
| `PluginRegistry` / `PluginPipeline` | `src/plugin/registry.ts`, `src/plugin/pipeline.ts` | Garak-style plugin pipeline |
| `ThreatModelPipeline` | `src/threat/threat-pipeline.ts` | End-to-end threat modeling |
| `generateThreatModel` | `src/threatmodel/stride.ts`, `src/threatmodel/dfd.ts` | STRIDE + DFD generators |
| `runEvolution` / `gaEvolver` | `src/evolution/evolver.ts`, `src/evolution/ga-evolver.ts` | 10,000-round + GA evolution |
| `evaluate` | `src/benchmark/evaluator.ts` | Precision / Recall / F1 metrics |
| `runMCP` | `src/mcp/server.ts` | MCP stdio server |
| `LineLocator` | `src/detection/line-locator.ts` | Function → line-level localization |

---

## 7. Dependencies

### Runtime dependencies (`package.json`)

| Package | Version | Used by |
|---|---|---|
| `@anthropic-ai/sdk` | ^0.102.0 | `llm/providers/anthropic.ts` |
| `@google/generative-ai` | ^0.24.1 | `llm/providers/google.ts` |
| `js-yaml` | ^4.2.0 | `engine/vule-config.ts`, config loading |
| `ollama` | ^0.6.3 | `llm/providers/ollama.ts` |
| `openai` | ^6.42.0 | `llm/providers/openai.ts`, `llm/providers/openai-compatible.ts` |
| `tree-sitter-php` | ^0.24.2 | PHP AST parsing |
| `tree-sitter` + lang grammars | (transitive, lazy-loaded) | `engine/parser.ts` |

### Dev dependencies

| Package | Version | Role |
|---|---|---|
| `@types/bun` | ^1.0.0 | Bun runtime types |
| `@types/node` | ^25.9.1 | Node typings |
| `@typescript-eslint/parser` | ^8.60.0 | Lint / parser |
| `typescript` | ^6.0.3 | Type-check |

`tree-sitter-php` is listed under `trustedDependencies` so Bun will allow native install.

### Internal module dependency graph (high-level)

```
cli.ts → engine/analyzer → parser, cfg, dfg, taint, math/cpg, math/anomaly
       → detection/{patterns, statistical, ml, combiner, line-locator, llm-agent}
       → llm/{router, providers/*, security, consensus, audit}
       → plugin/{registry, pipeline, builtins}
       → threat/{model-generator, stride-mapper, threat-pipeline}
       → threatmodel/{stride, dfd}
       → benchmark/{evaluator, synthetic-dataset}
       → utils/rng
```

---

## 8. Configuration

### `config/vule.yaml`

YAML template consumed by `loadConfig()`. Sections: `uvrs.weights`, `thresholds`, `dimensions.enabled`, `llm`, `cache`, `report`.

### `config/cpg-sinks.yaml`

Catalog of dangerous sink functions used by `CPGBuilder` to flag `is_sink = 1` features.

### `vule.config.json`

Created by `cmdInit()` at workspace root. Holds `llm.defaultProvider`, `llm.defaultModel`, `llm.routerStrategy`, `evolution.maxRounds`, `evolution.gaPopulation`, `detection.zscoreThreshold`, `detection.confidenceThreshold`, `detection.maxDepth`.

---

## 9. CI/CD Integration

### GitHub Action (`.github/action/action.yml`)

Composite action that runs `security-vule scan`, emits SARIF to GitHub Code Scanning, optionally runs PoC verification, optionally comments results.

### `.github/workflows/security-vule.yml`

Workflow that runs on push/PR, uploads SARIF, auto-updates baseline on main.

### `.gitlab-ci.d/security-vule.yml`

Remote-include template for GitLab CI / SAST.

### PoC runtime (`poc-validator/`)

- **`mock_dvwa.py`** — zero-dep Python server emulating DVWA endpoints for SQLi/LFI/CMDi/XSS/upload verification.
- **`verify_poc.py`** — consumes a findings JSON, drives exploits against the target, writes a verification report.
- **`vuln_db.json`** — vulnerability database mapping vuln types to PoC templates.
- **`real-apps/docker-compose.yml`** — Docker Compose for DVWA / bWAPP / sqli-labs / Pikachu.

---

## 10. Test Layout (`tests/`)

| Path | Coverage |
|---|---|
| `tests/llm/{ai-bom, audit, chaos, consensus, integration, metrics, security}.test.ts` | LLM subsystem |
| `tests/threatmodel/{dfd, stride}.test.ts` | Legacy STRIDE/DFD |
| `tests/unit/benchmark/benchmark.test.ts` | Benchmark evaluator |
| `tests/unit/detection/{combiner, detector, line-locator, rag-index, statistical}.test.ts` | Detection ensemble |
| `tests/unit/engine/cpg/{builder, metrics, queries, smoke, types}.test.ts` | Cosmic-galaxy CPG |
| `tests/unit/engine/dimensions/{base, dark-matter, entropy, gravity, information, kepler, nbody, orbital, p0-integration, p1p2-integration, perturbation, quantum, registry, relativistic, tidal, topology}.test.ts` | Every dimension + integration tests |
| `tests/unit/engine/{cfg, parser-ast, program-graph, taint-ast, vule-config, vule-engine}.test.ts` | Engine core |
| `tests/unit/evolution/ga-evolver.test.ts` | GA evolver |
| `tests/unit/integration/celestial-viz.test.ts` | Visualization |
| `tests/unit/llm/{openai-compatible, router}.test.ts` | LLM router / compat |
| `tests/unit/math/{anomaly, controlflow, cosm-x-project-analyzer-dedup, cosm-x-theory-23d, cpg, dataflow, entropy, graph-metrics, matching, run-evaluate, taint}.test.ts` | Math layers L1/L2/L3 |
| `tests/unit/mcp/server.test.ts` | MCP server |
| `tests/unit/plugin/plugin.test.ts` | Plugin registry/pipeline |
| `tests/unit/threat/{graph-query, model-generator, stride-mapper, trust-boundary}.test.ts` | Threat pipeline |
| `tests/unit/utils/rng.test.ts` | Deterministic RNG |
| `tests/v3-compat.test.ts` | v3 backwards-compat re-exports |

Run with `bun test`.

---

## 11. Documentation Index (`docs/`)

- `REDESIGN.md` — v3.0 architecture (L1/L2/L3 math layers).
- `design-philosophy.md` — cosmic-galaxy theoretical design.
- `math-underneath.md` — math behind the dimensions.
- `theoretical-validation.md` — theory vs ground truth.
- `RECURSIVE-MATH-VERIFICATION.md` — recursive mathematical verification.
- `SESSION-*.md` — sprint notes.
- `benchmark-report.md`, `competitive-analysis-*.md`, `all-tools-scores.md`, `top5-whitebox-comparison.md`, `whitebox-tool-comparison.md`, `three-tool-comparison.md`, `ai-tools-comparison.md` — benchmark + tool comparisons.
- `poc-verification.md`, `poc-tools-research.md` — runtime verification methodology.
- `expert-recommendations.md`, `ai-security-expert-recommendations.md` — security expert assessments.
- `owasp-ai-security-contribution.md` — OWASP alignment.
- `threat-model-pipeline-design.md` — pipeline design notes.
- `gap-analysis-sv-llm-vs-glm.md`, `llm-mode-gap-analysis.md` — LLM-mode analyses.
- `docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md` — cosmic-galaxy design spec.
- `docs/plans/vulnerability-mining-plan.md` — product plan.
- `theory/dimensions/*.md` — per-dimension theory (gravity, kepler, …).

---

## 12. How to Run / Extend

### Run a scan

```bash
bun install
bun run src/cli.ts scan ./src --sarif --output results.sarif
```

### Start the MCP server

```bash
bun run src/mcp/server.ts
# now drive it with any JSON-RPC 2.0 client over stdio
```

### Run the test suite

```bash
bun test
```

### Run a benchmark

```bash
bun run benchmark:eval
# or
bun --bun src/integration/benchmark.ts
```

### Run the evolutionary loop

```bash
bun run src/evolution/evolver.ts       # 10,000 rounds
bun run src/evolution/ga-evolver.ts    # GA variant
```

### Add a new dimension detector

1. Create `src/engine/dimensions/<name>.ts` extending `BaseDimension`.
2. Set `name`, `weight`, implement `compute(node, cpg) → number ∈ [0, 1]`.
3. Register in `src/engine/dimensions/registry.ts → DIMENSIONS`.
4. Add `theory/dimensions/<name>.md` explaining the formula.
5. Add a unit test under `tests/unit/engine/dimensions/<name>.test.ts`.

### Add a new plugin

1. Decide phase: `probe` / `detector` / `generator`.
2. Implement `PluginFactory` returning your `Plugin`.
3. Register via `PluginRegistry.register(meta, factory)`.
4. (Optionally) ship as a built-in in `src/plugin/builtins/`.
5. Drive with `PluginPipeline.run(code, filePath, config)`.

### Add a new LLM provider

1. Implement `ILLMProvider` (interface in `src/llm/types.ts`).
2. Add `registerProvider(id, provider)` to your `LLMRouter` config, **or**
3. Add a factory helper in `src/llm/providers/openai-compatible.ts` if it speaks the OpenAI Chat Completions API (recommended path).

### Add a new vulnerability pattern

- Add a row to `ALL_RULES` in `src/detection/patterns.ts` (with `rule_id`, `source`, `sink`, `pattern`, `confidence`, `cwe`, `languages`).
- For more elaborate rules, extend `WEAK_PATTERNS` in `src/engine/analyzer.ts`.

---

## 13. License

AGPL-3.0 — see [`LICENSE`](../LICENSE).

Commercial / enterprise licensing is offered by the project for organizations needing different terms, private redistribution, managed-service use, or broader deployment options.