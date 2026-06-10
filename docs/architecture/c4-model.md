# security-vule Architecture (C4 Model)

> Auto-generated diagrams (mermaid) for security-vule v0.3.0.
> Last updated: 2026-06-10

This document uses the [C4 model](https://c4model.com/) to describe the security-vule architecture at four levels:
1. **Context** — how security-vule fits in the world
2. **Container** — major runnable units
3. **Component** — internal modules of the VuleEngine
4. **Code** — key classes and their relationships

---

## Level 1: System Context

```mermaid
graph TB
    User[Security Engineer / DevOps]
    Dev[Software Developer]
    Auditor[Security Auditor]

    SV[security-vule<br/>🌌 Cosmic-galaxy aligned<br/>vulnerability scanner]

    GHA[GitHub Actions]
    GLA[GitLab CI]
    SIEM[Splunk/ELK SIEM]

    LLM[LLM Providers<br/>MiniMax / GLM / Claude / Ollama]

    TS[Trough Tools<br/>GitHub Code Scanning<br/>SARIF v2.1.0]

    POC[PoC Validator<br/>Playwright + curl]

    User -->|CLI commands<br/>vule analyze| SV
    Dev -->|Pre-commit hook| SV
    Auditor -->|HTML reports| SV

    SV -->|SARIF output| TS
    SV -->|Scan results| SIEM
    SV -->|CI scanning| GHA
    SV -->|CI scanning| GLA
    SV -->|LLM API calls| LLM
    SV -->|PoC verification| POC
```

**Key actors**:
- **Security Engineer**: Primary user, runs scans and reviews results
- **Software Developer**: Pre-commit hook integration
- **Security Auditor**: Reviews HTML reports and risk analysis
- **CI/CD Systems**: GitHub Actions, GitLab CI for automated scanning
- **External systems**: LLM providers, GitHub Code Scanning, SIEM, PoC validation

---

## Level 2: Container Diagram

```mermaid
graph TB
    subgraph "security-vule Distribution"
        CLI[vule CLI<br/>TypeScript + Commander<br/>5 commands]
        Server[Web UI Server<br/>Bun.serve + REST API<br/>port 3000]
        Lib[Library API<br/>TypeScript exports<br/>VuleEngine, CPGBuilder, etc.]
    end

    subgraph "Built-in Engines"
        AST[AST Analyzer<br/>tree-sitter<br/>21 vuln types]
        LLM[LLM Agent<br/>specialized prompts<br/>verify pass]
        Cos[29 Dimensions<br/>cosmic-galaxy UVRS<br/>sigmoid fusion]
    end

    subgraph "External Services"
        LLM[LLM APIs<br/>OpenAI-compatible]
        Git[GitHub<br/>SARIF + Releases]
    end

    subgraph "Targets"
        Code[Source Code<br/>PHP/Python/JS/TS]
        Docker[Docker<br/>DVWA/bWAPP/<br/>sqli-labs/Pikachu]
    end

    CLI --> AST
    CLI --> LLM
    CLI --> Cos
    Server --> Cos
    Lib --> AST
    Lib --> Cos
    CLI -->|reads| Code
    CLI -->|exports| Git
    Server -->|reads| Code
    Docker -.->|PoC| CLI
    LLM -.->|API calls| LLM
```

**Key containers**:
- **vule CLI**: Main entry point, 5 commands (analyze, dimension, visualize, server, list-dimensions)
- **Web UI Server**: Long-running Bun.serve exposing /healthz, /metrics, HTML dashboard
- **Library API**: TypeScript exports for programmatic integration
- **29 Dimension Detectors**: Cosmic-galaxy-aligned risk scoring
- **AST Analyzer**: tree-sitter-based fast static analysis (5s)
- **LLM Agent**: Slow but high-recall semantic analysis with verify pass

---

## Level 3: Component Diagram (VuleEngine)

```mermaid
graph TB
    subgraph "Entry Layer"
        CLI[vule CLI<br/>commander]
        Server[Web UI Server]
    end

    subgraph "VuleEngine"
        Engine[VuleEngine<br/>analyze/topRisk<br/>exportReport]
        Config[VuleConfig<br/>YAML loader]
        Report[VuleReport<br/>JSON/MD exporters]
    end

    subgraph "UVRS"
        UVRS[UVRS Engine<br/>sigmoid fusion]
        RiskLevel[RiskLevel<br/>enum]
    end

    subgraph "Dimension Registry"
        Registry[Registry<br/>getEnabledDimensions<br/>normalizeWeights]
        Base[BaseDimension<br/>abstract]
        P0[4 P0<br/>gravity/kepler/<br/>orbital/nbody]
        P1[5 P1<br/>perturbation/tidal/<br/>relativistic/darkMatter/entropy]
        P2[3 P2<br/>quantum/topology/<br/>information]
        P3[10 P3<br/>chaos/phaseTransition/...]
        MF[6 math frameworks<br/>typeTheory/functor/<br/>tda/pureFunctional/<br/>abstractInterpret/symbolicExec]
    end

    subgraph "CPG Core"
        CPG[CPG<br/>5 edge kinds]
        Types[types.ts<br/>interfaces]
        Builder[CPGBuilder<br/>from ProgramGraph]
        Queries[queries.ts<br/>bfs/dfs/allPaths/<br/>downstream/upstream]
        Metrics[metrics.ts<br/>pagerank/betweenness/<br/>degreeStats]
        Sinks[sinks.ts<br/>dangerous functions]
    end

    subgraph "LLM Pipeline"
        Agent[LLMAgent<br/>specialized prompts]
        Verify[verifyFindings<br/>AI FP filter]
        Router[LLM Router<br/>8 providers]
    end

    CLI --> Engine
    Server --> Engine
    Engine --> Config
    Engine --> Registry
    Engine --> UVRS
    Engine --> Report
    Engine --> CPG

    Registry --> Base
    Base --> P0
    Base --> P1
    Base --> P2
    Base --> P3
    Base --> MF

    Registry --> CPG
    P0 --> CPG
    P1 --> CPG
    P2 --> CPG
    P3 --> CPG
    MF --> CPG

    CPG --> Types
    CPG --> Builder
    CPG --> Queries
    CPG --> Metrics
    CPG --> Sinks

    Engine -.->|optional| Agent
    Agent --> Verify
    Agent --> Router
```

**Key components**:
- **VuleEngine** is the single entry point that orchestrates CPG + dimensions + UVRS
- **Registry** is the dimension catalog (29 detectors)
- **CPG core** is the data substrate (5 edge kinds, 5 query methods, 3 metrics)
- **LLM pipeline** is optional, used for higher recall

---

## Level 4: Code Diagram (Key Classes)

```mermaid
classDiagram
    class VuleEngine {
        +CPG cpg
        +string[] sinks
        +VuleConfig config
        +UVRS uvrs
        +analyze() VuleReport
        +computeUVRS(nodeId) ComputeResult
        +topRiskNodes(k) NodeReport[]
        +exportReport(path) string
    }

    class UVRS {
        +UVRSWeights weights
        +RiskThresholds thresholds
        +compute(components) UVRSResult
        +classify(score) RiskLevel
        +getRiskDistribution(scores) Record
    }

    class CPG {
        +Map~string,CPGNode~ nodes
        +CPGEdge[] edges
        +getNode(id) CPGNode
        +outEdges(id, kind) CPGEdge[]
        +inEdges(id, kind) CPGEdge[]
        +shortestPath(from, to) string[]
        +sinkNodes() CPGNode[]
        +sourcesFor(sinkId) CPGNode[]
        +inDegree(id) number
    }

    class BaseDimension {
        <<abstract>>
        +string name
        +number weight
        +compute(node, cpg) number*
    }

    class GravityDimension {
        +weight = 0.20
        +compute() number
    }

    class KeplerDimension {
        +weight = 0.15
        +compute() number
    }

    class VuleConfig {
        +UVRSWeightsConfig weights
        +RiskThresholdsConfig thresholds
        +dimensions enabled
    }

    class VuleReport {
        +string version
        +NodeReport[] topRisk
        +Record~RiskLevel,number~ riskDistribution
    }

    VuleEngine --> CPG
    VuleEngine --> UVRS
    VuleEngine --> VuleConfig
    VuleEngine --> VuleReport
    BaseDimension <|-- GravityDimension
    BaseDimension <|-- KeplerDimension
    CPG --> BaseDimension : queries via
```

**Key relationships**:
- VuleEngine composes CPG + UVRS + VuleConfig
- All dimensions extend BaseDimension (abstract)
- CPG provides query API used by all dimensions
- VuleReport is the output of VuleEngine.analyze()

---

## Data Flow: Scan → PoC

```mermaid
sequenceDiagram
    participant User
    participant CLI as vule CLI
    participant Engine as VuleEngine
    participant CPG
    participant Dim as 29 Dimensions
    participant UVRS
    participant LLM as LLM Provider
    participant POC as PoC Validator

    User->>CLI: vule analyze test.php
    CLI->>Engine: construct with CPG
    Engine->>CPG: build() via CPGBuilder
    CPG-->>Engine: CPG (5 edge kinds)

    loop for each node
        Engine->>Dim: compute(node, cpg)
        Dim-->>Engine: 0..1 risk
    end

    Engine->>UVRS: compute(components)
    UVRS-->>Engine: score, level, dominant

    alt LLM mode enabled
        Engine->>LLM: analyzeVulnerabilities()
        LLM-->>Engine: findings + verify pass
    end

    Engine-->>CLI: VuleReport

    CLI->>POC: verify exploitability
    POC-->>User: confirmed vulnerabilities
```

**Key data flow**:
1. CLI parses target file → constructs CPG
2. For each CPG node, all 29 dimensions compute their risk contribution
3. UVRS fuses the contributions via sigmoid
4. Optional LLM pass adds semantic analysis with verify filter
5. VuleReport is generated
6. Optional PoC validation confirms exploitability

---

## Deployment View

```mermaid
graph LR
    subgraph "User Machine"
        Bun[Bun Runtime]
        CLI[vule CLI]
    end

    subgraph "Docker Image"
        Img[security-vule:0.3<br/>oven/bun:1-slim<br/>~150MB]
    end

    subgraph "CI/CD Pipeline"
        CI[GitHub Actions]
        SBOM[CycloneDX SBOM<br/>v1.5]
        Sarif[SARIF Report]
    end

    subgraph "Observability"
        Prom[Prometheus<br/>13 metrics]
        Tempo[OpenTelemetry<br/>OTLP traces]
        Loki[Loki / Grafana<br/>pino structured logs]
    end

    Bun --> CLI
    Img --> Bun
    CI --> Img
    CI --> SBOM
    CI --> Sarif
    CLI --> Prom
    CLI --> Tempo
    CLI --> Loki
```

**Deployment options**:
- **CLI**: Direct Bun invocation on user machine
- **Docker**: Multi-arch (amd64+arm64) image, ~150MB
- **CI/CD**: GitHub Actions runs docker, exports SARIF + SBOM
- **Observability**: Prometheus scrapes /metrics, Tempo collects OTLP traces, Loki ingests pino logs

---

## Cross-cutting Concerns

```mermaid
mindmap
  root((security-vule<br/>v0.3.0))
    AI Safety
      Prompt injection detection (12 patterns)
      Secret redaction (17 patterns)
      XML isolation in LLM prompts
      Sensitive data never logged
    Performance
      AST: 5s for 1000 files
      LLM: 49s per file
      Caching: SHA-256 keyed
      Incremental: git diff
    Quality
      813 tests pass (94 files)
      73% line coverage
      15 property-based tests
      0 any types
      TypeScript strict
    Security
      AGPL-3.0 license
      No GPL contamination
      SBOM published per release
      Dependabot weekly updates
      SECURITY.md disclosure policy
```

**Cross-cutting concerns** that span all components:
- **AI Safety**: Every LLM call is wrapped in safety checks
- **Performance**: Caching, incremental, async pipeline
- **Quality**: Strict TypeScript, property-based tests, lint clean
- **Security**: SBOM, license check, secret scanning, Dependabot

---

## See Also

- [docs/design-philosophy.md](../design-philosophy.md) — cosmic-galaxy design philosophy
- [docs/engineering-roadmap-v1.0.md](../engineering-roadmap-v1.0.md) — 12-week engineering plan
- [docs/evolution-roadmap-v1.0.md](../evolution-roadmap-v1.0.md) — 12-month feature plan
- [docs/v0.3-competitive-comparison.md](../v0.3-competitive-comparison.md) — competitive analysis
- [C4 model](https://c4model.com/) — Simon Brown's architecture framework
