# security-vule LLM Mode Gap Analysis vs State-of-the-Art

> Analysis date: 2026-06-09
> Compared tools: vulnhuntr (ProtectAI, 2,674★), Anthropic defending-code-reference-harness (5,473★), truscan, codescan, ai-security-scanner, pwnkit, agent-smith, LuaN1aoAgent
> Source: GitHub repos + security-vule codebase (`src/llm/`, `src/detection/llm-agent.ts`, `src/engine/taint.ts`)

---

## 1. Current security-vule LLM Mode Architecture

```
File → redactSecrets() → detectPromptInjection() → buildAnalysisPrompt() → LLM API call → JSON parse → validateFinding() → Output
         ↓                      ↓                         ↓                                              ↓                    ↓
    17 patterns          12 jailbreak           taint paths injected                    single-shot          18-type whitelist
                                                 "report ONE per file"                 no retry         line range check
```

**What it has:**
- XML isolation (`<file>` tags) + UNTRUSTED DATA system prompt
- Taint analysis results injected into LLM context (source → sink paths)
- "Report at most ONE primary vulnerability per file" constraint
- Secret redaction (17 patterns) before LLM call
- Prompt injection detection (12 patterns, risk scoring)
- Finding validation (18 canonical types, line range checks, suspicious output detection)
- Multi-model consensus (two LLMs agree for CRITICAL/HIGH findings)
- Rate limiting + cost cap ($5/scan, 1M tokens)
- Audit logging (no code content, only hash + size)
- MITRE ATLAS defense mapping
- 8 LLM providers (OpenAI, Anthropic, Google, Ollama, DeepSeek, Qwen, GLM, Moonshot)
- LLM router with failover/round-robin/latency-based/cost-based strategies

---

## 2. Gap Analysis: Missing Capabilities

### 2.1 Per-Vuln-Type Specialized Prompts

**State-of-the-art (vulnhuntr):**
- 7 dedicated prompt templates: LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR
- Each template lists specific focus areas (high-risk functions, bypass techniques)
- Each template includes **concrete bypass payloads** as examples:
  ```
  LFI: ["../../../../etc/passwd", "/proc/self/environ", "data://text/plain;base64,..."]
  RCE: ["__import__('os').system('id')", "eval('__import__(\\'os\\').popen(\\'id\\')...')"]
  SSRF: ["http://0.0.0.0:22", "file:///etc/passwd", "dict://127.0.0.1:11211/"]
  ```
- LLM uses `<example_bypasses>` XML tags to reason about bypass feasibility

**security-vule current:**
- One generic prompt for all vulnerability types
- No bypass examples in prompt
- No per-type analysis instructions

**Impact:** Without type-specific focus areas, the LLM misses edge-case patterns (e.g., SSRF via DNS rebinding, LFI via PHP filters). The generic prompt produces generic analysis.

**Implementation effort:** Medium (~200 lines). Create a `VULN_PROMPTS` map with per-type templates and bypass examples, similar to vulnhuntr's `VULN_SPECIFIC_BYPASSES_AND_PROMPTS`.

---

### 2.2 Autonomous Context Collection Loop (Multi-Round)

**State-of-the-art (vulnhuntr):**
```
Initial file analysis → LLM requests more context (symbol names) → Symbol resolver fetches code → Feed back to LLM → Repeat up to 7 rounds → Final report
```
- LLM outputs `<context_code>` field listing class/function names it needs
- `symbol_finder.py` uses `jedi` library for Python symbol resolution
- Three-tier search: `file_search` → `project_search` → `all_names_search`
- Resolves class instances, alias imports, module symbols
- Each round builds on previous analysis (`<previous_analysis>` tags)

**security-vule current:**
- Single-shot: one LLM call per file
- No ability for LLM to request additional context
- Taint analysis provides some context but is intra-procedural only
- No cross-file code resolution

**Impact:** The single biggest gap. Without context collection, the LLM cannot trace data flows across function boundaries or files. This limits detection to "obvious" vulnerabilities visible in a single function.

**Implementation effort:** Large (~500 lines). Requires:
1. Extend `ChatMessage` with structured context-request fields
2. Build a symbol resolver (can leverage existing `program-graph.ts` edges)
3. Implement the multi-round loop in `LLMAgent.analyzeVulnerabilities()`
4. Track accumulated context across rounds

---

### 2.3 Multi-Finding Per File (Controlled)

**State-of-the-art:**
- vulnhuntr: Reports multiple findings per file with per-finding confidence (0-10)
- Anthropic harness: Reports all findings with structured exploit_scenario per finding
- agent-smith: Reports up to 20 findings per file with coverage matrix

**security-vule current:**
- `"Report at most ONE primary vulnerability per file"` — this was an intentional choice that improved F1 from 64.3% → 77.1% by reducing tangential FPs
- But it means secondary vulnerabilities are completely missed

**Impact:** The ONE-per-file constraint was the highest-leverage prompt engineering decision (cut raw findings by 60% while increasing TPs). However, a **controlled multi-finding** mode would be better for:
- Files with multiple distinct vulnerability types (e.g., SQLi + XSS + CSRF in one controller)
- Files where the secondary finding is also critical

**Implementation effort:** Small (~50 lines). Add a `--max-findings-per-file` flag (default: 1 for precision, configurable up to 5). Change prompt from "at most ONE" to "at most N, ranked by severity".

---

### 2.4 Structured Reasoning Chain (Scratchpad)

**State-of-the-art (vulnhuntr):**
```json
{
  "scratchpad": "Step-by-step reasoning about the vulnerability...",
  "analysis": "Final analysis after reviewing all context",
  "vulnerability_types": ["LFI", "RCE"],
  "context_code": ["ClassName1", "func_name"],
  "findings": [...]
}
```
- LLM produces reasoning BEFORE conclusions (chain-of-thought)
- Scratchpad is separate from final analysis
- Context requests are structured (class names, function names)

**security-vule current:**
- No reasoning chain. LLM outputs findings directly
- No `scratchpad` or `analysis` field
- Strips `<think/>` tags from some models but doesn't use structured reasoning

**Impact:** Without chain-of-thought, the LLM has no opportunity to "think through" the data flow before jumping to conclusions. This reduces both precision (hallucinated findings) and recall (missed complex flows).

**Implementation effort:** Small (~80 lines). Add `scratchpad` and `analysis` fields to the prompt schema. Use the Anthropic prefill trick (`{"scratchpad": "1.`) to force structured reasoning.

---

### 2.5 CWE Classification with Confidence Scoring

**State-of-the-art:**
- vulnhuntr: Per-finding confidence score (0-10) with detailed justification
- Anthropic harness: Maps to OWASP Top 10 + CWE with `exploit_scenario`
- ai-security-scanner: CodeBERT embedding similarity + CWE matching

**security-vule current:**
- Asks LLM for `cwe` and `owasp` fields but doesn't validate them
- No CWE-to-finding confidence scoring
- No CWE database for validation
- `validateFinding()` checks `type` (18 canonical types) but not `cwe`

**Impact:** CWEs are often wrong (LLM hallucinates CWE-89 for SQL injection that's actually CWE-564). Without validation, downstream consumers (SARIF, GitHub Code Scanning) get incorrect metadata.

**Implementation effort:** Medium (~150 lines). Create a CWE validation map:
```typescript
const TYPE_TO_CWE: Record<string, string[]> = {
  'SQL Injection': ['CWE-89', 'CWE-564', 'CWE-20'],
  'Command Injection': ['CWE-78', 'CWE-77', 'CWE-20'],
  // ...
};
```
Validate that reported CWE matches the vulnerability type. Add confidence scoring for CWE match.

---

### 2.6 CVSS-Like Severity Assessment

**State-of-the-art:**
- Anthropic harness: Uses exploit_scenario + impact assessment
- agent-smith: ASVS 5.0 mapping with chapter/requirement classification
- truscan: Framework-aware severity (Flask vs Django vs FastAPI)

**security-vule current:**
- 5-tier severity: critical/high/medium/low/info
- No numeric scoring (no CVSS vector)
- No exploitability assessment
- No framework-aware severity adjustment
- No attack complexity or privilege requirements scoring

**Impact:** Severity is subjective — what the LLM calls "critical" might be "medium" in context (e.g., SQLi on a public API vs internal admin tool). Without CVSS-like vectors, triage is unreliable.

**Implementation effort:** Medium (~200 lines). Add CVSS-like vector to prompt output:
```json
{
  "cvss_lite": {
    "attack_vector": "network|local|physical",
    "complexity": "low|high",
    "privileges": "none|low|high",
    "user_interaction": "none|required",
    "scope": "changed|unchanged"
  }
}
```
Map CVSS-lite to severity automatically.

---

### 2.7 False Positive Reduction via AI Verification Pass

**State-of-the-art (truscan):**
```
Semgrep findings → LLM analyzes each finding → classifies as true_positive or false_positive → Confidence threshold filter (0.7) → Enhanced remediation
```
- Dedicated AI engine for FP filtering
- Per-finding analysis with code context
- Framework-aware remediation (detects Flask/Django/FastAPI)
- Batch processing + caching

**State-of-the-art (ai-security-scanner):**
- `check_false_positive()` method on `LLMProvider`
- CodeBERT embedding similarity for finding clustering
- Reliability patterns (circuit breaker, retry, timeout)

**security-vule current:**
- `validateFinding()` does basic structural checks (type whitelist, line range)
- No AI-powered FP verification
- No second-pass triage
- Consensus mode exists but requires 2 full analysis calls (expensive)

**Impact:** security-vule standalone has 50% precision (13 TP / 26 findings on DVWA). An AI FP filter could potentially reduce FPs by 60-80%, bringing precision to 80%+ without losing recall.

**Implementation effort:** Large (~400 lines). Requires:
1. New `verifyFinding()` method that sends finding + code context to LLM
2. Prompt: "Given this code and this finding, is this a true positive or false positive? Rate confidence 0-1."
3. Framework detection module (identify Flask/Django/Express/Laravel patterns)
4. Batch processing for efficiency

---

### 2.8 Incremental/Diff-Based Scanning

**State-of-the-art:**
- Anthropic harness: Analyzes git diffs, not full files
- codescan: `scan_git_diff` MCP tool
- OCR (alibaba): Built on git diff review
- truscan: Git branch comparison

**security-vule current:**
- Full file analysis every time
- No git diff awareness
- No baseline management
- No incremental caching

**Impact:** In CI/CD, scanning unchanged files is wasteful. For a 10,000-file repo, only ~50 files change per PR. Full scan is 200x more expensive than diff scan.

**Implementation effort:** Medium (~300 lines). Requires:
1. Git integration (`git diff --name-only` to get changed files)
2. Baseline file format (`security-vule baseline save/load`)
3. Only scan files not in baseline or changed since baseline
4. Diff context (±3 lines around changes) fed to LLM

---

### 2.9 LLM Response Caching

**State-of-the-art (aiscan):**
- Diskcache with SHA-256 prompt hash as key
- Cache hit → instant response, zero cost
- Cache invalidation on prompt change

**security-vule current:**
- No LLM response caching
- Same file scanned twice = two full API calls

**Impact:** During development/testing, the same files are scanned repeatedly. Caching saves 80%+ of API costs during iteration.

**Implementation effort:** Small (~100 lines). Implement a disk-based cache:
```typescript
const cacheKey = sha256(messages.map(m => m.content).join(''));
const cached = await cache.get(cacheKey);
if (cached) return cached;
// ... call LLM ...
await cache.set(cacheKey, response);
```

---

### 2.10 Attack Chain / Data Flow Narrative

**State-of-the-art (vulnhuntr + Anthropic harness):**
```
Source: $_GET['id'] (line 7, user_input)
  → $id = $_GET['id'] (line 8, assignment)
  → $query = "SELECT * FROM users WHERE id=" . $id (line 12, concatenation)
  → mysqli_query($conn, $query) (line 13, SQL execution)
Sanitizers: none
Confidence: 9/10
```

**security-vule current:**
- Taint paths are injected into prompt but as raw data:
  ```
  - Source: $_GET['id'] (line 7, type: user_input) → Sink: mysqli_query (line 13, type: sql), confidence: 85%
  ```
- No narrative attack chain in output
- No source-to-sink step-by-step trace

**Impact:** Without a human-readable attack chain, security reviewers cannot verify findings quickly. The taint data is there but not formatted for consumption.

**Implementation effort:** Small (~60 lines). Format taint paths as numbered steps in the prompt and ask LLM to verify/expand each step.

---

### 2.11 CWE-to-Remediation Mapping

**State-of-the-art (truscan):**
- Framework-aware remediation: "In Flask, use parameterized queries with `db.execute('SELECT ... WHERE id=?', (id,))`"
- Detects Flask/Django/FastAPI and adjusts remediation

**security-vule current:**
- Asks LLM for generic `remediation` field
- No framework detection
- No CWE-to-fix mapping
- `suggestFix()` exists but is generic

**Impact:** Generic remediation ("use parameterized queries") is less actionable than framework-specific ("use `$stmt = $pdo->prepare('SELECT ... WHERE id=:id'); $stmt->execute([':id' => $id]);`").

**Implementation effort:** Medium (~200 lines). Detect framework from imports/dependencies, inject framework-specific remediation guidance into prompt.

---

### 2.12 LangGraph-Style Pipeline Orchestration

**State-of-the-art (codescan):**
```python
graph = StateGraph(FileAnalysisState)
graph.add_edge(START, "rule_scan")
graph.add_edge("rule_scan", "llm_scan")
graph.add_edge("llm_scan", "merge_and_finalize")
graph.add_edge("merge_and_finalize", END)
```

**security-vule current:**
- No formal pipeline. `LLMAgent.analyzeVulnerabilities()` is a monolithic method
- Static analysis and LLM analysis run independently
- No merge/dedup between static and LLM findings
- No state management between pipeline stages

**Impact:** Without a formal pipeline, it's hard to add new stages (FP filter, triage, verification) or control data flow between them.

**Implementation effort:** Large (~500 lines). Implement a pipeline:
```
rule_scan → taint_analysis → llm_analysis → merge_and_dedup → fp_filter → triage → report
```
Each stage has typed input/output and can be independently enabled/disabled.

---

## 3. Prioritized Improvement Roadmap

### Tier 1: High Impact, Low Effort (Implement in 1-2 days each)

| # | Capability | Impact on F1 | Effort | Files to modify |
|---|-----------|-------------|--------|-----------------|
| 1 | **Controlled multi-finding** (N per file, default 1) | +5% recall | Small | `llm-agent.ts` |
| 2 | **LLM response caching** (SHA-256 key, diskcache) | Cost -80% | Small | New `cache.ts` |
| 3 | **Scratchpad reasoning** (CoT before conclusions) | +3% precision | Small | `llm-agent.ts` prompt |
| 4 | **Attack chain narrative** in output | UX +10x | Small | `llm-agent.ts` prompt |
| 5 | **CWE validation map** (type→CWE whitelist) | +2% precision | Medium | `security.ts` |

### Tier 2: High Impact, Medium Effort (Implement in 3-5 days each)

| # | Capability | Impact on F1 | Effort | Files to modify |
|---|-----------|-------------|--------|-----------------|
| 6 | **Per-vuln-type specialized prompts** | +8% recall | Medium | New `prompts.ts` |
| 7 | **AI false-positive verification pass** | +15% precision | Large | New `fp-filter.ts` |
| 8 | **CVSS-lite severity assessment** | Better triage | Medium | `llm-agent.ts` prompt |
| 9 | **Incremental/diff-based scanning** | Cost -90% in CI | Medium | New `incremental.ts` |
| 10 | **Framework-aware remediation** | Better fixes | Medium | New `framework-detect.ts` |

### Tier 3: Transformational, Large Effort (Implement in 1-2 weeks each)

| # | Capability | Impact on F1 | Effort | Files to modify |
|---|-----------|-------------|--------|-----------------|
| 11 | **Autonomous context collection loop** (7-round) | +20% recall | Large | `llm-agent.ts` + new `symbol-resolver.ts` |
| 12 | **Pipeline orchestration** (LangGraph-style) | Architecture | Large | New `pipeline.ts` + refactor |
| 13 | **Cross-file data flow tracing** | +25% recall | Very Large | `program-graph.ts` + `taint.ts` |

---

## 4. Concrete Prompt Engineering Gaps

### 4.1 What vulnhuntr's prompts have that security-vule doesn't

| Feature | vulnhuntr | security-vule | Gap |
|---------|-----------|---------------|-----|
| Per-type templates (7) | ✅ | ❌ (1 generic) | Critical |
| Bypass examples per type | ✅ (5-7 per type) | ❌ | High |
| Structured scratchpad | ✅ | ❌ | High |
| Context request mechanism | ✅ (`<context_code>`) | ❌ | Critical |
| Previous analysis accumulation | ✅ (`<previous_analysis>`) | ❌ | High |
| README summary for attack surface | ✅ | ❌ | Medium |
| Confidence scoring (0-10) | ✅ | ✅ (0.0-1.0) | None |
| PoC in prompt | ✅ | ❌ | Medium |
| Pydantic output validation | ✅ | ❌ (manual JSON parse) | Medium |

### 4.2 What the Anthropic harness has that security-vule doesn't

| Feature | Anthropic harness | security-vule | Gap |
|---------|-------------------|---------------|-----|
| Focus areas per finding | ✅ (OWASP categories) | ❌ | Medium |
| Exploit scenario | ✅ | ❌ | High |
| Proof of concept | ✅ (LLM-generated) | ✅ (templated) | Low |
| Detailed recommendation | ✅ | ✅ | None |
| Confidence justification | ✅ | ❌ | Medium |
| Multi-file scope | ✅ (harness iterates) | ❌ (per-file) | High |

---

## 5. Recommended Prompt Architecture

Replace the current monolithic prompt with a **3-phase prompt chain**:

```
Phase 1: CLASSIFY
  Input: File code (with line numbers) + taint paths
  Output: { "vulnerability_types": ["SQLI", "XSS"], "confidence": [0.8, 0.3] }
  Purpose: Narrow the analysis scope — which vuln types are present?

Phase 2: ANALYZE (per type, with specialized template)
  Input: File code + type-specific template + bypass examples + taint paths for that type
  Output: { "findings": [...], "scratchpad": "...", "context_requests": [...] }
  Purpose: Deep analysis per type with chain-of-thought

Phase 3: VERIFY (for findings above threshold)
  Input: Finding + code context + framework detection
  Output: { "is_true_positive": true, "confidence": 0.9, "attack_chain": [...], "remediation_framework_specific": "..." }
  Purpose: False positive reduction + framework-aware fixes
```

This is closer to what vulnhuntr does (classify → analyze → verify) and would address 6 of the 12 gaps above.

---

## 6. Quick Wins (Can implement in < 1 day total)

### 6.1 Add bypass examples to prompt (30 minutes)

In `buildAnalysisPrompt()`, add after the JSON schema:

```typescript
const BYPASS_EXAMPLES: Record<string, string[]> = {
  'SQL Injection': ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT username, password FROM users--"],
  'Command Injection': ["; cat /etc/passwd", "$(whoami)", "`id`", "| ls -la"],
  'Cross-Site Scripting (XSS)': ["<script>alert(1)</script>", "{{7*7}}", "javascript:alert(1)"],
  'Path Traversal': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
  'File Inclusion': ["php://filter/convert.base64-encode/resource=index", "data://text/plain;base64,..."],
  'Server-Side Request Forgery': ["http://169.254.169.254/latest/meta-data/", "http://0.0.0.0:22"],
};
```

### 6.2 Add scratchpad field to prompt (15 minutes)

Change the JSON schema in the system prompt to include:
```json
{
  "scratchpad": "<your step-by-step reasoning about data flows>",
  "analysis": "<your final assessment>",
  "findings": [...],
  "summary": "..."
}
```

### 6.3 CWE validation (45 minutes)

In `validateFinding()`, add CWE validation:
```typescript
const TYPE_CWE_MAP: Record<string, string[]> = {
  'SQL Injection': ['CWE-89', 'CWE-564'],
  'Command Injection': ['CWE-78', 'CWE-77'],
  'Cross-Site Scripting (XSS)': ['CWE-79'],
  'Path Traversal': ['CWE-22', 'CWE-73'],
  // ...
};
```

### 6.4 Controlled multi-finding (30 minutes)

Change prompt from "Report at most ONE" to "Report at most N findings, ranked by exploitability. Only report findings you are confident about." Add `maxFindings` parameter to `buildAnalysisPrompt()`.

---

## 7. Summary: What security-vule's LLM Mode is Missing

| Category | Missing | Priority |
|----------|---------|----------|
| **Prompt Engineering** | Per-vuln-type templates, bypass examples, scratchpad reasoning, README attack surface analysis | P0 |
| **Multi-Round Analysis** | Autonomous context collection, symbol resolution, cross-file code fetching (up to 7 rounds) | P0 |
| **Finding Quality** | AI false-positive verification, CWE validation, CVSS-lite scoring, framework-aware remediation | P1 |
| **Output Granularity** | Controlled multi-finding (N per file), attack chain narrative, structured PoC generation | P1 |
| **Scanning Efficiency** | LLM response caching, incremental/diff scanning, pipeline orchestration | P2 |
| **Cross-File Analysis** | Symbol resolution, inter-procedural taint, call graph traversal | P2 |

**The single highest-ROI improvement** is implementing per-vuln-type specialized prompts with bypass examples (Item 6 in Tier 2). This requires no architecture changes — just better prompt content — and would improve recall by 5-10% based on vulnhuntr's results.

**The single most transformative improvement** is the autonomous context collection loop (Item 11 in Tier 3). This is what makes vulnhuntr capable of finding zero-day vulnerabilities — the LLM can reason about code it hasn't been given yet by requesting it. However, this requires significant new infrastructure (symbol resolver, multi-round loop, context management).
