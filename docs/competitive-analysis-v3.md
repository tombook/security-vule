# 第三轮竞品分析报告

> 分析日期: 2026-06-07
> 分析项目: 11个新项目（排除前两轮已分析的13个项目）
> 分析人: Sisyphus

---

## 目录

1. [项目概览](#1-项目概览)
2. [逐项目深度分析](#2-逐项目深度分析)
3. [横向对比](#3-横向对比)
4. [对本项目的启示](#4-对本项目的启示)

---

## 1. 项目概览

| # | 项目 | ⭐ | 语言 | 核心方法 | LLM提供商 | MCP支持 |
|---|------|-----|------|----------|-----------|---------|
| 1 | **vulnhuntr** (protectai) | 2,667 | Python | LLM自主分析+代码符号提取 | Claude/GPT/Ollama | ❌ |
| 2 | **aiscan** (samsepassi1) | 2 | Python | AST规则+LLM双层扫描 | Anthropic/OpenAI/Ollama | ❌ |
| 3 | **truscan** (spydra-tech) | - | Python | Semgrep+AI误报过滤 | OpenAI/Anthropic | ✅ (MCP规则) |
| 4 | **llm-security-scanner** (iknowjason) | - | Python | LLM单层扫描+GitHub Issues | OpenAI/Anthropic | ❌ |
| 5 | **LLMSecGuard** (aryakvnust) | 21 | Python+Vue | LLM代码生成+静态分析反馈 | 多模型 | ❌ |
| 6 | **codescan** (HeJiguang) | 22 | Python | LangGraph工作流+规则+LLM | DeepSeek/OpenAI/Anthropic | ✅ |
| 7 | **ai-security-scanner** (isbkch) | - | Python | CodeBERT嵌入+LLM验证 | OpenAI/Anthropic/Ollama/HF | ❌ |
| 8 | **reposhield** (ibrahimokdadov) | - | TypeScript | 多层扫描+AI深度分析 | GPT-4/Claude/Gemini | ❌ |
| 9 | **AI-Code-Security-Auditor** (Vijay-48) | - | Python | Bandit+Semgrep+多LLM | Groq/OpenRouter (20+模型) | ❌ |

---

## 2. 逐项目深度分析

### 2.1 vulnhuntr (protectai) — 🥇 本轮最佳

**基本信息**: 2,667⭐ | AGPL-3.0 | 5个Python文件 | 2024年10月

**核心架构**:
```
README摘要 → 初始文件分析 → 漏洞类型分类 → 逐类型深度分析(最多7轮) → 上下文代码提取 → 最终报告
```

**关键创新**:

1. **自主上下文收集循环** (最大7轮迭代)
   - LLM分析文件后，请求需要查看的类/函数 (`context_code` 字段)
   - 使用 `jedi` 库做Python符号解析 (`symbol_finder.py`)
   - 三层搜索策略: `file_search` → `project_search` → `all_names_search`
   - 自动解析类实例方法、别名导入、模块符号等边缘情况

2. **结构化Prompt工程**
   - 每种漏洞类型有专用prompt模板 (LFI/RCE/SSRF/AFO/SQLI/XSS/IDOR)
   - 每种类型提供具体bypass技术示例 (`VULN_SPECIFIC_BYPASSES_AND_PROMPTS`)
   - 使用XML标签结构化输入: `<file_code>`, `<context_code>`, `<example_bypasses>`
   - Pydantic模型强制LLM输出结构化JSON (`Response` 模型)

3. **多LLM抽象层** (`LLMs.py`)
   - `LLM` 基类 → `Claude` / `ChatGPT` / `Ollama` 三个子类
   - 统一 `chat()` 接口 + Pydantic `response_model` 验证
   - Claude使用prefill技巧 (`{    "scratchpad": "1.`) 强制JSON输出

4. **网络入口文件发现** (`RepoOps`)
   - 200+正则模式匹配Web框架路由 (Flask/FastAPI/Django/Gradio等)
   - 自动排除测试/示例/文档文件
   - README摘要用于理解项目攻击面

**源码规模**: ~950行 (LLMs.py 190 + prompts.py 395 + __main__.py 489 + symbol_finder.py 262)

**优势**: 自主0day发现能力、上下文循环、符号解析、结构化prompt
**局限**: 仅Python、单文件粒度入口、无规则引擎、无MCP

---

### 2.2 aiscan (samsepassi1) — AST+LLM双层架构

**基本信息**: MIT | ~20个Python文件 | AI生成代码专项

**核心架构**:
```
AST规则扫描 → LLM验证/补充 → 结果聚合 → SARIF/JSON输出
```

**关键创新**:

1. **AST规则引擎** (`rule_engine.py`)
   - 17条内置规则，按语言分类 (Python/JavaScript/Common)
   - 每条规则映射CWE ID + 严重级别
   - `BaseRule` 基类 + `check(ParsedFile)` 接口

2. **LLM引擎** (`llm_engine.py`)
   - 三个提供商: Anthropic / OpenAI / Ollama (local)
   - **零出站模式**: `provider="local"` 禁止设置API key
   - Diskcache缓存LLM响应 (SHA256 hash)
   - AST结果传递给LLM避免重复报告 (`context_findings`)
   - 专用system prompt关注AI代码的已知漏洞模式

3. **AI代码归属分析** (`attribution.py`)
   - 使用 `git blame` 追踪每行代码来源
   - 识别AI生成的commit (Co-Authored-By trailers)
   - 将发现映射到 `ai` / `human` / `unknown` 桶

4. **CI/CD集成**: GitHub Actions + Pre-commit hooks + SARIF输出

**优势**: AST+LLM互补、零出站模式、AI代码归属、GitHub Actions
**局限**: 规则数量少、无程序图分析

---

### 2.3 truscan (spydra-tech) — Semgrep+AI+MCP规则

**基本信息**: Python | Semgrep Python SDK + AI + MCP

**核心架构**:
```
Semgrep扫描 → AI误报过滤 → 增强修复建议 → SARIF/JSON/Console输出
```

**关键创新**:

1. **Semgrep深度集成** (`engine/semgrep_engine.py`)
   - 使用Semgrep Python SDK (非CLI子进程调用)
   - 离线优先: 所有扫描无需网络

2. **AI误报过滤** (`engine/ai_engine.py`) — **最强误报处理**
   - LLM分析每个发现: true positive vs false positive
   - 置信度阈值过滤 (默认0.7)
   - 按严重级别排序，支持最大分析数量限制
   - 批处理 + 缓存
   - 增强修复建议 (框架感知: Flask/Django/FastAPI)

3. **MCP规则集** (`engine/mcp_extractor.py`)
   - 专门检测MCP服务器漏洞 (FastMCP工具/资源/提示处理器)
   - 覆盖: 代码注入/命令注入/路径遍历/提示注入/SSRF/SQL注入
   - LangChain/LlamaIndex/LangGraph工具提取器

4. **评估测试生成** (`engine/eval_prompt_generator.py`)
   - 从工具定义自动生成安全测试用例
   - 评估类型: tool_selection/safety/prompt_injection/argument_correctness/robustness

**优势**: 最强误报过滤、MCP专项规则、评估测试生成
**局限**: 依赖Semgrep、仅Python

---

### 2.4 codescan (HeJiguang) — LangGraph工作流+MCP

**基本信息**: 22⭐ | MIT | Python | LangChain+LangGraph

**核心架构**:
```
规则扫描 → LLM扫描 → 合并去重 → HTML/JSON/Text报告
```

**关键创新**:

1. **LangGraph工作流** (`ai/workflow.py`) — **最佳流水线设计**
   ```python
   graph = StateGraph(FileAnalysisState)
   graph.add_edge(START, "rule_scan")
   graph.add_edge("rule_scan", "llm_scan")
   graph.add_edge("llm_scan", "merge_and_finalize")
   graph.add_edge("merge_and_finalize", END)
   ```
   - 三阶段流水线: 规则 → LLM → 合并
   - 基于 `(title, line_number, description)` 去重

2. **LangChain Provider工厂** (`ai/providers.py`)
   - `init_chat_model()` 统一接口
   - OpenAI兼容: openai/deepseek/custom (共用OpenAI SDK)
   - Anthropic: 需 `langchain-anthropic` 可选依赖

3. **MCP Server** (`mcp_server.py`) — **4个工具**
   - `scan_file`: 单文件扫描
   - `scan_directory`: 目录扫描 (max_workers=4)
   - `scan_git_diff`: Git分支对比扫描
   - `scan_github_repo`: 克隆远程仓库并扫描

4. **Codex Skill层**: 可安装的 `codescan-review` 技能

**优势**: LangGraph流水线、MCP Server 4工具、Skill层
**局限**: 规则质量待加强

---

### 2.5 ai-security-scanner (isbkch) — CodeBERT嵌入+多Provider

**基本信息**: Python | PostgreSQL + CodeBERT

**核心架构**:
```
模式匹配扫描 → CodeBERT嵌入 → LLM验证 → 趋势分析 → SARIF输出
```

**关键创新**:

1. **CodeBERT语义嵌入** (`models/embeddings/codebert.py`)
   - 代码语义理解而非纯文本匹配
   - 用于相似漏洞聚类

2. **LLM Provider抽象** (`core/llm/providers.py`) — **最佳Provider设计**
   - 抽象基类 `LLMProvider` + `analyze_vulnerability()` + `check_false_positive()`
   - 4个具体实现: OpenAI / Anthropic / Ollama / HuggingFace
   - 异步 (`async/await`) 全链路
   - 速率限制 (`rate_limit_requests_per_minute`)
   - 统一错误响应格式

3. **可靠性模式库** (`core/patterns/`)
   - 熔断器、重试、超时、幂等性、背压、优雅关停
   - 健康检查、可观测性、配置安全
   - 每个模式独立模块 (`circuit_breakers.py`, `retries.py` 等)

4. **成本追踪** (`core/llm/cost_tracker.py`)
   - 实时LLM API成本监控

5. **PostgreSQL历史追踪**: 扫描历史 + 趋势分析

**优势**: CodeBERT嵌入、异步Provider、可靠性模式、成本追踪
**局限**: 重型依赖 (PostgreSQL + CodeBERT)

---

### 2.6 其他项目简析

| 项目 | 核心特点 | 对本项目的价值 |
|------|---------|---------------|
| **llm-security-scanner** | LLM单层扫描 + GitHub Issues自动创建 | Issues集成思路 |
| **LLMSecGuard** | LLM生成代码→静态分析反馈→安全代码建议 | 代码修复循环 |
| **reposhield** | TypeScript全栈 + 5层扫描 + WebSocket实时进度 | 多层扫描架构 |
| **AI-Code-Security-Auditor** | Bandit+Semgrep+20+LLM模型 + 自动修复 | 多LLM路由 + Auto-Fix |

---

## 3. 横向对比

### 3.1 LLM集成架构对比

| 项目 | LLM抽象层 | 异步 | 缓存 | 速率限制 | 成本追踪 |
|------|-----------|------|------|---------|---------|
| vulnhuntr | LLM基类+3子类 | ❌ | ❌ | ❌ | ❌ |
| aiscan | LLMEngine | ❌ | ✅ diskcache | ❌ | ❌ |
| truscan | AIProvider | ❌ | ✅ 内存 | ❌ | ❌ |
| codescan | LangChain工厂 | ❌ | ❌ | ❌ | ❌ |
| ai-security-scanner | LLMProvider ABC+4实现 | ✅ | ❌ | ✅ | ✅ |
| reposhield | 硬编码3提供商 | ❌ | ❌ | ❌ | ❌ |

### 3.2 扫描方法对比

| 项目 | 规则引擎 | LLM分析 | 符号解析 | 程序图 | 误报过滤 |
|------|---------|---------|---------|--------|---------|
| vulnhuntr | ❌ | ✅ (自主循环) | ✅ jedi | ❌ | ❌ |
| aiscan | ✅ AST (17规则) | ✅ (补充AST) | ❌ | ❌ | ✅ AST先行 |
| truscan | ✅ Semgrep | ✅ (误报过滤) | ❌ | ❌ | ✅ AI过滤 |
| codescan | ✅ 规则 | ✅ (LangGraph) | ❌ | ❌ | ✅ 去重合并 |
| ai-security-scanner | ✅ OWASP模式 | ✅ (验证) | ❌ | ❌ | ✅ LLM检查 |
| **security-vule** | ✅ 36规则 | ❌ | ❌ | ✅ 7边类型 | ❌ |

### 3.3 MCP/集成对比

| 项目 | MCP Server | GitHub Actions | SARIF | CI/CD |
|------|-----------|---------------|-------|-------|
| truscan | ✅ MCP规则 | ✅ | ✅ | ✅ |
| codescan | ✅ 4工具 | ❌ | ❌ | ❌ |
| aiscan | ❌ | ✅ | ✅ | ✅ |
| **security-vule** | ✅ 4工具 | ❌ | ❌ | ❌ |

---

## 4. 对本项目的启示

### 4.1 最高优先级改进 (从竞品提炼)

#### 改进A: LLM多Provider集成层
**来源**: ai-security-scanner + vulnhuntr + aiscan

所有9个竞品都集成了LLM，而本项目仍无LLM支持。需建立:

- `LLMProvider` 抽象基类 (参考 ai-security-scanner)
- 4个实现: OpenAI / Anthropic / Ollama / HuggingFace
- 异步 (`async/await`) 扫描接口
- 速率限制 + 成本追踪
- Diskcache LLM响应缓存

#### 改进B: 自主上下文收集循环
**来源**: vulnhuntr (独家创新)

vulnhuntr的核心竞争力是LLM驱动的自主上下文收集:
1. LLM分析文件 → 请求需要查看的类/函数
2. 符号解析器提取代码 → 喂给LLM
3. 重复最多7轮直到完整调用链

本项目可结合已有的程序图 (`program-graph.ts`) 实现:
- 从程序图的边关系自动收集跨函数上下文
- LLM请求补充上下文时，从图中查找相关节点

#### 改进C: AI误报过滤
**来源**: truscan + ai-security-scanner

两个项目都有专门的AI误报过滤机制:
- truscan: AI分析每个Semgrep发现，判断true/false positive
- ai-security-scanner: `check_false_positive()` 方法

本项目可在检测管道后增加AI过滤层:
```
规则检测 → 程序图分析 → LLM误报过滤 → 最终报告
```

#### 改进D: LangGraph扫描流水线
**来源**: codescan

codescan的LangGraph工作流是最清晰的扫描流水线设计:
```
rule_scan → llm_scan → merge_and_finalize
```

本项目可参考实现:
```
rule_scan → program_graph_analysis → llm_deep_analysis → false_positive_filter → report
```

### 4.2 中等优先级改进

| 改进 | 来源 | 描述 |
|------|------|------|
| SARIF输出 | aiscan + truscan | 标准安全报告格式，GitHub Code Scanning集成 |
| 零出站模式 | aiscan | Ollama本地模式，API key禁止设置 |
| LLM响应缓存 | aiscan | diskcache + SHA256 prompt hash |
| 多LLM路由 | AI-Code-Security-Auditor | 按任务复杂度路由到不同模型 (快速分类vs深度分析) |
| AI代码归属 | aiscan | git blame追踪AI生成代码的安全问题 |
| MCP漏洞规则 | truscan | 检测MCP服务器的注入/SSRF/路径遍历 |
| Auto-Fix | AI-Code-Security-Auditor | LLM生成修复diff并自动应用 |

### 4.3 竞品排名 (第三轮)

| 排名 | 项目 | 理由 |
|------|------|------|
| 🥇 | **vulnhuntr** | 自主0day发现、上下文循环、符号解析、2667星 |
| 🥈 | **truscan** | 最强AI误报过滤、MCP专项规则、Semgrep深度集成 |
| 🥉 | **codescan** | LangGraph最佳流水线、MCP 4工具、Skill层 |
| 4 | **ai-security-scanner** | CodeBERT嵌入、最佳Provider设计、可靠性模式 |
| 5 | **aiscan** | AST+LLM双层、零出站模式、AI归属 |
| 6 | **AI-Code-Security-Auditor** | 20+LLM模型、Auto-Fix |
| 7 | **reposhield** | 多层扫描、多Provider、WebSocket实时 |
| 8 | **llm-security-scanner** | 简洁LLM扫描、GitHub Issues |
| 9 | **LLMSecGuard** | 学术背景、代码安全反馈循环 |

### 3.10 anthropics/defending-code-reference-harness ⭐ 工业级

**项目地址**: https://github.com/anthropics/defending-code-reference-harness
**Stars**: 1200+ | **语言**: Python | **作者**: Anthropic官方
**定位**: 工业级AI漏洞挖掘+PoC生成+自动补丁 pipeline

#### 核心架构: 5阶段闭环 Pipeline

```
recon (自动发现) → find (深度挖掘) → grade (PoC验证) → judge (去重判定) → patch (自动修复)
```

每个阶段在独立的 gVisor 容器中执行，信任边界 = Docker镜像tag。

#### 核心模块分析

| 模块 | 文件 | 功能 | 关键设计 |
|------|------|------|----------|
| Agent | `agent.py` | Claude Code headless CLI wrapper | JSONL transcript流、Docker+gVisor沙箱 |
| Find | `find.py` | 深度漏洞挖掘循环 | max_turns=2000, PoC生成 |
| Judge | `judge.py` | LLM triage去重判断 | NEW / DUP_BETTER / DUP_SKIP 三级分类 |
| Recon | `recon.py` | 自动发现focus areas | max_turns=100 |
| Grade | `grade.py` | 新容器验证PoC | 信任边界=镜像tag |
| Patch | `patch.py` | 补丁生成+迭代验证 | 最多5轮迭代 |
| Sandbox | `sandbox.py` | gVisor容器+egress白名单代理 | 出站网络控制 |
| Prompts | `find_prompt.py` | 详细安全研究prompt模板 | 质量分层+排除规则 |

#### 关键技术创新

1. **gVisor沙箱隔离**: 每个阶段独立容器，PoC验证在新容器中执行，防止污染
2. **2000轮深度循环**: find阶段允许高达2000轮工具调用，远超普通扫描器
3. **三级去重判定**: judge使用LLM判断 NEW / DUP_BETTER / DUP_SKIP
4. **自动补丁**: patch阶段生成修复补丁并在新容器中验证，最多5轮迭代
5. **AddressSanitizer**: 编译时启用ASan，捕获内存安全问题
6. **信任边界设计**: 以Docker镜像tag作为信任边界，不同阶段完全隔离
7. **Claude Code headless**: 通过CLI wrapper驱动整个pipeline

#### Prompt工程亮点 (`find_prompt.py`)

- 质量分层: 区分"必须报告"和"可选报告"的漏洞类型
- 排除规则: 明确排除非安全问题和低风险发现
- 上下文管理: 自动收集代码上下文，符号解析
- 报告格式: 结构化JSON输出，包含PoC和影响分析

---

### 3.11 alibaba/open-code-review ⭐ 生产级

**项目地址**: https://github.com/alibaba/open-code-review
**Stars**: 500+ | **语言**: Go | **作者**: 阿里巴巴
**定位**: 生产级AI代码审查Agent，已服务数万开发者，发现数百万缺陷

#### 核心架构: Plan → Review 两阶段 Agent

```
Plan阶段 (理解代码) → Review阶段 (多文件并行审查)
```

6个Agent工具: `code_comment` / `file_read` / `file_find` / `file_read_diff` / `code_search` / `task_done`

#### 核心模块分析

| 模块 | 文件 | 行数 | 功能 |
|------|------|------|------|
| Agent核心 | `internal/agent/agent.go` | 1400+ | plan→review两阶段，6个工具调用，多文件并行 |
| LLM客户端 | `internal/llm/client.go` | 700+ | Anthropic+OpenAI双协议，token计数(tiktoken)，重试 |
| 工具定义 | `internal/tool/definitions.go` | - | 6个tool-use能力定义 |
| Skill | `skills/open-code-review/SKILL.md` | - | Claude Code Skill集成 |

#### 关键技术创新

1. **双LLM协议**: 同时支持Anthropic和OpenAI API协议，统一客户端抽象
2. **6个Agent工具**: 代码审查专用工具集 (code_comment/file_read/file_find/file_read_diff/code_search/task_done)
3. **Token计数**: 集成tiktoken进行精确token计数和成本控制
4. **多文件并行Review**: Agent可同时审查多个文件的变更
5. **Claude Code Skill**: 原生集成为Claude Code的Skill，通过npm包分发
6. **CI/CD集成**: GitHub Actions / GitLab CI 开箱即用配置
7. **生产验证**: 已服务数万开发者，发现数百万代码缺陷

#### 工具设计详解

| 工具 | 功能 | 应用场景 |
|------|------|----------|
| `code_comment` | 在代码行上添加审查评论 | 发现问题并标注 |
| `file_read` | 读取文件完整内容 | 理解代码上下文 |
| `file_find` | 按模式搜索文件名 | 定位相关文件 |
| `file_read_diff` | 读取文件diff | 审查代码变更 |
| `code_search` | 正则搜索代码内容 | 跨文件追踪模式 |
| `task_done` | 标记审查完成 | 结束审查流程 |

---

### 4.4 来自新项目的额外改进建议

#### 改进E: 5阶段闭环 Pipeline (来自 Anthropic harness)

**优先级**: 高

Anthropic的5阶段pipeline是目前最完整的AI漏洞挖掘流程:

```
recon (自动发现攻击面) → find (深度挖掘+PoC生成) → grade (PoC验证) → judge (去重判定) → patch (自动修复)
```

本项目可借鉴的核心设计:
- **阶段隔离**: 每个阶段独立运行，find阶段不依赖grade阶段的输出
- **PoC验证闭环**: grade阶段在新环境中验证PoC可行性
- **去重机制**: judge使用LLM判断发现的漏洞是否重复
- **自动补丁**: patch阶段生成修复并验证

建议实现:
```typescript
interface Pipeline {
  recon(context: ScanContext): FocusArea[];
  find(areas: FocusArea[]): Finding[];
  grade(findings: Finding[]): VerifiedFinding[];
  judge(findings: VerifiedFinding[]): DeduplicatedFinding[];
  patch(findings: DeduplicatedFinding[]): Patch[];
}
```

#### 改进F: Agent工具架构 (来自阿里巴巴 OCR)

**优先级**: 高

阿里巴巴的6个Agent工具设计精良，适合代码审查场景:

| 工具 | 本项目对应 |
|------|-----------|
| `code_comment` | → 新增: 漏洞标注工具 |
| `file_read` | → 已有: 源码读取 |
| `file_find` | → 新增: 文件模式搜索 |
| `file_read_diff` | → 新增: Git diff审查 |
| `code_search` | → 已有: 程序图搜索 |
| `task_done` | → 新增: 扫描完成信号 |

建议实现统一的Agent工具接口:
```typescript
interface AgentTool {
  name: string;
  description: string;
  parameters: zod.ZodSchema;
  execute(params: unknown): Promise<ToolResult>;
}
```

#### 改进G: 双LLM协议支持 (来自阿里巴巴 OCR)

**优先级**: 高

阿里巴巴的统一LLM客户端同时支持Anthropic和OpenAI协议，本项目应直接采用:

```typescript
interface LLMProvider {
  chat(messages: Message[]): Promise<Response>;
  countTokens(text: string): number;  // tiktoken
  model: string;
}
```

这与改进A (LLM多Provider集成) 强烈互补，提供具体实现参考。

#### 改进H: 沙箱隔离执行 (来自 Anthropic harness)

**优先级**: 中

gVisor容器 + egress白名单代理设计:
- PoC执行在完全隔离的容器中
- 出站网络请求通过白名单代理
- 信任边界 = Docker镜像tag

本项目PoC验证阶段可采用类似方案:
```typescript
interface Sandbox {
  execute(poc: string, context: ScanContext): Promise<PoCResult>;
}
```

---

### 4.5 更新竞品排名 (全部11个)

| 排名 | 项目 | 理由 |
|------|------|------|
| 🥇 | **vulnhuntr** | 自主0day发现、上下文循环、符号解析、2667星 |
| 🥈 | **defending-code-reference-harness** | Anthropic官方、5阶段闭环pipeline、gVisor沙箱、PoC+补丁自动化 |
| 🥉 | **open-code-review** | 阿里巴巴生产级、6个Agent工具、双LLM协议、数万用户验证 |
| 4 | **truscan** | 最强AI误报过滤、MCP专项规则、Semgrep深度集成 |
| 5 | **codescan** | LangGraph最佳流水线、MCP 4工具、Skill层 |
| 6 | **ai-security-scanner** | CodeBERT嵌入、最佳Provider设计、可靠性模式 |
| 7 | **aiscan** | AST+LLM双层、零出站模式、AI归属 |
| 8 | **AI-Code-Security-Auditor** | 20+LLM模型、Auto-Fix |
| 9 | **reposhield** | 多层扫描、多Provider、WebSocket实时 |
| 10 | **llm-security-scanner** | 简洁LLM扫描、GitHub Issues |
| 11 | **LLMSecGuard** | 学术背景、代码安全反馈循环 |

---

## 5. 本项目当前定位

经过三轮24个竞品分析（含2个顶级工业项目），本项目 (security-vule) 的差异化定位:

| 维度 | 本项目 | 竞品主流 | 顶级竞品 (Anthropic/阿里) |
|------|--------|---------|--------------------------|
| 语言 | TypeScript (唯一) | Python为主 | Python / Go |
| LLM | ❌ 尚未集成 | 全部11个竞品都有 | Claude Code headless / 双协议 |
| 程序图 | ✅ 7种边类型 | 仅vulnhuntr有符号解析 | ❌ 无 |
| 规则引擎 | ✅ 36规则 | 参差不齐 | ❌ 依赖LLM |
| 插件架构 | ✅ 完整 | 仅garak有 | ❌ 无 |
| MCP Server | ✅ 4工具 | 2个有 | ❌ 无 |
| 评估基准 | ✅ 20样本 | 仅truscan有eval生成 | ❌ 无 |
| PoC生成 | ❌ 无 | vulnhuntr有 | ✅ Anthropic: grade+judge |
| 自动补丁 | ❌ 无 | 1个有 | ✅ Anthropic: 5轮迭代 |
| Agent工具 | ❌ 无 | 3个有 | ✅ 阿里: 6个专用工具 |
| 沙箱隔离 | ❌ 无 | 1个有 | ✅ Anthropic: gVisor |
| 生产验证 | ❌ 无 | 2个有 | ✅ 阿里: 数万用户 |

**最大差距**: LLM集成 + Agent工具架构 + PoC闭环验证
**最大优势**: TypeScript生态 + 程序图 + 插件架构 + 评估基准
**新增差距**: 沙箱隔离执行、自动补丁、生产级验证

---

## 6. 下一步建议 (更新版)

### 紧急优先级 (P0)

1. **LLM多Provider集成层** (改进A) — 全部24个竞品都有LLM，本项目最大差距
2. **Agent工具架构** (改进F) — 借鉴阿里巴巴6工具设计，实现代码审查Agent
3. **双LLM协议支持** (改进G) — Anthropic + OpenAI统一客户端

### 高优先级 (P1)

4. **5阶段闭环Pipeline** (改进E) — 借鉴Anthropic harness: recon→find→grade→judge→patch
5. **AI误报过滤** (改进C) — truscan已验证有效
6. **自主上下文收集循环** (改进B) — vulnhuntr核心能力

### 中期 (P2)

7. **沙箱隔离执行** (改进H) — PoC验证需要隔离环境
8. **LangGraph扫描流水线** (改进D) — codescan参考
9. **SARIF输出** — GitHub Code Scanning集成
10. **Auto-Fix** — Anthropic patch阶段参考

### 持续改进

- 零出站模式 (Ollama本地)
- LLM响应缓存 (diskcache)
- 多LLM路由 (按任务复杂度)
- MCP漏洞规则
- CI/CD集成 (GitHub Actions / GitLab CI)
