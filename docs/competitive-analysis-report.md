# AI 漏洞挖掘竞品深度分析报告

> **日期**: 2026-06-07  
> **目标**: GitHub 上 7 个 AI 漏洞挖掘项目 vs CosmX Galaxy (security-vule) 深度对比分析  
> **方法**: 下载源码到本地，逐个读取核心引擎代码，分析架构与方法论

---

## 一、竞品概览

| # | 项目 | 语言 | 核心方法 | Stars | 许可证 |
|---|------|------|---------|-------|--------|
| 1 | **Phoenix** (by CREDIT-COMPLIANCE) | Python | 三 Agent 协同 (Slicer→Reverser→Judge) | 研究级 | MIT |
| 2 | **BayreuthWing** | Python | 混合引擎: CodeTransformer(25M) + 静态规则 + Code Flow | 研究级 | MIT |
| 3 | **VulnHawk** | Python | LLM 上下文增强扫描 (chunk + 相关代码 + 认证模式) | 新兴 | Apache-2.0 |
| 4 | **Heimdall** | Rust | 9 阶段管线 + Agent 循环 + 静态污点分析 + Sandbox | 新兴 | FSL |
| 5 | **c-vulnerability-detection** | Python | BGRU + HAN Attention 深度学习 | 研究级 | MIT |
| 6 | **SAIST** | Python | 多 LLM 后端扫描 + SCM 集成 | 新兴 | MIT |
| 7 | **Metis** (by Arm) | Python | RAG + LlamaIndex + 向量检索 + TreeSitter 可达性 | 工业级 (Arm) | Apache-2.0 |

---

## 二、逐项深度分析

### 1. Phoenix — 三 Agent 行为合约验证

**架构**: `agent1_slicer.py` → `agent2_reverser.py` → `agent3_judge.py`

**核心流程**:
1. **Slicer**: 从漏洞报告中提取 "behavioral contract"（前置条件 + 后置条件 + 不变式）
2. **Reverser**: 将合约反向映射到代码片段，定位潜在违规
3. **Judge**: 最终裁判，综合合约与代码判断是否存在漏洞

**源码关键发现**:
- `agent1_slicer.py`: 使用结构化 prompt 从 CVE/NVD 描述中提取 `<precondition>`, `<postcondition>`, `<invariant>` 标签
- `agent2_reverser.py`: 反向工程，将合约映射到函数/代码块
- `agent3_judge.py`: 使用 Chain-of-Thought 推理，综合判断，输出 verdict + confidence
- **无需训练** — 纯 prompt 工程，依赖 LLM 推理能力

**性能**: F1=0.825 (论文数据，在 D2A/CVE 数据集上)

**优势**:
- 训练无关 (training-free)，部署简单
- 行为合约概念有学术创新性
- 三 Agent 分工明确，各司其职

**弱点**:
- 完全依赖 LLM 质量，幻觉风险高
- 无静态分析兜底
- 无法发现合约之外的漏洞类型
- 依赖已有的漏洞报告/CVE 描述，无法发现 0-day
- 单文件/函数粒度分析，缺乏跨过程流追踪

---

### 2. BayreuthWing — 混合引擎 (最接近 CosmX 的竞品)

**架构**: `scanner/engine.py` (编排器) + `model/transformer.py` (CodeTransformer) + `scanner/analyzer.py` (Code Flow)

**核心组件**:
1. **CodeTransformer (25M 参数)**: 
   - 自定义 Transformer 架构，输入代码序列，输出漏洞概率
   - 使用代码 token embedding + position encoding
   - 支持多种编程语言
2. **静态规则引擎**: 预定义漏洞模式匹配 (regex + AST pattern)
3. **Code Flow Analyzer**: 追踪函数调用链、数据依赖关系
4. **Finding Merger**: 合并多个分析通道的发现，去重+排序
5. **Severity Calculator**: 基于多维度评分的严重度计算

**源码关键发现** (`engine.py`):
```python
class HybridScanner:
    def scan(self, files):
        ml_findings = self.model.predict(files)      # CodeTransformer 推理
        static_findings = self.analyzer.analyze(files) # 静态规则
        flow_findings = self.flow_analyzer.trace(files) # Code Flow
        merged = self.merger.merge(ml_findings, static_findings, flow_findings)
        return self.severity_calculator.rank(merged)
```

**与 CosmX Galaxy 的关键差异**:
| 维度 | BayreuthWing | CosmX Galaxy |
|------|-------------|-------------|
| ML 模型 | CodeTransformer 25M (通用) | 统计+ML 混合分类器 + GA 进化 |
| 数学模型 | 无 | 宇宙学数学模型 (开普勒/引力/潮汐/摄动) |
| 图分析 | Code Flow (函数级) | CPG + CFG + DFG (全程序级) |
| 污点分析 | 无 | 完整污点传播引擎 |
| 评分 | Severity Calculator | 23 维 UVRS 评分体系 |
| 进化优化 | 无 | GA 演化优化检测规则 |

**优势**:
- 最成熟的混合架构竞品
- CodeTransformer 可增量训练
- 三通道融合降低误报
- 工程化程度较高

**弱点**:
- 无数学模型抽象层
- Code Flow 仅追踪函数调用，不做全程序数据流
- 无进化优化机制
- 模型规模较大 (25M)，推理成本高
- 评分体系较简单

---

### 3. VulnHawk — LLM 上下文增强扫描

**架构**: `vulnhawk/scanner/engine.py` (核心引擎)

**核心方法**: Chunk-based LLM scanning with context enrichment
1. 将代码文件切分为 chunks
2. 对每个 chunk 附加三类上下文:
   - **Related chunks**: 同文件中与当前 chunk 相关的其他代码段
   - **Auth patterns**: 检测认证/授权模式
   - **Import context**: 导入依赖分析
3. 使用 LLM 对每个 chunk + context 进行漏洞扫描
4. 结果聚合 + 去重

**源码关键发现** (`engine.py`):
```python
class ScannerEngine:
    def scan_file(self, file_path, content):
        chunks = self.chunker.chunk(content)
        for chunk in chunks:
            context = self.context_builder.build(chunk, content)
            # context = {
            #   "related_chunks": [...],
            #   "auth_patterns": [...],
            #   "imports": [...]
            # }
            result = self.llm.analyze(chunk, context)
            findings.extend(result.findings)
        return self.deduplicator.deduplicate(findings)
```

**优势**:
- 上下文增强减少 LLM 幻觉
- 认证模式检测有针对性
- 实现简洁，易于扩展

**弱点**:
- 纯 LLM 依赖，无静态/数学分析
- Chunk 切分可能切断数据流
- 无跨文件流追踪
- 无评分/严重度模型
- 性能瓶颈在 LLM API 调用

---

### 4. Heimdall — Rust 9 阶段管线 (工程化最强的竞品)

**架构**: 9 阶段管线 (Rust 实现)
```
Index → Tyr(攻击面发现) → Hunt(Agent调查) → Static Analysis → Taint Analysis → 
Dependency → Sandbox → Report → Export
```

**核心组件深入分析**:

#### 4.1 Hunt Agent (`hunt/agent.rs` — 695 行)
- **Agent Loop**: 迭代式 LLM 调用，最多 25 轮
- **状态机**: Planning → AwaitingLLM → ExecutingTool → ReportingFinding → Completed
- **工具调用**: Agent 可调用 read_file, search_code, trace_callers 等工具
- **Finding 报告**: 通过 `report_finding` 工具提交，必须包含 code_snippet + suggested_patch + fix_summary
- **LLM 配置**: temperature=0.3, max_tokens=4096
- **Prompt 设计**: 将攻击面描述 + 代码库概览 + 静态分析上下文注入 system prompt

#### 4.2 Taint Analyzer (`taint/mod.rs` — 784 行)
- **Source 定义**: 硬编码 30+ source patterns，覆盖 Python/JS/Go/Java/Rust
  - Python: request.args, request.form, input(), sys.argv, os.environ
  - JS: req.body, req.query, document.location, process.argv
  - Go: r.URL.Query, r.FormValue, r.Body
  - Java: request.getParameter, request.getHeader
  - Rust: web::Json, web::Query, web::Path
- **Sink 定义**: SQL/Command/XSS/Deserialization/FileAccess 分类
- **传播算法**: 固定点迭代 (最多 10 轮)，变量级追踪
- **变量提取**: 支持 let/const/var 声明，= 赋值，:= 短声明
- **限制**: 仅单文件内追踪，无跨文件/跨过程传播

#### 4.3 Tyr (攻击面发现)
- 通过 LLM 分析代码结构，识别 API endpoints、输入处理函数、权限检查点
- 输出 AttackSurface: name, risk_level, endpoint, file, line, description

**优势**:
- **Rust 实现** — 性能优势显著，内存安全
- **9 阶段管线** — 最完整的工程化流程
- **Agent + Taint + Static 三重验证** — 降低误报
- **Sandbox 验证** — 可运行 PoC 验证漏洞
- **DB 持久化** — 所有 agent 交互、tool call、LLM 用量都入库

**弱点**:
- 污点分析仅限单文件，无跨过程传播
- Agent 依赖 LLM，25 轮上限可能不足
- 无 ML 模型辅助
- 无数学/统计评分模型
- 硬编码 source/sink 列表，扩展需改代码重编译
- FSL 许可证限制商用

---

### 5. c-vulnerability-detection — BGRU + HAN Attention

**架构**: 纯深度学习方案

**核心模型** (`model/bgru.py`):
- **Embedding Layer**: vocab_size → embedding_dim
- **Bidirectional GRU**: 多层双向 GRU，正交初始化
- **HAN Attention**: Hierarchical Attention Network，多头注意力 (4 heads)
- **Residual Connection**: attention output + max-pooling output
- **LayerNorm**: 训练稳定性
- **FC 分类器**: feature_dim → fc_hidden_dim → 2 classes (vulnerable/safe)

**模型特点**:
- 输入: 代码 token 序列
- 输出: 二分类 (有漏洞/无漏洞)
- 参数量: 相对较小 (embedding + GRU + attention + FC)
- 正交初始化: `nn.init.orthogonal_` 用于 GRU 权重

**优势**:
- 端到端学习，无需手动规则
- 双向 GRU 捕获前后文依赖
- HAN Attention 可解释注意力权重
- 正交初始化提升训练稳定性

**弱点**:
- **纯序列模型** — 无 AST/CFG/DFG 结构信息
- **无跨函数/跨文件分析** — 仅看单个函数/代码片段
- **无污点分析** — 不追踪数据流
- **训练数据依赖** — 需要大量标注数据
- **无评分体系** — 仅二分类，无严重度/置信度
- **无修复建议** — 不生成补丁
- 泛化能力存疑 — 跨项目表现未知

---

### 6. SAIST — 多 LLM 后端扫描 + SCM

**架构**: `saist/main.py` (统一入口)

**核心方法**:
1. **多 LLM 后端**: 支持 OpenAI, Anthropic, Gemini, Ollama, vLLM, LM Studio 等
2. **SCM 集成**: Security Configuration Management，结合安全配置检查
3. **统一接口**: 抽象 LLM Provider，可切换不同模型
4. **扫描策略**: 文件级扫描，对每个文件生成 LLM prompt

**源码关键发现**:
- LLM Provider 抽象层设计良好
- 支持本地模型 (Ollama) 和云端 API
- SCM 组件可检查安全配置合规性

**优势**:
- LLM 后端灵活性最强
- 本地部署选项 (隐私友好)
- SCM 安全配置检查是差异化功能

**弱点**:
- 扫描深度有限 (文件级，无流分析)
- 无静态分析/ML 模型
- 无评分体系
- 依赖 LLM 幻觉控制
- 工程化程度较低

---

### 7. Metis (Arm) — RAG + 向量检索 + 可达性 (工业级)

**架构**: `engine/core.py` (编排器) + `graphs/` (Review/Ask Graphs) + `reachability/` (TreeSitter)

**核心组件深入分析**:

#### 7.1 MetisEngine (`core.py` — 353 行)
- **初始化**: 配置 LLM Provider + Vector Backend + Plugin System
- **双 embedding 模型**: 代码 embedding + 文档 embedding
- **核心服务**:
  - `IndexContextService`: 索引+上下文管理
  - `TreeSitterReachabilityService`: 基于 TreeSitter 的代码可达性分析
  - `ReviewService`: 安全审查服务
  - `TriageService`: 漏洞分诊服务
- **Graph 系统**: `ReviewGraph` (审查流程图) + `AskGraph` (问答图)
- **插件系统**: 支持语言插件，通过文件扩展名路由

#### 7.2 Review Service
- 基于 LlamaIndex 的 RAG 架构
- 向量检索相关代码片段
- LLM 审查相关片段的安全性

#### 7.3 Triage Service
- 对已知漏洞进行分诊 (确认/排除/升级)
- 使用 similarity_top_k 进行语义检索
- 支持分诊 checkpoint (每 50 个)

#### 7.4 TreeSitter Reachability
- 使用 TreeSitter 解析 AST
- 分析函数调用可达性
- 确定漏洞是否可被外部触发

**优势**:
- **Arm 出品** — 工业级品质
- **RAG 架构** — 代码库向量索引，语义检索
- **TreeSitter 可达性** — 判断漏洞是否可被外部触发
- **插件系统** — 可扩展语言支持
- **分诊系统** — 对已知漏洞进行自动化分级
- **双 embedding** — 代码和文档分别索引

**弱点**:
- **RAG 依赖** — 检索质量决定审查质量
- **无 ML 模型** — 不使用自定义模型
- **无数学评分** — 无多维度评分体系
- **可达性局限** — TreeSitter 仅做语法级，非语义级流分析
- **无污点分析** — 不追踪数据流传播
- **重量级** — 需要向量数据库 + LLM + TreeSitter 三件套

---

## 三、综合对比矩阵

### 3.1 技术能力矩阵

| 能力维度 | CosmX Galaxy | Phoenix | BayreuthWing | VulnHawk | Heimdall | c-vuln-det | SAIST | Metis |
|---------|-------------|---------|-------------|---------|---------|-----------|--------|-------|
| **AST/CPG 分析** | ✅ CPG全程序 | ❌ | ❌ | ❌ | ✅ TreeSitter | ❌ | ❌ | ✅ TreeSitter |
| **CFG/DFG** | ✅ 完整 | ❌ | ✅ Code Flow | ❌ | ❌ | ❌ | ❌ | ❌ |
| **污点分析** | ✅ 跨过程 | ❌ | ❌ | ❌ | ⚠️ 单文件 | ❌ | ❌ | ❌ |
| **ML/DL 模型** | ✅ 统计+ML | ❌ | ✅ 25M参数 | ❌ | ❌ | ✅ BGRU+HAN | ❌ | ❌ |
| **LLM 辅助** | ❌ | ✅ 三Agent | ❌ | ✅ 上下文增强 | ✅ Agent循环 | ❌ | ✅ 多后端 | ✅ RAG |
| **数学模型** | ✅ 宇宙学 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **进化优化** | ✅ GA演化 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **多维度评分** | ✅ 23维UVRS | ❌ | ⚠️ 简单 | ❌ | ⚠️ 基于类型 | ❌ | ❌ | ❌ |
| **修复建议** | ✅ | ✅ | ✅ | ✅ | ✅ 补丁 | ❌ | ✅ | ✅ |
| **Sandbox验证** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **可达性分析** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ TreeSitter |
| **跨语言** | ✅ 多语言 | ✅ LLM泛化 | ✅ 多语言 | ✅ LLM泛化 | ✅ 5语言 | ⚠️ 有限 | ✅ LLM泛化 | ✅ 插件扩展 |
| **向量检索/RAG** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ LlamaIndex |

### 3.2 工程化成熟度

| 维度 | CosmX Galaxy | Phoenix | BayreuthWing | VulnHawk | Heimdall | c-vuln-det | SAIST | Metis |
|------|-------------|---------|-------------|---------|---------|-----------|--------|-------|
| **代码质量** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **性能** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐(Rust) | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **可扩展性** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **部署复杂度** | 中 | 高(LLM) | 中 | 高(LLM) | 低(单二进制) | 低 | 高(LLM) | 高(RAG+向量DB) |
| **许可证** | 开源 | MIT | MIT | Apache-2.0 | FSL(限制) | MIT | MIT | Apache-2.0 |
| **商业背景** | 独立 | 学术 | 学术 | 独立 | 独立 | 学术 | 独立 | Arm工业级 |

### 3.3 核心差异矩阵

| 差异维度 | CosmX Galaxy 独有 | 竞品最佳实践 |
|---------|-------------------|-------------|
| 数学模型 | ✅ 宇宙学数学映射 (开普勒/引力/潮汐/摄动) | 无竞品使用 |
| UVRS 评分 | ✅ 23 维统一漏洞评分 | BayreuthWing 有简单severity |
| GA 进化 | ✅ 检测规则遗传算法演化 | 无竞品使用 |
| CPG | ✅ 完整 Code Property Graph | BayreuthWing 仅 Code Flow |
| Rust 实现 | ❌ | Heimdall 全 Rust |
| Agent 循环 | ❌ | Heimdall 25 轮 Agent Loop |
| Sandbox | ❌ | Heimdall 可运行 PoC |
| 向量索引 | ❌ | Metis 双 embedding + LlamaIndex |
| 可达性 | ❌ | Metis TreeSitter Reachability |
| 行为合约 | ❌ | Phoenix 三 Agent 合约验证 |
| 工业级背景 | ❌ | Metis (Arm) |
| 多 LLM | ❌ | SAIST 6+ LLM 后端 |

---

## 四、CosmX Galaxy 独特优势

### 4.1 竞争壁垒 (无可替代)

1. **宇宙学数学模型**: 将代码结构映射到天体力学模型（开普勒轨道=函数轨道，引力=数据依赖，潮汐力=外部影响，摄动=安全威胁），这是**所有 7 个竞品完全不具备的**。这种数学抽象提供了：
   - 理论可解释性（不像 DL 黑箱）
   - 独特的漏洞空间拓扑视角
   - 可发表的学术创新

2. **23 维 UVRS 评分**: 远超竞品的简单 severity 分类，提供漏洞评估的"化学元素周期表"

3. **GA 进化优化**: 检测规则自动演化，越用越准——竞品全部是固定规则或固定模型

4. **CPG + CFG + DFG 三图融合**: 全程序级图分析，仅 BayreuthWing 有类似能力但远不如完整

### 4.2 需要补齐的差距

| 优先级 | 差距 | 最佳参考 | 理由 |
|--------|------|---------|------|
| **P0** | LLM Agent 调查能力 | Heimdall hunt/agent.rs | Agent 循环可大幅提升上下文理解，减少误报 |
| **P0** | 修复建议生成 | Heimdall/Phoenix | 用户最需要的输出之一，CosmX 目前缺失 |
| **P1** | 向量索引/RAG | Metis engine/core.py | 大型代码库的语义检索能力 |
| **P1** | 可达性分析 | Metis reachability/ | 判断漏洞是否可被外部触发 |
| **P2** | Sandbox 验证 | Heimdall pipeline/sandbox | 自动化 PoC 验证 |
| **P2** | 性能优化 (考虑 Rust 核心) | Heimdall 全 Rust | 大型代码库扫描性能 |
| **P3** | 多 LLM 后端 | SAIST | 灵活切换模型，降低供应商锁定 |

---

## 五、竞品排名 (综合实力)

| 排名 | 项目 | 理由 |
|------|------|------|
| 🥇 1 | **Heimdall** | 最完整工程化，Rust 性能，9阶段管线，Agent+Taint+Static+Sandbox |
| 🥈 2 | **Metis (Arm)** | 工业级品质，RAG+向量检索+可达性，Arm 背书 |
| 🥉 3 | **BayreuthWing** | 最接近 CosmX 的混合架构，CodeTransformer + 静态 + Flow |
| 4 | **Phoenix** | 学术创新性行为合约，F1=0.825 训练无关 |
| 5 | **CosmX Galaxy** | 数学模型独特但工程化需提升，CPG/UVRS/GA 无竞品可比 |
| 6 | **VulnHawk** | LLM 上下文增强有亮点，但深度不足 |
| 7 | **SAIST** | 多 LLM 灵活，但扫描深度有限 |
| 8 | **c-vulnerability-detection** | 纯 DL 方案，无结构分析，应用场景窄 |

---

## 六、结论

### CosmX Galaxy 的定位

CosmX Galaxy 在**理论创新性**上独树一帜——宇宙学数学模型、UVRS 评分、GA 进化优化在竞品中**完全没有同类**。但在**工程化成熟度**上，Heimdall (Rust 9阶段管线) 和 Metis (Arm RAG 架构) 显著领先。

### 核心建议

1. **短期** (1-2 周): 添加 LLM Agent 调查能力 + 修复建议生成，参考 Heimdall 的 hunt/agent.rs
2. **中期** (1 月): 集成向量索引 (参考 Metis)，实现代码库级语义检索
3. **长期** (季度): 考虑核心引擎 Rust 重写 (参考 Heimdall)，提升大规模代码库扫描性能

CosmX Galaxy 的核心价值不在于"比竞品做得更好"，而在于**用完全不同的数学范式看待漏洞挖掘问题**。这个差异化如果包装得当（学术论文 + 开源社区 + benchmark 刷榜），有巨大的学术和商业潜力。
