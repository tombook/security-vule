# 第二轮竞品分析报告：AI漏洞检测工具深度对比

> 生成时间：2026-06-07  
> 对比基准：security-vule (CosmX Galaxy)  
> 竞品数量：6个新项目

---

## 一、竞品概览

| # | 项目名 | 语言 | Stars | 技术方向 | 来源 |
|---|--------|------|-------|----------|------|
| 1 | **garak** (NVIDIA/0din-ai) | Python | 4000+ | LLM红队评估 & 漏洞扫描 | NVIDIA研究 |
| 2 | **VulneraMCP** | TypeScript | 新项目 | AI驱动Bug Bounty MCP平台 | 社区 |
| 3 | **Nebula** | Python | 800+ | AI驱动渗透测试CLI | berylliumsec |
| 4 | **DL-VD-Empirical-Study** | Python | 学术 | 11种DL模型漏洞检测实证研究 | ICSE 2023 |
| 5 | **FUNDED_NISL** | Python | 学术 | GNN图神经网络漏洞检测 | IEEE TIFS 2021 |
| 6 | **VulDeePecker** | 数据集 | 经典 | 深度学习漏洞检测开山之作 | NDSS 2018 |

---

## 二、逐项深度分析

### 1. garak — LLM漏洞扫描器 (NVIDIA)

**定位**: "nmap for LLMs" — 针对大语言模型的红队评估与安全扫描工具

**核心架构**:
```
garak/
├── probes/        ← 40+种探测插件（漏洞触发器）
│   ├── promptinject.py   ← 提示注入
│   ├── dan.py            ← DAN越狱
│   ├── encoding.py       ← 编码绕过
│   ├── leakreplay.py     ← 数据泄露
│   ├── malwaregen.py     ← 恶意代码生成
│   ├── visual_jailbreak/ ← 多模态越狱
│   └── ...
├── detectors/     ← 29+种检测器（判断LLM是否失败）
│   ├── judge.py          ← LLM判断器
│   ├── knownbadsignatures.py ← 已知恶意签名
│   ├── unsafe_content.py ← 不安全内容检测
│   └── ...
├── generators/    ← 24+种LLM后端
│   ├── openai.py, huggingface.py, ollama.py
│   ├── bedrock.py, groq.py, litellm.py
│   └── ...
├── harnesses/     ← 运行编排
├── evaluators/    ← 评估聚合
└── buffs/         ← 预处理/后处理
```

**技术亮点**:
- **插件化架构**: Probe → Detector → Generator 三层解耦，每个都是独立插件
- **多LLM支持**: OpenAI、HuggingFace、Ollama、Bedrock、LiteLLM等24种后端
- **多模态**: 支持文本、图像、音频的探测
- **40+探测类型**: 覆盖提示注入、越狱、数据泄露、幻觉、毒性、恶意代码生成等
- **Tier分级**: OF_CONCERN > COMPETE_WITH_SOTA > INFORMATIONAL > UNLISTED

**与security-vule对比**:
| 维度 | garak | security-vule |
|------|-------|---------------|
| 目标 | **LLM自身安全**（LLM是否可被攻击） | **代码安全**（代码是否存在漏洞） |
| 扫描对象 | LLM模型输出 | 源代码 |
| 探测方式 | 向LLM发送恶意提示 | AST分析+污点追踪+模式匹配 |
| 检测器 | 判断LLM是否"失败" | 检测CWE漏洞模式 |
| LLM使用 | 被扫描的对象 | 分析工具（推理+修复） |
| 多LLM | 24种后端（作为目标） | 5种供应商（作为分析引擎） |

**借鉴价值**:
- ⭐ **插件化架构**: Probe/Detector/Generator三层解耦设计值得学习
- ⭐ **多LLM路由**: 支持litellm统一接口，类似我们的LLM Router
- ⭐ **Tier分级**: 漏洞严重度分级体系

---

### 2. VulneraMCP — AI驱动Bug Bounty MCP平台

**定位**: 基于Model Context Protocol (MCP)的AI驱动安全测试平台

**核心架构**:
```
src/
├── index.ts          ← MCP Server入口
├── mcp/server.ts     ← MCP协议实现
├── tools/            ← 9个工具模块
│   ├── recon.ts      ← 侦察（Subfinder/Amass/HTTPx）
│   ├── security.ts   ← 安全测试（XSS/SQLi/IDOR/CSRF）
│   ├── js.ts         ← JavaScript分析
│   ├── csrf.ts       ← CSRF专项
│   ├── zap.ts        ← OWASP ZAP集成
│   ├── render.ts     ← Puppeteer截图/DOM
│   ├── database.ts   ← PostgreSQL存储
│   ├── training.ts   ← AI训练数据
│   └── training_extractor.ts ← 从Writeup提取模式
├── integrations/
│   ├── postgres.ts   ← PostgreSQL ORM
│   └── redis.ts      ← Redis缓存
└── types/            ← TypeScript类型定义
```

**技术亮点**:
- **MCP协议**: 使用标准Model Context Protocol，可与任何AI Agent集成
- **全栈安全工具链**: XSS/SQLi/IDOR/CSRF/CSP/Auth Bypass全覆盖
- **工具集成**: ZAP + Burp Suite + Caido + sqlmap + subfinder + httpx
- **PostgreSQL持久化**: 所有发现存储在数据库中
- **AI训练数据**: 从HackTheBox/PortSwigger提取攻击模式
- **Web Dashboard**: 实时统计+发现管理

**与security-vule对比**:
| 维度 | VulneraMCP | security-vule |
|------|-----------|---------------|
| 目标 | **Web应用安全测试**（渗透测试） | **源代码漏洞检测**（静态分析） |
| 阶段 | 运行时测试 | 编译前检测 |
| 协议 | MCP（AI Agent标准） | CLI命令行 |
| 存储 | PostgreSQL + Redis | 文件系统 |
| AI集成 | MCP协议让AI调用安全工具 | LLM直接分析代码 |

**借鉴价值**:
- ⭐ **MCP协议**: 可考虑为security-vule添加MCP支持，让AI Agent能调用分析功能
- ⭐ **工具集成模式**: ZAP/Burp/sqlmap集成方式值得参考
- ⭐ **训练数据管理**: 从Writeup提取攻击模式的方法

---

### 3. Nebula — AI驱动渗透测试助手

**定位**: CLI界面的AI驱动渗透测试工具，集成Ollama/OpenAI模型

**核心架构**:
```
src/nebula/
├── nebula.py            ← 入口
├── MainWindow.py        ← Qt GUI主窗口
├── initial_logic.py     ← 启动逻辑
├── terminal_emulator.py ← 终端模拟器
├── conversation_memory.py ← 对话记忆
├── chroma_manager.py    ← ChromaDB向量存储
├── search.py            ← AI搜索功能
├── configuration_manager.py ← 配置管理
├── tools/
│   ├── searchsploit.py  ← SearchSploit集成
│   └── terminal.py      ← 终端工具
├── config/              ← 模型配置
└── ...
```

**技术亮点**:
- **本地模型支持**: Ollama (Llama-3.1, Mistral-7B, DeepSeek-R1)
- **OpenAI API支持**: 通过环境变量配置API Key
- **Qt GUI**: 完整的图形界面（不是纯CLI）
- **ChromaDB**: 向量存储用于RAG
- **对话记忆**: 上下文感知的多轮对话
- **终端集成**: 内置终端模拟器+SearchSploit

**与security-vule对比**:
| 维度 | Nebula | security-vule |
|------|--------|---------------|
| 目标 | **渗透测试辅助**（人工为主） | **自动化漏洞检测**（自动为主） |
| UI | Qt GUI + CLI | 纯CLI |
| 模型 | Ollama本地/OpenAI | 多供应商（OpenAI/Anthropic/Google/Ollama/本地） |
| 向量存储 | ChromaDB | 自定义RAG索引 |
| 分析类型 | 运行时渗透 | 静态代码分析 |

**借鉴价值**:
- ⭐ **ChromaDB集成**: 可替代我们的自定义RAG索引，获得更好的向量搜索
- ⭐ **对话记忆**: 多轮上下文感知的分析模式

---

### 4. DL-VD-Empirical-Study — 深度学习漏洞检测实证研究

**定位**: ICSE 2023论文 — 11种深度学习漏洞检测模型的系统对比

**包含模型**:
| 模型 | 类型 | 技术栈 | 特点 |
|------|------|--------|------|
| **Devign** | 图神经网络 | GGNN + AST/CFG/DFG/CDG图 | 开山GNN方法 |
| **ReVeal** | 图神经网络 | GGNN + CPG图 + SMOTE | 解决数据不平衡 |
| **ReGVD** | 图神经网络 | Gated Graph + 多关系图 | Devign改进 |
| **LineVul** | Transformer | CodeBERT + 行级检测 | 函数级+行级 |
| **CodeBERT** | 预训练模型 | CodeBERT微调 | 迁移学习 |
| **VulBERTa-CNN** | 预训练模型 | VulBERTa + CNN | CNN分类头 |
| **VulBERTa-MLP** | 预训练模型 | VulBERTa + MLP | MLP分类头 |
| **PLBART** | 预训练模型 | PLBART微调 | 双向自回归 |
| **Code2Vec** | 神经网络 | AST路径编码 | 轻量级 |
| **SySeVR** | RNN | BiLSTM + 程序切片 | 失败复现 |
| **VulDeeLocator** | 混合 | LLVM IR + 源码 + BiLSTM | 行级定位 |

**数据集**:
- **Devign数据集**: C/C++函数级，27,000+样本
- **MSR数据集**: C/C++ CVE修复commit，34,000+样本

**关键发现**:
1. LineVul在MSR数据集上表现最好（F1 ~88%）
2. 图方法（Devign/ReVeal）在合成数据上好但真实数据差
3. 预训练模型（CodeBERT/VulBERTa）泛化能力更强
4. 数据不平衡是核心挑战
5. SySeVR和VulDeeLocator无法复现

**与security-vule对比**:
| 维度 | DL-VD研究 | security-vule |
|------|----------|---------------|
| 方法 | **纯ML/DL**（需训练数据） | **规则+LLM**（无需训练） |
| 检测粒度 | 函数级/行级 | 文件级+函数级 |
| 语言 | C/C++ | JavaScript/TypeScript + Python + Java + Go |
| 依赖 | 大量GPU+训练数据 | 仅需LLM API |
| 部署 | 需训练模型 | 开箱即用 |

**借鉴价值**:
- ⭐ **LineVul架构**: CodeBERT微调+行级检测是最强方案
- ⭐ **数据集**: Devign/MSR数据集可用于评估
- ⭐ **评估指标**: F1/Precision/Recall/Accuracy标准评估框架

---

### 5. FUNDED_NISL — GNN图神经网络漏洞检测

**定位**: IEEE TIFS 2021 — 结合GNN和自动数据收集的漏洞检测

**核心架构**:
```
FUNDED/
├── cli/
│   ├── train.py      ← 训练入口
│   └── test.py       ← 测试入口
├── layers/
│   ├── message_passing/
│   │   ├── ggnn.py   ← GGNN层（GRU消息传递）
│   │   ├── gnn_edge_mlp.py
│   │   ├── gnn_film.py
│   │   └── message_passing.py ← 消息传递基类
│   ├── gnn.py         ← GNN模型
│   ├── nodes_to_graph_representation.py ← 图级聚合
│   └── graph_global_exchange.py ← 图全局交换
├── models/
│   ├── graph_binary_classification_task.py ← 二分类
│   └── graph_task_model.py ← 任务基类
├── data/
│   ├── graph_dataset.py
│   ├── jsonl_graph_dataset.py
│   └── data_preprocess.py
└── Edge_processing/   ← AST/CFG/PDG边提取（Java）
```

**核心技术**:
- **GGNN (Gated Graph Neural Network)**: 使用GRU单元进行消息传递
- **7种边类型**: AST边 + CFG边 + PDG边（控制+数据+调用依赖）
- **图级聚合**: WeightedSum + Multi-head Attention
- **多语言预处理**: C/C++(Joern+CDT), Java(Soot+JDT), PHP/Swift(ANTLR)
- **NNI调参**: 使用Microsoft NNI进行超参搜索

**模型参数**:
```
GGNN: hidden_dim=256, num_layers=5
Aggregation: 16 heads, hidden=[128]
Optimizer: Adam, lr=0.001
结果: F1=0.917(CWE-77), Accuracy=0.942
```

**与security-vule对比**:
| 维度 | FUNDED | security-vule |
|------|--------|---------------|
| 核心 | GNN图神经网络 | LLM+规则+GA |
| 输入 | 程序图（AST+CFG+PDG） | 源代码文本 |
| 图构建 | Joern+Soot+ANTLR | @typescript-eslint/parser |
| 训练 | 需要标注数据 | 零样本（LLM推理） |
| 语言 | C/C++, Java, PHP, Swift | JS/TS, Python, Java, Go |

**借鉴价值**:
- ⭐ **7种边类型**: AST+CFG+PDG多关系图，比纯AST分析更丰富
- ⭐ **GGNN架构**: GRU消息传递是GNN漏洞检测的标准方法
- ⭐ **NNI调参**: 自动超参搜索框架

---

### 6. VulDeePecker — 深度学习漏洞检测开山之作

**定位**: NDSS 2018 — 首个将深度学习应用于漏洞检测的系统

**核心贡献**:
- **Code Gadget概念**: 将代码按数据依赖切分为语义相关的语句组合
- **BiLSTM分类**: 使用双向LSTM进行漏洞/非漏洞二分类
- **数据集**: 61,638个代码片段，覆盖CWE-119(缓冲区)和CWE-399(资源管理)
- **Guiding Principles**: 提出DL漏洞检测的指导原则

**数据集统计**:
```
CWE-119: 520个开源文件 + 8,122个测试用例 → 10,440漏洞CG
CWE-399: 320个开源文件 + 1,729个测试用例 → 7,285漏洞CG
总计: 61,638个代码片段 (17,725漏洞 + 43,913非漏洞)
```

**与security-vule对比**:
| 维度 | VulDeePecker | security-vule |
|------|-------------|---------------|
| 时代 | 2018（开创性） | 2025-2026 |
| 方法 | BiLSTM + Code Gadget | LLM + AST + 污点分析 |
| 数据 | 大量标注数据 | 零样本 |
| 检测类型 | 仅CWE-119, CWE-399 | 多种CWE类型 |

---

## 三、综合对比矩阵

| 维度 | garak | VulneraMCP | Nebula | DL-VD | FUNDED | VulDeePecker | **security-vule** |
|------|-------|-----------|--------|-------|--------|-------------|-------------------|
| **目标** | LLM安全 | Web渗透 | 渗透辅助 | 学术研究 | 学术研究 | 学术研究 | **代码漏洞检测** |
| **方法** | 动态探测 | MCP工具 | AI+CLI | DL训练 | GNN | BiLSTM | **LLM+AST+GA** |
| **语言** | - | - | - | C/C++ | C/Java/PHP | C/C++ | **JS/TS+Python+Java+Go** |
| **LLM集成** | 作为目标 | MCP协议 | Ollama/OpenAI | 无 | 无 | 无 | **5供应商** |
| **训练需求** | 无 | 无 | 无 | 大量GPU | GPU+数据 | GPU+数据 | **零样本** |
| **可解释性** | 低 | 低 | 中 | 低 | 低 | 低 | **高（LLM推理）** |
| **部署难度** | 低 | 中 | 中 | 高 | 高 | 高 | **低** |
| **成熟度** | 生产级 | 早期 | 生产级 | 学术 | 学术 | 学术 | **改进中** |

---

## 四、security-vule独特优势

### 现有优势（vs 竞品）

1. **零样本检测**: 不需要训练数据，直接使用LLM推理，这是vs DL-VD/FUNDED/VulDeePecker的核心优势
2. **多LLM供应商**: 5种LLM后端（OpenAI/Anthropic/Google/Ollama/本地），比Nebula的2种更多
3. **多语言支持**: JS/TS + Python + Java + Go，覆盖比大多数竞品更广
4. **LLM修复建议**: 不仅检测漏洞，还提供修复代码，大多数竞品不具备
5. **GA进化引擎**: 使用遗传算法优化检测参数，独特于所有竞品
6. **RAG知识库**: 内置13个CWE条目的向量索引，支持知识检索增强

### 需要改进的方面（从竞品学习）

1. **插件化架构**（学习garak）:
   - garak的Probe/Detector/Generator三层解耦是最佳实践
   - 建议: 将检测器、LLM供应商、分析引擎全部插件化

2. **MCP协议支持**（学习VulneraMCP）:
   - MCP是AI Agent的标准协议
   - 建议: 添加MCP Server模式，让其他AI工具可以调用security-vule

3. **GNN图分析**（学习FUNDED）:
   - FUNDED的7种边类型（AST+CFG+PDG）提供了更丰富的代码表示
   - 建议: 在AST解析基础上增加CFG/PDG边提取

4. **行级检测**（学习LineVul）:
   - LineVul的行级漏洞定位是ICSE 2023最佳方法
   - 建议: 在函数级检测后，增加行级定位

5. **评估基准**（学习DL-VD）:
   - 使用Devign/MSR标准数据集进行评估
   - 建议: 添加benchmark命令，使用标准数据集评估性能

---

## 五、综合排名

| 排名 | 项目 | 综合评分 | 理由 |
|------|------|---------|------|
| 🥇 | **garak** | 9.5/10 | 最成熟、最专业的LLM安全扫描框架，插件架构堪称教科书 |
| 🥈 | **DL-VD-Empirical-Study** | 8.5/10 | 学术价值最高，11种模型对比+标准评估，是漏洞检测研究的基准 |
| 🥉 | **FUNDED_NISL** | 8.0/10 | GNN漏洞检测的标杆实现，7种边类型的图构建方法值得学习 |
| 4 | **VulneraMCP** | 7.5/10 | MCP协议是亮点，工具链集成完整，但项目较新 |
| 5 | **Nebula** | 7.0/10 | AI渗透测试的好产品，但与代码漏洞检测方向不同 |
| 6 | **VulDeePecker** | 6.5/10 | 开山之作，但技术已过时，主要是历史数据集价值 |
| **-** | **security-vule** | **7.0/10** | 零样本+多LLM+GA进化是独特优势，但需加强插件化和标准评估 |

---

## 六、下一步改进建议（优先级排序）

### 高优先级
1. **插件化架构重构**: 学习garak的三层解耦，将检测器/分析器/LLM供应商全部插件化
2. **标准评估基准**: 下载Devign/MSR数据集，建立benchmark评估体系
3. **MCP Server模式**: 添加MCP协议支持，让AI Agent可以调用security-vule

### 中优先级
4. **行级漏洞定位**: 在函数级检测后，增加行级精确定位
5. **CFG/PDG边提取**: 在AST基础上增加控制流和数据流边
6. **ChromaDB替代**: 用ChromaDB替代自定义RAG索引

### 低优先级
7. **Web Dashboard**: 添加类似VulneraMCP的实时统计面板
8. **Qt GUI**: 类似Nebula的图形界面（可选）
