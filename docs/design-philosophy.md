# 🌌 security-vule 设计哲学 (Design Philosophy)

> **本项目的设计思路来自 [cosmic-galaxy](../cosmic-galaxy) 宇宙星系法** — 以天体物理与理论物理类比构建白盒漏洞分析框架

[![Version](https://img.shields.io/badge/version-0.3-blue)]()
[![Dimensions](https://img.shields.io/badge/dimensions-target_23-purple)]()
[![Engine](https://img.shields.io/badge/engine-typescript-brightgreen)]()

---

## 一、设计原则 (Principles)

### 1. 理论驱动开发 (Theory-Driven Development)

cosmic-galaxy 的核心原则：

> "每个新增功能必须对应明确的数学公式。不可凭空添加启发式规则。"

**在 security-vule 中的体现：**

| cosmic-galaxy 原则 | security-vule 对应 |
|------------------|--------------------|
| 每个理论维度 = 一个独立模块 + `compute() -> float` 统一接口 | 每个检测器 (SQLi/XSS/RCE/...) = 一个独立模块 + `detect() -> Finding[]` |
| `mappings.yaml` 宇宙→代码映射表 | `docs/cwe-mapping.md` 漏洞类型↔CWE↔OWASP 映射表 |
| `equations.json` 所有公式 JSON | `docs/detection-formulas.md` 污点传播规则、风险评分公式 |

### 2. 维度优先级 (Dimension Priority)

cosmic-galaxy 的开发顺序按权重降序：

```
w=0.20 引力场  → 污点传播 (Taint Propagation)
w=0.15 开普勒  → 距离风险 (Distance Risk)
w=0.10 潮汐/N体/相对论 → 二次注入/并行风险/复杂度
w=0.08 暗物质  → 隐藏依赖 (反射/动态加载)
w=0.05 摄动/熵 → 代码演化风险
```

**在 security-vule 中的体现：**
- AST 静态分析 = 开普勒轨道（节点到汇点的图距离）
- LLM 污点分析 = 引力场（数据流从源到汇的引力）
- N体多模型共识 = N体模拟（多个 LLM 之间的相互作用）
- 二次验证 = 相对论修正（高精度模型校正 LLM 噪声）
- 反思机制 = 摄动理论（迭代漂移检测）

### 3. 模块化设计 (Modular Design)

cosmic-galaxy 的模块契约：
```python
class GravityField:
    def compute(node, cpg) -> float  # 统一接口
```

**security-vule 对应契约：**
```typescript
interface Detector {
  detect(ctx: VulnerabilityContext): VulnerabilityFinding[]
  weight: number  // 在 UVRS 中的权重
  theoryFormula?: string  // 对应的理论公式
}
```

---

## 二、23 维度映射 (Dimension Mapping)

| # | cosmic-galaxy 理论 | 核心公式 | security-vule 检测维度 | 状态 |
|---|------------------|---------|----------------------|------|
| 1 | 开普勒第一定律 | `r(θ)=a(1-e²)/(1+e·cosθ)` | **节点到危险函数的图距离风险** | ✅ AST 距离分析 |
| 2 | 轨道六要素 | `[a, e, i, Ω, ω, θ]` | **节点多维特征** (复杂度/耦合度/PageRank) | ✅ `src/engine/orbital.ts` |
| 3 | 万有引力 | `F=Γ·W_v·W_s/d²` | **污点传播引力** (源权重×汇权重/距离²) | ✅ `src/engine/taint.ts` |
| 4 | N体问题 | `ΣF/m, Barnes-Hut O(N log N)` | **多 LLM 共识** (并行模型+投票融合) | ✅ `src/llm/consensus.ts` |
| 5 | 摄动理论 | `da/dt, de/dt, di/dt` | **迭代漂移检测** (代码演化风险) | 🔲 计划 |
| 6 | 潮汐力 | `F=2Γ·W_a·W_b·C_ab/d³` | **多汇点撕裂风险** (复合漏洞链) | ✅ 链式污点 |
| 7 | 相对论修正 | `G_μν+Λg_μν=κT_μν` | **复杂函数时空弯曲** (深度嵌套风险) | 🔲 计划 |
| 8 | 暗物质/暗能量 | `M_dark=observed−visible` | **隐藏依赖** (反射/动态调用/DI/回调) | ✅ AST partial |
| 9 | 量子力学 | `|ψ⟩=α\|safe⟩+β\|vuln⟩` | **概率性漏洞** (race condition/timing) | 🔲 计划 |
| 10 | 熵增原理 | `dS/dt≥0, ρ_vuln=ρ₀·exp(λS)` | **代码复杂度熵增** (McCabe/Halstead) | 🔲 计划 |
| 11-23 | (扩展维度: 信息论/范畴论/分形/混沌等) | ... | (对应: Shannon/Sheaf/Lyapunov 等) | 🔲 远期 |

---

## 三、核心架构对齐 (Architecture Alignment)

### cosmic-galaxy 架构
```
CosmicEngine
  ├─ OrbitalElements    (Kepler)
  ├─ GravityField       (引力)
  ├─ NBodySimulation    (N体)
  ├─ UVRS               (统一评分)
  ├─ KalmanObserver     (观测)
  ├─ RelativisticCorrection
  ├─ DarkMatterDetector
  ├─ TidalForce
  ├─ PerturbationTheory
  └─ HTMLVisualization  (星图)
```

### security-vule 对应架构
```
VuleEngine
  ├─ ASTAnalyzer        (开普勒 - 节点距离/复杂度)
  ├─ TaintAnalyzer      (引力 - 数据流传播)
  ├─ LLMAgent           (N体 - 多模型并行分析)
  ├─ ConsensusModule    (统一评分 - 多模型共识)
  ├─ VerifyPass         (相对论 - 二次验证)
  ├─ DarkMatterScanner  (暗物质 - 隐藏依赖)
  ├─ ChainDetector      (潮汐 - 复合漏洞链)
  ├─ EvolutionTracker   (摄动 - 演化漂移)
  └─ RiskStarMap        (可视化 - 风险星图)
```

---

## 四、UVRS 统一风险评分 (Unified Vulnerability Risk Score)

### cosmic-galaxy 公式
```
SUVRS(v) = σ(Σᵢ wᵢ · Rᵢ(v))
σ(x) = 1/(1 + e^(-x))
```

### security-vule 对应公式
```
S_VULE(v) = σ(Σᵢ wᵢ · Rᵢ(v))
  R_ast = AST 静态分析置信度
  R_taint = 污点传播完整性
  R_llm = LLM 分析置信度
  R_consensus = 双模型共识度
  R_verify = 二次验证通过率
  R_chain = 漏洞链关联度
```

### 默认权重 (基于 cosmic-galaxy v7.0)
```typescript
const VULE_WEIGHTS = {
  taint: 0.20,        // w=0.20 引力场
  ast: 0.15,          // w=0.15 开普勒
  llm: 0.10,          // w=0.10 N体
  consensus: 0.10,    // w=0.10 相对论
  verify: 0.10,       // w=0.10 观测
  chain: 0.10,        // w=0.10 潮汐
  darkMatter: 0.08,   // w=0.08 暗物质
  evolution: 0.05,    // w=0.05 摄动
  quantum: 0.07,      // w=0.07 量子
  entropy: 0.05,      // w=0.05 熵
};
```

### 风险等级阈值
```typescript
const RISK_THRESHOLDS = {
  LOW: 0.25,      // 轨道稳定
  MEDIUM: 0.50,   // 轨道轻微扰动
  HIGH: 0.75,     // 轨道显著偏斜
  CRITICAL: 0.85, // 即将碰撞
};
```

---

## 五、CLI 设计对齐 (CLI Alignment)

### cosmic-galaxy CLI
```bash
python cosmic_galaxy.py analyze \
  --graph graph.pkl \
  --sinks store,output \
  --security-apis validate \
  --export report.html \
  --format html
```

### security-vule CLI (计划)
```bash
vule analyze <path> \
  --mode ast|llm|consensus|failover \
  --verify \
  --export report.json,report.html \
  --format json|html|markdown \
  --visualize star-map.html \
  --weights "taint:0.2,ast:0.15,..." \
  --threshold critical=0.85
```

---

## 六、开发路线图 (Roadmap)

### 已完成 ✅ (对齐 cosmic-galaxy v1-v3)
- [x] AST 静态分析 (开普勒轨道)
- [x] LLM 单模式扫描 (引力场)
- [x] LLM 双模型共识 (N体)
- [x] 二次验证 (相对论修正)
- [x] 污点传播 (引力)
- [x] 类型归一化 (类似 `TYPE_NORMALIZE`)
- [x] Prompt 注入检测 (类似 cosmic-galaxy 的 anomaly 检测)

### Sprint 1: 核心引擎对齐 ⏳ 当前
- [ ] 实现 `VuleEngine` 统一入口 (对齐 `CosmicEngine`)
- [ ] 实现 `UVRS` 统一风险评分模块 (sigma fusion)
- [ ] 实现权重配置 YAML (对齐 cosmic-galaxy `mappings.yaml`)
- [ ] CLI 命令对齐 (`vule analyze` 命名)
- [ ] 多格式报告导出 (JSON/HTML/Markdown)

### Sprint 2: 高级分析
- [ ] 隐藏依赖检测 (暗物质)
- [ ] 漏洞链关联 (潮汐力)
- [ ] 演化漂移检测 (摄动理论)
- [ ] 概率性漏洞 (量子态)

### Sprint 3: 产品级
- [ ] 交互式风险星图 HTML 可视化 (对齐 `HTMLVisualization`)
- [ ] 全局缓存机制 (对齐 cosmic-galaxy `Cache`)
- [ ] 配置系统 (YAML/JSON)
- [ ] MCP 服务器集成

### Sprint 4: 集成扩展
- [ ] Joern CPG 自动生成
- [ ] SARIF 输出格式
- [ ] IDE 插件
- [ ] SaaS 化

---

## 七、关键决策记录 (Decision Log)

| 日期 | 决策 | 来源对齐 |
|------|------|----------|
| 2026-06-10 | 采用 cosmic-galaxy 设计哲学 | 本文档 |
| 2026-06-10 | UVRS 阈值 CRITICAL=0.85 | cosmic-galaxy v5.0 修正 |
| 2026-06-10 | LLM 二次验证采用"二次调用"机制 | cosmic-galaxy 卡尔曼观测器 |
| 2026-06-10 | 类型归一化通过 `TYPE_NORMALIZE` 映射 | cosmic-galaxy 维度标准化 |
| 2026-06-10 | 多模型共识采用并行+投票融合 | cosmic-galaxy N体 + 拉格朗日点 |
| 2026-06-10 | `maxFindings` 可配置 (默认 5) | cosmic-galaxy 可配置超参数 |
| 2026-06-10 | Prompt 注入检测 + 数据隔离 | cosmic-galaxy 暗物质异常检测 |

---

## 八、文件结构对齐 (File Structure)

### cosmic-galaxy
```
cosmic-galaxy/
├── engine/
│   ├── __init__.py      # CosmicEngine
│   ├── orbital.py       # 开普勒轨道
│   ├── gravity.py       # 引力场
│   ├── nbody.py         # N体
│   ├── uvrs.py          # 统一评分
│   ├── cache.py         # 缓存
│   └── config.py        # 配置
├── theory/
│   ├── equations.json   # 公式
│   └── mappings.yaml    # 宇宙→代码映射
└── tests/
```

### security-vule (目标对齐)
```
security-vule/
├── src/
│   ├── engine/
│   │   ├── analyzer.ts  # VuleEngine (对齐 CosmicEngine)
│   │   ├── taint.ts     # 污点传播 (对齐 gravity)
│   │   ├── orbital.ts   # AST 距离 (对齐 orbital)
│   │   ├── uvrs.ts      # 统一风险评分 (对齐 uvrs.py)
│   │   ├── cache.ts     # LLM 响应缓存 (对齐 cache.py)
│   │   └── config.ts    # 权重配置 (对齐 config.py)
│   ├── llm/
│   │   ├── agent.ts     # LLM 分析 (对齐 nbody)
│   │   ├── consensus.ts # 多模型共识 (对齐 N体)
│   │   └── verify.ts    # 二次验证 (对齐 kalman)
│   └── detection/
│       └── llm-agent.ts # 检测器 (对齐 dimensional modules)
├── theory/
│   ├── equations.json   # 检测公式 (对齐 cosmic-galaxy)
│   └── mappings.yaml    # 漏洞→代码映射
└── docs/
    └── design-philosophy.md  # 本文档
```

---

## 九、与 cosmic-galaxy 的差异 (Differences)

| 方面 | cosmic-galaxy | security-vule |
|------|--------------|---------------|
| 主语言 | Python | TypeScript |
| 主数据结构 | NetworkX 图 | AST + CodeQL |
| 核心引擎 | 物理公式 (数学) | LLM + AST (AI + 静态) |
| 输出 | UVRS 评分 | 漏洞发现 + PoC 验证 |
| 验证 | 单元测试 (45+71) | 运行时 PoC (Playwright) |
| 部署 | Docker Compose | Bun + MCP |
| 用户 | 安全研究者 | 开发者 + 安全工程师 |

---

## 十、引用 (References)

- **cosmic-galaxy 项目**: `/Users/tombook/Documents/work/ai_openclaw/dev_work/cosmic-galaxy`
- **核心论文理论**: 23 个天体物理/理论物理维度
- **核心公式**: `cosmic-galaxy/theory/equations.json`
- **宇宙→代码映射**: `cosmic-galaxy/theory/mappings.yaml`

---

> 🌌 **以宇宙之理，护代码安全** — security-vule v0.3 (design philosophy v1)