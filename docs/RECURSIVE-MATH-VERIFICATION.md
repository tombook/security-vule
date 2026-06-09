# security-vule v3.0 递归数学验证 (操作手册)

> 本文是 REDESIGN.md 的姊妹文档. REDESIGN.md 说 "做什么", 本文说 "怎么做".
> 核心: **数学 → 物理 → 代码 → GA 反验 → 回灌数学** 的递归闭环.

## 1. 抽象层次 (L1-L4)

```
L1 原始数学          L2 宇宙理论          L3 漏洞挖掘          L4 验证闭环
─────────────────  ──────────────────  ──────────────────  ──────────────────
矩阵/概率/统计  ──同构→ 距离/引力/摄动  ──同构→ 阈值/F1/GA  ──同构→ 反向优化
execution/      theory/          application/      pipeline/
```

- L1 = 纯数学 (CPG/pagerank/entropy)
- L2 = 数学对物理的同构解释 (开普勒/引力/潮汐)
- L3 = 数学对代码的同构应用 (12 类规则 + 扫描器)
- L4 = 真实 GT 评估 + GA 进化 (反向验证数学模型)

## 2. 目录速查

```
src/math/
├── theory/                      # L2 宇宙理论
│   ├── 23d/                     # 23 维理论
│   │   ├── definitions.ts       # TheoryDimension + THEORY_DEFINITIONS
│   │   ├── calculator.ts        # CosmicTheoryEngine
│   │   ├── uvrs.ts              # UVRSCalculator + 默认权重
│   │   └── build-graph-23d.ts   # ★ buildGraphData23Dv3 (per-node 修复)
│   ├── physics/                 # 6 维物理
│   │   ├── orbital.ts           # 开普勒 / 轨道六根数
│   │   ├── gravity.ts           # 万有引力 (Barnes-Hut)
│   │   ├── tidal.ts             # 潮汐 / 拉格朗日点
│   │   ├── perturbation.ts      # 摄动 / 异常检测
│   │   ├── nbody.ts             # N 体 / cosmXAnalyze
│   │   └── saturation.ts        # ★ extractRawSignals (非饱和)
│   └── index.ts
├── execution/                   # L1 原始数学
│   ├── cpg.ts                   # CPG 构建
│   ├── graph-metrics.ts         # pagerank / betweenness
│   ├── entropy.ts               # 信息熵
│   ├── anomaly.ts               # z-score / Mahalanobis
│   └── index.ts
├── application/                 # L3 漏洞挖掘
│   ├── scanner.ts               # scanFile / scanProject / scanProjectWithUVRS
│   ├── patterns.ts              # 12 类 VULN_PATTERNS
│   ├── dedup.ts                 # 去重 + 置信度过滤
│   ├── calibration.ts           # ★ 12 维 GA 基因空间
│   ├── gnn-classifier.ts        # GNN 漏洞分类
│   ├── training-pipeline.ts     # 训练管道
│   └── index.ts
├── pipeline/                    # L3 + L4
│   ├── run-scan.ts              # CLI: 单次扫描
│   ├── run-evolve.ts            # CLI: GA 进化入口
│   ├── run-evaluate.ts          # CLI: 真实 GT 评估
│   └── run-report.ts            # CLI: 报告生成
└── compat/                      # 旧 cosm-x-* API 兼容
    ├── cosm-x-theory-23d.ts     # → theory/23d/index.js
    ├── cosm-x-galaxy.ts         # → theory/physics/index.js
    ├── cosm-x-project-analyzer.ts # → application/scanner.js
    ├── cosm-x-dedup.ts          # → application/dedup.js
    └── cosm-x-cli.ts            # → pipeline/run-scan.js
```

## 3. 三个 v3 修复点

### 3.1 per-node buildGraphData23D (§4.1)

**问题**: 旧版只用 `_project_avg`, UVRS 实测只有 3 个值.

**新 API**:
```typescript
import { buildGraphData23Dv3, type CPGNodeInput } from './math/theory/23d/index.js';

const nodes: CPGNodeInput[] = [
  { nodeId: 'auth.js:42', pagerank: 0.8, betweenness: 0.6, inDegree: 5, outDegree: 3, cyclomaticComplexity: 8 },
  // ... 从 CPG 实际提取
];
const graph = buildGraphData23Dv3(nodes, sixDim, { severity: 0.9, nodeId: 'auth.js:42' });
// per-node 数据从 CPG 实际填充, UVRS 反映真实位置风险
```

### 3.2 6 维非饱和信号 (§4.2)

**问题**: 旧 CosmXResult.vulnerabilityScore saturate 到 0-1, 不能精细过滤.

**新 API**:
```typescript
import { extractRawSignals, computeComposite } from './math/theory/physics/saturation.js';
import { cosmXAnalyze } from './math/theory/physics/nbody.js';
import { CPGBuilder } from './math/execution/cpg.js';

const cpg = new CPGBuilder().addFile('app.ts', code).build();
const result = cosmXAnalyze(cpg);
const sigs = extractRawSignals(result);
// sigs.anomaly_raw: 0-10
// sigs.perturbation_raw: 0-10
// sigs.gravity_raw: 0-10
// sigs.composite: 0-1 (a*0.4 + p*0.3 + g*0.3, capped)

// 用 anomaly_raw 做精细过滤 (而非 saturated composite)
const highAnomaly = sigs.anomaly_raw > 7;
```

### 3.3 12 维 GA 基因空间 (§4.3)

**问题**: 旧 GA 只优化 minScore (6 维), 找到 52.52 过滤掉全部 (过拟合).

**新 API**:
```typescript
import { DEFAULT_GAGENE_SPACE, DEFAULT_GAGENE_VECTOR, decodeGAGene, applyGAGene } from './math/application/calibration.js';

// 12 维基因:
//   [0]  min_score
//   [1]  dedup_strategy (0=none, 1=file-type, 2=file-line-type)
//   [2-6] 5 个规则权重 (sqli/xss/rce/path/auth)
//   [7-11] 5 个信号开关 (kepler/entropy/tda/chaos/gravitational)

const gene = decodeGAGene([10, 1, 1.5, 1.0, 1.0, 0.8, 1.0, 1, 1, 0, 1, 1]);
// = { min_score: 10, dedup_strategy: 'file-type',
//     rule_weights: { sqli: 1.5, xss: 1.0, rce: 1.0, path: 0.8, auth: 1.0 },
//     signal_switches: { use_kepler: true, use_entropy: true, use_tda: false, use_chaos: true, use_gravitational: true } }

const filtered = applyGAGene(findings, gene);
// 应用: min_score 过滤 + dedup + 规则权重
```

## 4. 递归验证流程

### 4.1 单次扫描 (L3)

```bash
bun src/math/pipeline/run-scan.ts /path/to/project --min-score 0 --dedup file-type
```

### 4.2 真实 GT 评估 (L4)

```bash
# 1. 扫描项目, 输出 JSON
bun src/math/pipeline/run-scan.ts /path/to/project > /tmp/scan.json

# 2. 用真实 GT 评估
bun src/math/pipeline/run-evaluate.ts /tmp/scan.json /path/to/ground-truth.json
# 输出: TP/FP/FN, Precision/Recall/F1
```

### 4.3 GA 进化 (L4 闭环)

```bash
# v3 入口: 12 维基因空间
bun src/math/pipeline/run-evolve.ts --rounds 10000 --population 100

# 实际 GA 循环 (项目历史保留在 src/evolution/)
bun src/evolution/evolver-enhanced.ts
```

### 4.4 数据回灌 (L4 → L2/L1)

GA 找到的最优基因可以回写到 `DEFAULT_GAGENE_SPACE`:
```typescript
// src/math/application/calibration.ts
export const DEFAULT_GAGENE_SPACE: GAGeneSpace = {
  // 从 GA 收敛点填入
  min_score: 0,           // v3 改用规则权重 + 信号开关, 不再 min_score 过拟合
  dedup_strategy: 'file-type',
  rule_weights: { ... },
  signal_switches: { ... },
};
```

## 5. compat 兼容层

| 旧 API 路径                           | 新 API 路径                              |
|---------------------------------------|------------------------------------------|
| `import { ... } from './cosm-x-theory-23d.js'`     | `'./theory/23d/index.js'`                |
| `import { ... } from './cosm-x-galaxy.js'`         | `'./theory/physics/index.js'`            |
| `import { ... } from './cosm-x-project-analyzer.js'` | `'./application/scanner.js'`             |
| `import { ... } from './cosm-x-dedup.js'`          | `'./application/dedup.js'`               |
| `import { ... } from './cosm-x-cli.js'`            | `'./pipeline/run-scan.js'`               |
| `import { ... } from './cpg.js'`                   | `'./execution/cpg.js'`                   |
| `import { ... } from './entropy.js'`               | `'./execution/entropy.js'`               |
| `import { ... } from './anomaly.js'`               | `'./execution/anomaly.js'`               |
| `import { ... } from './graph-metrics.js'`         | `'./execution/graph-metrics.js'`         |

新代码请用新路径. 旧代码通过 compat/ 自动 re-export, 无需改.

## 6. 验证

```bash
# 跑所有测试
bun test

# 当前状态: 113 pass / 0 fail
```

## 7. 哲学

```
[数学]  → 同构映射 →  [宇宙理论]  → 同构应用 →  [漏洞挖掘]
  ↑                         │                        │
  └──── 反向验证 (GA) ──────┴──── 数据回灌 (findings) ┘
```

数学不依赖物理存在 (L1 → L2 是同构, 不是依赖), 漏洞挖掘不依赖宇宙理论 (L3 可独立工作).
但物理验证和代码验证**递归回流**到 L1/L2 的参数校准 — 这就是 "递归数学验证".
