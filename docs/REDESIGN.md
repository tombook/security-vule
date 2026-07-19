# security-vule 重新设计提案 (v3.0)

> 基于"递归数学验证架构"分析, 重新设计 security-vule. 数学是核心, 宇宙理论是数学对物理的同构解释, 漏洞挖掘是数学对代码的同构应用.

## 1. 设计哲学

```
[数学]  → 同构映射 →  [宇宙理论]  → 同构应用 →  [漏洞挖掘]
  ↑                         │                        │
  └──── 反向验证 (GA) ──────┴──── 数据回灌 (findings) ┘
```

- **数学是核心** (pagerank 矩阵、距离反比、信息熵、z-score)
- **宇宙理论** = 数学对物理的同构解释 (开普勒/引力/潮汐/摄动)
- **漏洞挖掘** = 数学对代码的同构应用 (CFG/DFG/taint/CPG)
- **递归验证** = 漏洞挖掘产出数据, 反向验证 UVRS 权重 (GA 进化)

## 2. 目录重新组织 (从 cosm-x-* 到 math-*)

### 旧结构 (v2.x)
```
src/math/
├── cosm-x-theory-23d.ts       # 23 维定义 + UVRS
├── cosm-x-galaxy.ts           # 6 维物理 (开普勒/引力/潮汐/...)
├── cosm-x-project-analyzer.ts # 扫描器主入口
├── cosm-x-dedup.ts            # 去重 + 过滤
├── cosm-x-cli.ts              # CLI 包装
├── cpg.ts                     # CPG 图构建
├── graph-metrics.ts           # pagerank/betweenness
├── entropy.ts                 # 信息熵
├── anomaly.ts                 # z-score 异常
├── gnn-classifier.ts          # GNN 分类器
└── training-pipeline.ts       # 训练管道
```

**问题**:
- `cosm-x-*` 命名隐含"宇宙理论是装饰" 的误解
- 4 个独立算法的维度 (KEPLER/ENTROPY/TDA/CHAOS) 和 19 维 fallback 混在一起
- UVRS / 23 维理论 / 6 维物理 / 去重 是不同抽象层级, 但都叫 cosm-x

### 新结构 (v3.0)
```
src/math/
├── theory/                    # L2 宇宙理论层 (数学对物理的同构)
│   ├── 23d/                   # 23 维理论
│   │   ├── definitions.ts     # THEORY_DEFINITIONS (23 维定义)
│   │   ├── calculator.ts      # calculate_dimension_score (4 维独立 + 19 维 fallback)
│   │   └── uvrs.ts            # UVRS 聚合 (sigmoid)
│   ├── physics/               # 6 维物理 (开普勒/引力/潮汐/摄动/N体/相对论)
│   │   ├── orbital.ts         # 轨道六根数
│   │   ├── gravity.ts         # 万有引力场
│   │   ├── tidal.ts           # 潮汐力
│   │   ├── perturbation.ts    # 摄动理论
│   │   ├── nbody.ts           # N 体问题
│   │   ├── relativistic.ts    # 广义相对论 (复杂度张量)
│   │   └── saturation.ts      # 饱和风险评分
│   └── index.ts               # 统一导出
├── execution/                 # L1 原始数学 (CPG/图论/统计)
│   ├── cpg.ts                 # CPG 构建 (CFG/DFG/call/source-sink)
│   ├── graph-metrics.ts       # pagerank/betweenness/closeness
│   ├── entropy.ts             # 信息熵
│   ├── anomaly.ts             # z-score/Mahalanobis
│   ├── tda.ts                 # 0/1 维 Betti 数
│   ├── lyapunov.ts            # Lyapunov 近似
│   └── index.ts
├── application/               # L3 漏洞挖掘应用
│   ├── scanner.ts             # 项目扫描器 (旧 cosm-x-project-analyzer)
│   ├── patterns.ts            # 12 类漏洞规则 (VULN_PATTERNS)
│   ├── dedup.ts               # 去重 + 置信度过滤
│   ├── build-graph-23d.ts     # 23 维图数据构建 (修复 per-node)
│   ├── calibration.ts         # GA 进化 → 默认值回写
│   └── index.ts
├── pipeline/                  # 端到端管道
│   ├── run-scan.ts            # 单次扫描入口
│   ├── run-evolve.ts          # GA 进化入口
│   ├── run-evaluate.ts        # 真实 GT 评估入口
│   └── run-report.ts          # 报告生成入口
└── compat/                    # 兼容旧 API
    ├── cosm-x-theory-23d.ts   # re-export from theory/23d
    ├── cosm-x-galaxy.ts       # re-export from theory/physics
    ├── cosm-x-project-analyzer.ts  # re-export from application/scanner
    ├── cosm-x-dedup.ts        # re-export from application/dedup
    └── cosm-x-cli.ts          # re-export from pipeline/run-scan
```

## 3. 抽象层次清晰化

| 层次 | 数学对象 | 物理叙事 | 代码叙事 | 文件位置 |
|---|---|---|---|---|
| **L1 原始数学** | 矩阵/概率/统计 | 测量/观测 | CPG/pagerank | `math/execution/` |
| **L2 宇宙理论** | 距离/引力/摄动 | 物理定律 | 风险叙事 | `math/theory/` |
| **L3 漏洞挖掘** | 阈值/F1/GA | 实验验证 | 扫描管道 | `math/application/` + `math/pipeline/` |
| **L4 验证闭环** | 反向优化 | 物理实验 | 真实 GT 评估 | `math/pipeline/run-evaluate.ts` + `math/pipeline/run-evolve.ts` |

## 4. 数据层改进 (关键)

### 4.1 per-node 特征丰富度 (修复 #1 优先级)

**问题**: 当前 `buildGraphData23D` 只写 `_project_avg`, UVRS 实测只有 3 个值 (24.35/31.20/39.71)

**新设计**:
```typescript
export function buildGraphData23D(cpg, sixDim, finding): GraphData23D {
  // per-node 数据从 CPG 实际提取
  const node = finding.nodeId;  // "file:line"
  const cpgNode = cpg.nodes.get(node);
  
  return {
    // 从 CPG 节点直接拿
    pagerank: { [node]: cpgNode.pagerank, _project_avg: sixDim.vulnScore / 100 },
    betweenness: { [node]: cpgNode.betweenness, _project_avg: sixDim.vulnScore / 100 },
    in_degree: { [node]: cpgNode.inDegree },
    out_degree: { [node]: cpgNode.outDegree },
    cyclomatic_complexity: { [node]: cpgNode.cyclomaticComplexity },
    architectural_smells: { [node]: sixDim.anomalyScore },
    // ... 真实 per-node 特征
  };
}
```

**结果**: UVRS 反映**真实位置风险** 而非 severity 锚点

### 4.2 6 维非饱和信号 (修复 #2 优先级)

**问题**: 6 维 score 恒 100, 不能分级

**新设计**: 暴露**原始**子信号, 不用 saturate 封顶
```typescript
vulnerabilityScore = {
  anomaly_raw: anomalyScore,        // 0-10
  perturbation_raw: perturbationScore, // 0-10
  gravity_raw: gravityScore,        // 0-10
  composite: Math.min(1.0, anomalyScore*0.4 + perturbationScore*0.3 + gravityScore*0.3),
  composite_100: composite * 100,
};
```

**结果**: 过滤器可以基于 anomaly_raw / perturbation_raw (非饱和) 做精细过滤

### 4.3 GA 闭环 (修复 #3 优先级)

**问题**: GA 找到的 minScore=52.52 在真实扫描中过滤掉全部 (过拟合)

**新设计**: GA 不只优化 minScore, 还优化**规则权重** + **信号权重** + **dedup 策略**
```typescript
// GA 基因空间扩展 (6 维 → 12 维)
const geneSpace = [
  minScore,           // 阈值
  dedupStrategy,      // 'none' | 'file-type' | 'file-line-type'
  // 5 类规则权重
  w_sqli, w_xss, w_rce, w_path, w_auth,
  // 4 个信号开关
  use_kepler, use_entropy, use_tda, use_chaos,
];
```

**结果**: GA 可以**打开/关闭**维度, 而非只调阈值

## 5. 实施步骤

| 步骤 | 工作量 | 风险 | 状态 |
|---|---|---|---|
| 1. 写 REDESIGN.md (本文档) | 0.5h | 无 | ✓ 完成 |
| 2. 创建新目录 `src/math/{theory,execution,application,pipeline,compat}` | 0.1h | 低 | 待 |
| 3. 移动 cosm-x-* 到 compat/ (保留原文件) | 0.1h | 无 | 待 |
| 4. 创建新文件 re-export 旧 API | 0.2h | 无 | 待 |
| 5. 跑测试 104/104 验证兼容 | 0.1h | 低 | 待 |
| 6. 修复 buildGraphData23D per-node | 1.0h | 中 | 待 |
| 7. 暴露 6 维非饱和信号 | 0.5h | 中 | 待 |
| 8. 扩展 GA 基因空间 | 1.0h | 中 | 待 |
| 9. 写 RECURSIVE-MATH-VERIFICATION.md (操作手册) | 0.5h | 无 | 待 |
| 10. 跑真实扫描验证无 regression | 0.5h | 低 | 待 |

**预计总工作量**: ~4.5h, 分 3 个阶段交付

## 6. 命名原则 (新)

### 数学对象 (执行层)
- 用标准数学/ML 命名: `pagerank`, `betweenness`, `entropy`, `zscore`
- 文件位置: `src/math/execution/`

### 物理叙事 (理论层)
- 用物理命名: `orbitalElements`, `gravityField`, `tidalForce`, `perturbationGradient`
- 文件位置: `src/math/theory/`
- **每个物理命名都有对应的执行层数学实现** (同构映射)

### 代码应用 (应用层)
- 用代码分析命名: `cpg`, `taint`, `dataflow`, `cfg`, `dfg`
- 文件位置: `src/math/application/`

### 验证闭环
- 用验证命名: `calibration`, `evaluation`, `evolution`
- 文件位置: `src/math/pipeline/`

## 7. 不破坏的承诺

- ✓ **保留所有现有测试** (104/104 必须通过)
- ✓ **保留 cosm-x-* API** (通过 compat/ re-export)
- ✓ **保留 GA 进化结果** (v2.5.2 F1=0.1765 不丢)
- ✓ **保留现有 findings 格式** (含 uvrs / graph_data 字段)
- ✗ **不**改变 23 维命名 (叙事层完整)
- ✗ **不**重写核心数学 (KEPLER/ENTROPY/TDA/CHAOS 已工作)
- ✗ **不**破坏 GA 收敛点 (F1=0.1765 是基线)

## 8. 总结

**重新设计的目标**:
- 抽象层次清晰 (L1 原始数学 / L2 宇宙理论 / L3 漏洞挖掘 / L4 验证闭环)
- 命名按层次统一 (数学/物理/代码/验证)
- 数据层执行能力提升 (per-node + 非饱和 + GA 扩展)
- 保留所有现有功能 (compat layer)
- 数学验证叙事完整 (递归闭环)

**哲学不变**: 宇宙理论是数学对物理的同构解释, 漏洞挖掘是数学对代码的同构应用, 两者递归验证.
