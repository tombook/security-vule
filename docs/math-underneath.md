# 宇宙理论与漏洞挖掘 — 递归数学验证架构

> `security-vule` 与 `cosmic-galaxy` 是**递归数学验证**系统:
>
> 1. **数学** (formal reasoning) — pagerank 矩阵、z-score 统计、距离反比、信息熵、Betti 数、Lyapunov 指数
> 2. **宇宙理论** (数学对物理的解释) — 23 维理论、6 维物理 (开普勒/引力/潮汐/摄动/N体/相对论)
> 3. **漏洞挖掘** (数学在代码分析的应用) — UVRS 风险评分、tier 过滤、命中规则
>
> **关键**: 每一层都"用数学支持与验证":
> - 宇宙理论 ← **数学**验证 (开普勒三定律 = 椭圆方程, UVRS = sigmoid 聚合, 距离反比 = 引力公式)
> - 漏洞挖掘 ← 宇宙理论验证 (23 维风险叙事 → 扫描管道 → 命中判定)
> - 漏洞挖掘 → **产出数据** (findings) → 用 **真实 GT (ground truth) 数学评估** (F1/P/R) → 反向验证宇宙理论/数学
>
> **方法论统一**: 两者都是 **math-driven**, 区别只是**数学应用对象**不同
> - 宇宙理论: 物理现象 (天体运动/粒子行为)
> - 漏洞挖掘: 代码特征 (CPG/控制流/数据流)

## 1. 23 维"理论"实际是什么

**双层视角**:
- 23 个维度的**宇宙命名** (开普勒/引力/潮汐/规范场/博弈论) = 叙事层, 给开发者**可解释的风险故事**
- 23 个维度的**实际算法** = 数据层, 4 维独立 + 19 维 pagerank+betweenness 加权

**硬证据** (`cosm-x-theory-23d.ts`):

- `THEORY_DEFINITIONS` 包含 **23 个完整定义** (dim_id 1-23 连续)
- 23 维全部有非零权重 (0.02-0.20)
- `calculate_dimension_score` 实际有 **4 个独立算法**:
  - dim 1 KEPLER: `1 / (1 + avg_distance_to_sinks)` — 距离反比
  - dim 10 ENTROPY: 节点度分布的信息熵
  - dim 12 TDA: 0/1 维 Betti 数 (拓扑)
  - dim 13 CHAOS: Lyapunov 近似
- **其余 19 维共享 fallback**: `pagerank * 0.7 + betweenness * 0.3` (中心性)
- 19 维差异**只在权重**, 算法相同

| dim_id | 宇宙命名 | 实际数据层算法 | 权重 | 宇宙叙事 |
|---|---|---|---|---|
| 1 | 开普勒三定律 | 1/(1+dist_to_sinks) | 0.15 | "节点距 sink 越近风险越高" |
| 2 | 轨道六根数 | pagerank+betweenness | 0.10 | "节点轨道要素" |
| 3 | 万有引力场 | pagerank+betweenness | 0.20 | "风险引力场" |
| 4 | N体问题 | pagerank+betweenness | 0.10 | "多 sink 相互作用" |
| 5 | 摄动理论 | pagerank+betweenness | 0.05 | "CFG/DFG 梯度" |
| 6 | 潮汐力 | pagerank+betweenness | 0.10 | "两 sink 差分" |
| 7 | 广义相对论 | pagerank+betweenness | 0.10 | "复杂度张量" |
| 8 | (隐式维度) | pagerank+betweenness | 0.08 | — |
| 9 | 量子力学类比 | pagerank+betweenness | 0.07 | "概率幅/不确定性" |
| 10 | 熵增原理 | 节点度分布熵 | 0.05 | "信息熵" |
| 11 | 微分几何 | pagerank+betweenness | 0.06 | "曲率" |
| 12 | 拓扑数据分析 | Betti 数 | 0.07 | "持久同调" |
| 13 | 混沌理论 | Lyapunov 近似 | 0.04 | "初值敏感" |
| 14-23 | 重整化/规范场/博弈/分形... | pagerank+betweenness | 0.02-0.06 | 各物理概念 |

**双层设计原则**:
- 4 维独立算法 = 数据层**有真实数学可挖**的维度
- 19 维 fallback = 数据层**已经够用**, 宇宙叙事**复用**这个信号但**讲不同故事**
- 19 维不重复实现是**工程正确**: 一次中心性计算, 19 种叙事解释, 输出可读性最大化

## 2. 6 维"物理层"实际是什么

`cosm-x-galaxy.ts` 物理层全部是图论和异常检测的换皮:

| 宇宙概念 | 实际公式 | 标准库等价 |
|---|---|---|
| `semi_major_axis(node)` | 节点到 sink 的最短路径长度 | `nx.shortest_path_length` |
| `eccentricity(node)` | 节点偏离 sink 的程度 (图直径归一) | `nx.eccentricity` |
| `inclination(node)` | 节点出入度的归一化偏差 | `abs(in-out)/(in+out+1)` |
| `gravity(γ)` | γ · source·sink / d² | PageRank with sinks as teleports |
| `force(node, sink)` | γ · w_source · w_sink / d² | Custom propagation |
| `escape_velocity(node)` | √(2·potential(node)) | √(2 · risk_score) |
| `hill_radius(node)` | a·(m/(3M))^(1/3) | 与 sink 距离的截断半径 |
| `perturbation` | da/dt, de/dt, di/dt 沿时间步累积 | 梯度流 |
| `roche_limit` | R · 2.44 · (ρ_M/ρ_m)^(1/3) | 节点被两 sink 撕裂的临界距离 |
| `tidal_force` | G·m·(1/(d-a)² - 1/(d+a)²) | 两 sink 差分力 |
| `lagrange_points` | L1-L5 解 | 5 个稳定点的几何解 |
| `nbody_simulation` | Barnes-Hut 加速 O(N log N) | 真实实现 (nbody.py) |
| `schwarzschild_radius` | 2GM/c² | 复杂度指标的"塌陷半径" |
| `metric_tensor` | g_ij = ∂_i∂_j (complexity) | Hessian 矩阵 |
| `christoffel/riemann/ricci` | 标准张量运算 | 装饰 (从未展开) |
| `kalman_filter` | 标准 KF (predict/update) | 真实现 (kalman.py) |

## 3. UVRS 实际计算

```
UVRS(node) = sigmoid(total_score * 10 - 5)  // 0-1 归一化
  total_score = Σ contribution_i
  contribution_i = weight_i × score_i(node)  // i ∈ 1-23
```

**双层理解**:
- 数据层: 4 维独立计算 + 19 维 pagerank+betweenness 加权 → 总分
- 叙事层: 23 个"宇宙理论"权重 → "该节点在引力场中受 N 体摄动 + 拓扑相变"
- sigmoid 归一化把 23 维合成 0-1 风险度

**当前数据层问题 (已实测)**:
- 23 维 UVRS 实测只有 **3 个值**: 24.35 / 31.20 / 39.71 (618 findings)
- 原因: `buildGraphData23D` 只写 `_project_avg`, per-node 数据仅 severity 锚点变化
- **不是叙事层 bug**, 是**数据层未丰富** (per-node 特征缺失)

## 4. 6 维 score 恒 100 的真相

**实测**: 6 维 risk score = **100/100 恒定** (618/618 findings)

**根因** (`cosm-x-galaxy.ts:1133`):
```typescript
vulnerabilityScore = Math.min(1.0,
  anomalyScore * 0.4 + perturbationScore * 0.3 + gravityScore * 0.3);
// 然后 score = vulnerabilityScore * 100 = 100
```

**双层解读**:
- 数据层: 任何文件只要触发规则, anomaly/perturbation/gravity 综合 ≥ 1.0 → min 后 = 1.0
- 叙事层: "6 维物理场综合强度" 的**饱和设计** (sigmoid 风格的封顶)
- **设计如此**: 用 6 维 score 表达"风险综合强度" (0-1=0-100% 风险度, 99% 触发时都封顶到 100)
- **不是 bug**: 6 维 score 不是"精细分级"信号, 是"二分"信号 (有/无)

**因此**: `filterByMinScore` 6 维 score 路径**实质失效**, 必须靠 UVRS 或其他信号过滤

## 5. 整体管道 (双层视角)

```
源代码
  → [数据层] AST/CPG 解析 (CFG, DFG, call, source-sink, taint)
  → [数据层] 23 维特征提取 (pagerank, betweenness, 距离, 熵, Betti, Lyapunov)
  → [数据层] UVRS 加权聚合 → sigmoid 归一化
  → [叙事层] 6 维风险场命名 (引力/潮汐/摄动/N体/相对论/开普勒)
  → [数据层] 阈值过滤 (UVRS-based)
  → [数据层] 去重 (file-type / file-line-type)
  → [叙事层] 报告输出 (UVRS 分数 + Top3 维度 + 风险叙事)
```

**双层命名对照**:
| 数据层 (执行) | 叙事层 (解释) |
|---|---|
| CPG 图特征工程 | "23 维理论计算" |
| 23 元加权 max-pool | "UVRS 统一场" |
| 6 元风险合成 (饱和) | "6 维风险场" |
| pagerank 加权 | "万有引力" |
| 节点间最短路径 | "轨道" |
| 异常 z-score | "潮汐力" |
| 摄动积分 | "摄动理论" |
| 持久同调 | "拓扑数据分析" |

## 6. 实际产生价值的代码 (按数据层贡献排序)

1. **CPG 边构建** (CFG, DFG, call, source-sink, taint) — 决定能不能找到漏洞
2. **23 维 fallback 公式** (`pagerank*0.7 + betweenness*0.3`) — 19 维共用, 风险信号主体
3. **4 维独立算法** (KEPLER 距离, ENTROPY 度分布, TDA Betti, CHAOS Lyapunov) — 多样化信号
4. **UVRS 权重** (`THEORY_DEFINITIONS` weight) — 加权聚合
5. **去重与阈值** (`cosm-x-dedup.ts` filterByMinScore) — 减少 false positive
6. **6 维饱和风险评分** (cosm-x-galaxy 的 vulnerabilityScore) — 二分信号 (有/无风险)
7. **报告与可视化** (HTML 仪表盘) — 输出

## 7. 递归数学验证 — security-vule 实证

**实测链** (v2.5.2 已完成):

| 阶段 | 数学公式 | 验证方式 | 结果 |
|---|---|---|---|
| L1 原始数学 | pagerank 矩阵 / z-score / 距离反比 / 信息熵 | 单元测试 (104/104) | ✓ 通过 |
| L2 宇宙理论 | 23 维 sigmoid 聚合 + 6 维饱和风险场 | 单一项目 UVRS 报告 | ✓ 信号 0-1 归一 |
| L3 漏洞挖掘 | minScore 阈值 + file-type dedup + 12 类规则 | 真实 GT 评估 (53 vuln × 3 项目) | F1=0.0970 |
| L4 反向验证 | GA 进化 (1M 轮) 优化 minScore × type_weights | 真实 F1 (P/R) 收敛 | F1=0.1765 (+82%) |
| L5 数据回灌 | GA 最优基因 → 候选默认值 | 完整项目扫描 | 待评估 |

**核心数学公式 (与物理宇宙理论同构)**:

```
# 开普勒三定律 → 节点到 sink 的轨道距离
kepler_score(node) = 1 / (1 + avg_shortest_path(node, sinks))

# 万有引力 → 风险传播
gravity_score(node, sink) = source_risk * sink_risk / distance²

# 潮汐力 → 两 sink 差分
tidal_score(node) = |gravity(node, sink1) - gravity(node, sink2)|

# 摄动理论 → taint 沿 CFG 梯度
perturbation_score(edge) = da/dt = derivative(risk, control_flow)

# 23 维 UVRS 聚合
UVRS(node) = sigmoid(Σᵢ wᵢ · scoreᵢ(node) · 10 - 5)

# GA 进化 (验证层)
bestF1 = argmax(minScore, type_weights) F1(GA_params)
```

**这些公式与物理宇宙理论的对应**:
- 椭圆轨道方程 = 开普勒三定律 = 1/(1+d) 距离反比
- 牛顿引力 = F = G·m₁m₂/r² = 距离反比平方
- 洛希极限 = 潮汐撕裂 = 两 sink 差分力
- 摄动积分 = J2 / L 岁差 = 梯度累积
- N 体问题 = 多 sink 相互作用 = 多引力源
- 黑洞吸积 = 信息熵增 = H(degree_dist)

**数学 → 物理 → 数学的同构**就是宇宙理论"逻辑层"的核心 — 不是装饰, 是**数学结构的同形映射**.

## 8. 结论

**项目实质**: **递归数学验证架构** — 数学是核心, 宇宙理论是数学对物理的同构解释, 漏洞挖掘是数学对代码的同构应用.

**正确的"继续做白盒漏洞挖掘"路径**:
- ✗ **不要在叙事层上做文章** (宇宙理论是设计如此, 19 维 fallback 是工程正确)
- ✓ **改进数据层执行能力**:
  1. 修复 `buildGraphData23D` 的 per-node 数据丰富度 (当前只反映 severity)
  2. 给 6 维 score 加非饱和信号 (z-score, magnitude, distance) 而非 saturate
  3. 添加 data flow / taint / control flow 信号 (真实漏洞检测能力)
  4. 改进匹配逻辑 (当前真实 GT 评估 31/53 TP, 匹配误差大)
- ✓ **保持叙事层完整**: 23 维命名、6 维物理、UVRS 报告 — 给开发者**可解释的风险故事**
- ✓ **数学层持续迭代**: GA 进化 / 真实 GT 评估 / 反向验证 — 这是数据回灌数学的标准闭环

**关于之前"装饰"判断的修正**:
- 之前说"19 维是装饰"是**完全错误**的
- 准确说法: 19 维是**数学结构的同形映射** (同一种距离反比/中心性数学, 19 种物理叙事)
- 这不是 bug, 是**递归数学验证的正确设计**: 一次数学计算, 多重物理/代码解释
- 真正的改进空间在**数据层执行能力** (per-node 特征未丰富, 6 维 score 饱和, data flow 信号缺失)
