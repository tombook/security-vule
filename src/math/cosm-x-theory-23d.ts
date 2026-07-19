/**
 * 宇宙科学理论核心引擎 (Cosmic Theory Core) — 23 维度理论框架
 * =================================================================
 * 将 cosmic-galaxy/engine/cosmic_theory.py 与 uvrs.py 完整移植到 TypeScript
 *
 * 23 个理论维度覆盖：经典力学 → 相对论/量子 → 热力学/混沌
 *                 → 几何/拓扑 → 场论/相变 → 信息/逻辑 → 迁移/演化
 *
 * 核心映射 (Astrophysics / Theoretical Physics → Code Security Risk):
 * - 开普勒三定律 / 轨道六根数    → 节点到汇点的距离 / 节点多维风险特征
 * - 万有引力 / 潮汐力 / N体 / 摄动 → 调用链引力 / 多汇点撕裂 / 相互作用 / 迭代漂移
 * - 广义相对论 / 暗物质 / 量子    → 高复杂度时空弯曲 / 隐性技术债 / 边界不确定性
 * - 熵增 / 混沌 / 非平衡态        → 复杂度累积 / 蝴蝶效应 / 持续交付不稳定
 * - 微分几何 / TDA / 重整化群 / 分形 → 依赖曲率 / 拓扑缺陷 / 尺度缩放 / 自相似
 * - 量子场论 / 相变 / 规范场论    → 函数作为激发 / 架构临界 / 设计对称
 * - 信息论 / 范畴论 / 博弈论      → 信息密度 / 模块映射 / 团队策略
 * - 跨项目迁移理论                → 技术栈迁移与复用风险
 *
 * 风险等级阈值 (UVRS):
 *   < 0.25  LOW       🟢  轨道稳定
 *   < 0.50  MEDIUM    🟡  轨道轻微扰动
 *   < 0.85  HIGH      🟠  轨道显著偏斜
 *   >= 0.85 CRITICAL  🔴  即将碰撞
 *
 * @module cosm-x-theory-23d
 * @version 7.5 — TypeScript 移植版 (port of cosmic_theory.py + uvrs.py)
 */

// 无运行时依赖 — 纯算法 + 纯类型实现

// ============================================================================
// 第一部分：类型与枚举
// ============================================================================

/**
 * 23 个理论维度枚举
 *
 * 经典力学层 (1-6):
 * - 1 KEPLER              开普勒三定律
 * - 2 ORBITAL_ELEMENTS    轨道六根数
 * - 3 GRAVITY             万有引力场
 * - 4 N_BODY              N 体问题
 * - 5 PERTURBATION        摄动理论
 * - 6 TIDAL_FORCE         潮汐力
 *
 * 相对论与量子层 (7-9):
 * - 7 RELATIVITY          广义相对论
 * - 8 DARK_MATTER         暗物质/暗能量
 * - 9 QUANTUM_MECHANICS   量子力学类比
 *
 * 热力学与混沌层 (10, 13, 22):
 * - 10 ENTROPY                       熵增原理
 * - 13 CHAOS                         混沌理论
 * - 22 NONEQUILIBRIUM_THERMODYNAMICS 非平衡态热力学
 *
 * 几何与拓扑层 (11, 12, 14, 21):
 * - 11 DIFFERENTIAL_GEOMETRY      微分几何
 * - 12 TOPOLOGICAL_DATA_ANALYSIS  拓扑数据分析
 * - 14 RENORMALIZATION_GROUP      重整化群
 * - 21 FRACTAL                    分形几何
 *
 * 场论与相变层 (15-17):
 * - 15 FIELD_THEORY      量子场论
 * - 16 PHASE_TRANSITION  相变理论
 * - 17 GAUGE_THEORY      规范场论
 *
 * 信息与逻辑层 (18-20):
 * - 18 INFORMATION_THEORY 信息论
 * - 19 CATEGORY_THEORY    范畴论
 * - 20 GAME_THEORY        博弈论
 *
 * 迁移与演化层:
 * - 23 CODE_MIGRATION 跨项目迁移理论
 */
export enum TheoryDimension {
  // 经典力学层 (1-6)
  KEPLER = 1,
  ORBITAL_ELEMENTS = 2,
  GRAVITY = 3,
  N_BODY = 4,
  PERTURBATION = 5,
  TIDAL_FORCE = 6,

  // 相对论与量子层 (7-9)
  RELATIVITY = 7,
  DARK_MATTER = 8,
  QUANTUM_MECHANICS = 9,

  // 热力学与混沌层
  ENTROPY = 10,

  // 几何与拓扑层
  DIFFERENTIAL_GEOMETRY = 11,
  TOPOLOGICAL_DATA_ANALYSIS = 12,

  // 混沌 (层号 13)
  CHAOS = 13,

  // 重整化群 (层号 14)
  RENORMALIZATION_GROUP = 14,

  // 场论与相变层
  FIELD_THEORY = 15,
  PHASE_TRANSITION = 16,
  GAUGE_THEORY = 17,

  // 信息与逻辑层
  INFORMATION_THEORY = 18,
  CATEGORY_THEORY = 19,
  GAME_THEORY = 20,

  // 分形 (层号 21)
  FRACTAL = 21,

  // 非平衡态热力学 (层号 22)
  NONEQUILIBRIUM_THERMODYNAMICS = 22,

  // 迁移与演化层
  CODE_MIGRATION = 23,
}

/**
 * 风险等级 (UVRS 统一风险评分)
 */
export enum RiskLevel {
  LOW = 'LOW',            // 🟢 轨道稳定
  MEDIUM = 'MEDIUM',      // 🟡 轨道轻微扰动
  HIGH = 'HIGH',          // 🟠 轨道显著偏斜
  CRITICAL = 'CRITICAL',  // 🔴 即将碰撞
}

/**
 * 理论维度完整定义 (Python dataclass TheoryDefinition 对应)
 */
export interface TheoryDefinition {
  /** 维度 ID (1-23) */
  dim_id: number;
  /** 中文名称 */
  name: string;
  /** 维度的物理/数学描述 */
  description: string;
  /** 核心公式 (LaTeX 风格) */
  core_formula: string;
  /** 与代码风险的具体映射说明 */
  code_risk_mapping: string;
  /** 原始权重 (在引擎初始化时会被归一化) */
  weight: number;
  /** 是否启用 */
  enabled: boolean;
}

/**
 * 单维度风险计算结果
 */
export interface TheoryCalculationResult {
  dim_id: number;
  name: string;
  score: number;
  risk_level: RiskLevel | string;
  contribution: number;
  calculation_details: Record<string, unknown>;
}

/**
 * 风险等级阈值 (与 Python 端一致)
 *
 * - < 0.25  → LOW
 * - < 0.50  → MEDIUM
 * - < 0.85  → HIGH
 * - >= 0.85 → CRITICAL
 */
export const RISK_THRESHOLDS: Record<RiskLevel, number> = {
  [RiskLevel.LOW]: 0.25,
  [RiskLevel.MEDIUM]: 0.50,
  [RiskLevel.HIGH]: 0.75,
  [RiskLevel.CRITICAL]: 0.85,
};

/**
 * 图数据 (CPG/调用图) 上下文
 *
 * 兼容 cosm-x-galaxy.ts 的 CPGBuilder 产出，所有字段都是可选的，
 * 未提供的字段将退回到维度特定的默认值或基于 pageRank 的回退算法。
 */
export interface GraphData {
  /** 风险汇点 (sink) ID 列表 (如污点汇聚点) */
  sinks?: string[];
  /** node -> sink -> 最短路径距离 */
  shortest_paths?: Record<string, Record<string, number>>;
  in_degree?: Record<string, number>;
  out_degree?: Record<string, number>;
  cyclomatic_complexity?: Record<string, number>;
  /** 节点是否处于循环中 */
  cycles?: Record<string, boolean>;
  /** 节点是否孤立 */
  isolated_nodes?: Record<string, boolean>;
  /** 架构坏味计数 */
  architectural_smells?: Record<string, number>;
  input_params?: Record<string, number>;
  output_vals?: Record<string, number>;
  side_effects?: Record<string, number>;
  pagerank?: Record<string, number>;
  betweenness?: Record<string, number>;
  /** 任意其他维度数据 — 允许后续扩展 */
  [key: string]: unknown;
}

/**
 * 节点维度分量 (UVRS 使用的扁平化结构)
 */
export type DimensionComponents = Record<string, number>;

// ============================================================================
// 第二部分：23 维度完整元数据
// ============================================================================

/**
 * 23 维度完整元数据常量
 *
 * 顺序与 cosmic_theory.py THEORY_DEFINITIONS 完全一致。
 * 权重在引擎构造时会被归一化到 sum = 1.0。
 */
export const THEORY_DEFINITIONS: readonly TheoryDefinition[] = [
  // ---------- 经典力学层 (1-6) ----------
  {
    dim_id: 1,
    name: '开普勒三定律',
    description: '行星运动三大定律：椭圆轨道、面积速度守恒、周期平方与半长轴立方成正比',
    core_formula: 'T² = (4π²/GM)a³',
    code_risk_mapping: '节点到汇点的距离风险，距离越近风险越高',
    weight: 0.15,
    enabled: true,
  },
  {
    dim_id: 2,
    name: '轨道六根数',
    description: '描述天体轨道的6个参数：半长轴、偏心率、轨道倾角、升交点赤经、近心点幅角、真近点角',
    core_formula: '[a, e, i, Ω, ω, θ]',
    code_risk_mapping: '节点多维风险特征向量，综合评估轨道稳定性',
    weight: 0.10,
    enabled: true,
  },
  {
    dim_id: 3,
    name: '万有引力场',
    description: '两个物体之间的引力与质量成正比，与距离平方成反比',
    core_formula: 'F = G·m1·m2/r², v_escape = √(2GM/r)',
    code_risk_mapping: '节点受汇点的引力风险，质量对应代码复杂度，距离对应调用深度',
    weight: 0.20,
    enabled: true,
  },
  {
    dim_id: 4,
    name: 'N体问题',
    description: 'N个天体在引力相互作用下的运动规律，Barnes-Hut算法实现O(N log N)模拟',
    core_formula: 'd²r_i/dt² = Σ_{j≠i} G·m_j (r_j - r_i)/|r_j - r_i|³',
    code_risk_mapping: '多节点之间的相互作用风险，复杂调用链路的整体稳定性评估',
    weight: 0.10,
    enabled: true,
  },
  {
    dim_id: 5,
    name: '摄动理论',
    description: '天体运动受其他天体引力影响的微小偏移，拉格朗日行星方程计算长期漂移',
    core_formula: 'da/dt, de/dt, di/dt = f(摄动力)',
    code_risk_mapping: '代码迭代的长期风险漂移，依赖变化导致的轨道偏移',
    weight: 0.05,
    enabled: true,
  },
  {
    dim_id: 6,
    name: '潮汐力',
    description: '天体不同部位受引力差异产生的拉伸力，超过罗希极限会被撕裂',
    core_formula: 'F_tidal = 2G·M·m·Δr / r³',
    code_risk_mapping: '多汇点对节点的撕裂风险，多业务线同时调用导致的代码复杂度暴涨',
    weight: 0.10,
    enabled: true,
  },

  // ---------- 相对论与量子层 (7-9) ----------
  {
    dim_id: 7,
    name: '广义相对论',
    description: '引力是时空弯曲的表现，爱因斯坦场方程描述时空曲率与物质能量的关系',
    core_formula: 'G_μν + Λg_μν = 8πG/c⁴ T_μν, R_s = 2GM/c²',
    code_risk_mapping: '高复杂度节点的时空弯曲效应，代码质量对风险的非线性放大',
    weight: 0.10,
    enabled: true,
  },
  {
    dim_id: 8,
    name: '暗物质/暗能量',
    description: '不可见的质量和能量，占宇宙总质能的95%，驱动宇宙加速膨胀',
    core_formula: 'M_dark = M_observed - M_visible, d²a/dt² = H²aΩ_Λ',
    code_risk_mapping: '隐藏的依赖风险、隐性技术债务、不可见的团队沟通成本',
    weight: 0.08,
    enabled: true,
  },
  {
    dim_id: 9,
    name: '量子力学类比',
    description: '微观粒子的波粒二象性、不确定性原理、量子隧穿效应',
    core_formula: '|ψ⟩ = α|safe⟩ + β|vuln⟩, P_tunnel = exp(-2d√2m(V-E)/ħ)',
    code_risk_mapping: '低概率高影响漏洞、边界情况触发的异常风险、黑盒系统的不确定性',
    weight: 0.07,
    enabled: true,
  },

  // ---------- 热力学与混沌层 (10) ----------
  {
    dim_id: 10,
    name: '熵增原理',
    description: '孤立系统的无序度随时间自发增加，热力学第二定律',
    core_formula: 'dS/dt ≥ 0, ρ_vuln = ρ₀ exp(λS)',
    code_risk_mapping: '代码复杂度随时间自发增加，技术债务的熵增效应',
    weight: 0.05,
    enabled: true,
  },

  // ---------- 几何与拓扑层 (11, 12) ----------
  {
    dim_id: 11,
    name: '微分几何',
    description: '研究微分流形的几何性质，度量张量、曲率、测地线',
    core_formula: 'g_μν, Γ^α_βγ, R^α_βγδ, S_EH = ∫R√(-g) d⁴x',
    code_risk_mapping: '代码依赖空间的曲率、最短调用路径、复杂系统的几何结构特征',
    weight: 0.06,
    enabled: true,
  },
  {
    dim_id: 12,
    name: '拓扑数据分析',
    description: '通过拓扑不变量分析数据的内在结构，持久同调、贝蒂数、Mapper算法',
    core_formula: 'β_0 (连通分支), β_1 (环), β_2 (空洞), Persistence Diagram',
    code_risk_mapping: '代码结构的拓扑缺陷、依赖环、孤立模块、架构设计的结构性风险',
    weight: 0.07,
    enabled: true,
  },

  // ---------- 混沌 (13) ----------
  {
    dim_id: 13,
    name: '混沌理论',
    description: '确定性系统的内在随机行为，初始条件敏感依赖，蝴蝶效应',
    core_formula: 'λ = lim_{t→∞} (1/t) ln|δx(t)/δx(0)|, T_predict ≈ 1/λ',
    code_risk_mapping: '微小输入变化导致的巨大输出异常，不可预测的系统行为',
    weight: 0.04,
    enabled: true,
  },

  // ---------- 重整化群 (14) ----------
  {
    dim_id: 14,
    name: '重整化群',
    description: '不同尺度下物理系统的行为变化，重标度变换、不动点、临界指数',
    core_formula: 'RG: Γ_eff(p) = Γ₀(p/Λ) + Σ corrections, β(g) = dg/d ln μ',
    code_risk_mapping: '不同抽象层级的风险缩放、宏观架构风险与微观代码风险的映射关系',
    weight: 0.05,
    enabled: true,
  },

  // ---------- 场论与相变层 (15-17) ----------
  {
    dim_id: 15,
    name: '量子场论',
    description: '粒子是场的激发态，费曼图计算相互作用，路径积分量子化',
    core_formula: 'Z = ∫Dφ exp(iS[φ]/ħ), S = ∫L(φ, ∂_μφ) d⁴x',
    code_risk_mapping: '代码作为场的激发态，函数调用是粒子相互作用，副作用是虚粒子过程',
    weight: 0.06,
    enabled: true,
  },
  {
    dim_id: 16,
    name: '相变理论',
    description: '系统从一种有序态转变为另一种有序态的临界行为，序参量、临界指数、普适类',
    core_formula: 'M(T) ≈ T_c - T)^β, χ ≈ |T-T_c|^-γ, ξ ≈ |T-T_c|^-ν',
    code_risk_mapping: '系统架构的临界转变、技术栈升级的相变过程、团队规模超过阈值的行为突变',
    weight: 0.05,
    enabled: true,
  },
  {
    dim_id: 17,
    name: '规范场论',
    description: '对称性决定相互作用，规范对称性、杨-米尔斯理论、标准模型',
    core_formula: 'D_μ = ∂_μ + igA_μ^a T^a, L_YM = -1/4 F^a_μν F^{a μν}',
    code_risk_mapping: '代码设计的规范约束、架构的对称性与不变性、设计模式的统一相互作用',
    weight: 0.04,
    enabled: true,
  },

  // ---------- 信息与逻辑层 (18-20) ----------
  {
    dim_id: 18,
    name: '信息论',
    description: '信息的量化、传输、存储，香农熵、互信息、信道容量',
    core_formula: 'H(X) = -Σ p_i log p_i, C = B log2(1 + S/N)',
    code_risk_mapping: '代码的信息密度、注释信息熵、接口设计的信息传输效率、日志的信息增益',
    weight: 0.03,
    enabled: true,
  },
  {
    dim_id: 19,
    name: '范畴论',
    description: '研究数学结构之间的关系，对象、态射、函子、自然变换、范畴等价',
    core_formula: 'F: C→D, F(f: X→Y) = F(f): F(X)→F(Y), η: F→G',
    code_risk_mapping: '代码模块之间的映射关系、架构设计的 functor 模式、领域模型的范畴等价性',
    weight: 0.02,
    enabled: true,
  },
  {
    dim_id: 20,
    name: '博弈论',
    description: '多个理性决策者之间的策略互动，纳什均衡、囚徒困境、演化博弈',
    core_formula: 'u_i(s_i, s_{-i}) ≥ u_i(s_i\', s_{-i}) ∀s_i\' ∀i',
    code_risk_mapping: '团队开发的协作博弈、技术选型的策略平衡、技术债务的囚徒困境、开源社区的演化博弈',
    weight: 0.02,
    enabled: true,
  },

  // ---------- 分形 (21) ----------
  {
    dim_id: 21,
    name: '分形几何',
    description: '具有自相似结构的几何对象，分形维度、迭代函数系统',
    core_formula: 'D = log N / log s, Mandelbrot Set: z_{n+1} = z_n² + c',
    code_risk_mapping: '代码结构的自相似性、重复模式、递归调用的复杂度、微服务架构的分形特征',
    weight: 0.04,
    enabled: true,
  },

  // ---------- 非平衡态热力学 (22) ----------
  {
    dim_id: 22,
    name: '非平衡态热力学',
    description: '远离热力学平衡态的系统行为，耗散结构、自组织现象',
    core_formula: 'dS = dS_ext + dS_int, σ = J·X, Onsager L_ij = L_ji',
    code_risk_mapping: '快速迭代的不稳定系统、自组织团队的开发行为、持续交付系统的稳定性',
    weight: 0.03,
    enabled: true,
  },

  // ---------- 迁移与演化层 (23) ----------
  {
    dim_id: 23,
    name: '跨项目迁移理论',
    description: '代码在不同项目、架构、技术栈之间迁移的规律',
    core_formula: 'ΔRisk = αΔComplexity + βΔTechGap + γΔTeamSkill + ε',
    code_risk_mapping: '代码迁移的风险评估、技术栈升级的成本预测、跨项目复用的风险度量',
    weight: 0.03,
    enabled: true,
  },
] as const;

// ============================================================================
// 第三部分：内部数学工具
// ============================================================================

/**
 * 数值安全 sigmoid 函数 — 防止上溢/下溢
 *
 * @param x 实数输入
 * @returns 1 / (1 + e^{-x})
 */
function sigmoid(x: number): number {
  if (x > 50) return 1.0;
  if (x < -50) return 0.0;
  return 1.0 / (1.0 + Math.exp(-x));
}

/**
 * 数组算术平均
 */
function mean(values: number[]): number {
  if (values.length === 0) return 0.0;
  let s = 0.0;
  for (const v of values) s += v;
  return s / values.length;
}

/**
 * 数组中位数
 */
function median(values: number[]): number {
  if (values.length === 0) return 0.0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

/**
 * 数组第 p 百分位 (0-100)，使用线性插值
 */
function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0.0;
  const sorted = [...values].sort((a, b) => a - b);
  if (sorted.length === 1) return sorted[0];
  const rank = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo];
  const w = rank - lo;
  return sorted[lo] * (1 - w) + sorted[hi] * w;
}

/**
 * 数组标准差 (总体)
 */
function stddev(values: number[]): number {
  if (values.length === 0) return 0.0;
  const m = mean(values);
  let acc = 0.0;
  for (const v of values) {
    const d = v - m;
    acc += d * d;
  }
  return Math.sqrt(acc / values.length);
}

/**
 * 将数值 score 映射到风险等级
 */
function classifyByScore(score: number): RiskLevel {
  if (score < RISK_THRESHOLDS[RiskLevel.LOW]) return RiskLevel.LOW;
  if (score < RISK_THRESHOLDS[RiskLevel.MEDIUM]) return RiskLevel.MEDIUM;
  if (score < RISK_THRESHOLDS[RiskLevel.CRITICAL]) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

// ============================================================================
// 第四部分：CosmicTheoryEngine — 23 维度理论核心引擎
// ============================================================================

/**
 * 宇宙科学理论核心引擎
 *
 * 职责：
 *  1. 加载 23 个维度的元数据
 *  2. 归一化权重 (在构造时把所有启用维度的权重除以总和)
 *  3. 对单个节点按 23 个维度分别计算 0-1 风险得分
 *  4. 加权融合 + sigmoid 归一化得到统一风险评分
 *  5. 生成白皮书数据 / 优化权重
 *
 * 维度特定算法：
 *  - dim 1  (开普勒)    : 1 / (1 + avg_distance_to_sinks)
 *  - dim 10 (熵增)      : (in+out)*cyclo / 100
 *  - dim 12 (拓扑)      : in_cycle + isolated + smell
 *  - dim 13 (混沌)      : (input+output+side_effect) / 20
 *  - 其余维度          : 基于 pagerank + betweenness 的回退算法
 */
export class CosmicTheoryEngine {
  /** 内部维度元数据 (深拷贝，避免外部修改) */
  private readonly definitions: Map<number, TheoryDefinition>;
  /** 启用的维度 ID 列表 */
  public readonly enabled_dims: number[];
  /** 归一化后的总权重 (通常 = 1.0) */
  public readonly total_weight: number;

  constructor(enabled_dimensions?: number[]) {
    // 深拷贝 + 过滤
    this.definitions = new Map<number, TheoryDefinition>();
    const enabled = enabled_dimensions ?? THEORY_DEFINITIONS.map((d) => d.dim_id);
    for (const def of THEORY_DEFINITIONS) {
      this.definitions.set(def.dim_id, { ...def });
    }
    this.enabled_dims = enabled.filter((id) => this.definitions.has(id));

    // 归一化权重 (只对启用的维度归一化)
    const totalRawWeight = this.enabled_dims.reduce(
      (acc, id) => acc + (this.definitions.get(id)?.weight ?? 0),
      0,
    );
    this.total_weight = totalRawWeight > 0 ? totalRawWeight : 1.0;
    if (totalRawWeight > 0) {
      for (const id of this.enabled_dims) {
        const d = this.definitions.get(id);
        if (d) d.weight = d.weight / totalRawWeight;
      }
    }
  }

  /**
   * 获取指定 ID 的维度定义
   *
   * @param dim_id 维度 ID (1-23)
   * @returns TheoryDefinition 或 null (未启用/不存在)
   */
  get_dimension_definition(dim_id: number): TheoryDefinition | null {
    return this.definitions.get(dim_id) ?? null;
  }

  /**
   * 列出当前所有启用的维度定义 (按 dim_id 升序)
   */
  list_dimensions(): TheoryDefinition[] {
    const out: TheoryDefinition[] = [];
    for (const id of this.enabled_dims) {
      const d = this.definitions.get(id);
      if (d) out.push(d);
    }
    return out.sort((a, b) => a.dim_id - b.dim_id);
  }

  /**
   * 计算单个维度的风险得分
   *
   * 不同维度使用不同的核心算法；其余维度使用基于 pageRank + betweenness 的回退算法。
   *
   * @param dim_id 维度 ID (1-23)
   * @param graph_data 图数据上下文
   * @param node 目标节点 ID
   * @returns 该维度的计算结果
   */
  calculate_dimension_score(
    dim_id: number,
    graph_data: GraphData,
    node: string,
  ): TheoryCalculationResult {
    const dim_def = this.get_dimension_definition(dim_id);
    if (!dim_def) {
      return {
        dim_id,
        name: 'Unknown',
        score: 0.0,
        risk_level: RiskLevel.LOW,
        contribution: 0.0,
        calculation_details: {},
      };
    }

    let score = 0.0;
    const details: Record<string, unknown> = {};

    // 节点级查找辅助: 若 node 无数据则回退到 _project_avg 聚合点
    // 这是 v2.5.1 修复: 之前 buildGraphData23D 只写 _project_avg, 导致所有 dimension
    // 拿到 0, UVRS 恒为 0.01 (sigmoid(-5)≈0.0067). 现在统一回退到项目级值.
    const getNode = (table: Record<string, number> | undefined, fallback: number = 0): number => {
      if (!table) return fallback;
      if (typeof table[node] === 'number') return table[node];
      if (typeof table['_project_avg'] === 'number') return table['_project_avg'];
      return fallback;
    };
    const getNodeBool = (table: Record<string, boolean> | undefined): boolean | undefined => {
      if (!table) return undefined;
      if (node in table) return table[node];
      if ('_project_avg' in table) return table['_project_avg'];
      return undefined;
    };
    const getNodeArr = (table: Record<string, number[]> | undefined, key: string): number | undefined => {
      if (!table) return undefined;
      if (Array.isArray(table[node])) {
        const arr = table[node];
        return key in arr ? arr[Number(key)] : undefined;
      }
      if (Array.isArray(table['_project_avg'])) {
        return table['_project_avg'][Number(key)];
      }
      return undefined;
    };

    if (dim_id === TheoryDimension.KEPLER) {
      // 半长轴对应到汇点的平均距离 → 1 / (1 + d)
      const sinks = graph_data.sinks ?? [];
      const sp = graph_data.shortest_paths ?? {};
      const distances: number[] = [];
      for (const sink of sinks) {
        const d = sp[node]?.[sink] ?? sp['_project_avg']?.[sink];
        if (typeof d === 'number' && Number.isFinite(d)) {
          distances.push(d);
        }
      }
      if (distances.length > 0) {
        const avg = mean(distances);
        score = 1.0 / (1.0 + avg);
        details['average_distance_to_sinks'] = avg;
        details['sink_count'] = distances.length;
      } else {
        // fallback: 用 vulnerabilityScore 作锚
        score = 0.5;
        details['algorithm'] = 'fallback_kepler_no_sinks';
      }
    } else if (dim_id === TheoryDimension.ENTROPY) {
      // 复杂度熵: (in+out) * cyclo / 100，clip 到 [0,1]
      const inDeg = getNode(graph_data.in_degree);
      const outDeg = getNode(graph_data.out_degree);
      const cyclo = getNode(graph_data.cyclomatic_complexity, 1);
      const entropy = ((inDeg + outDeg) * cyclo) / 100.0;
      score = Math.min(1.0, entropy / 5.0);
      details['complexity_entropy'] = entropy;
      details['in_degree'] = inDeg;
      details['out_degree'] = outDeg;
      details['cyclomatic_complexity'] = cyclo;
    } else if (dim_id === TheoryDimension.TOPOLOGICAL_DATA_ANALYSIS) {
      // 拓扑缺陷
      const inCycle = getNodeBool(graph_data.cycles) === true;
      const isolated = getNodeBool(graph_data.isolated_nodes) === true;
      const smell = getNode(graph_data.architectural_smells);
      score = 0.0;
      if (inCycle) score += 0.3;
      if (isolated) score += 0.2;
      score += Math.min(0.5, smell / 10.0);
      details['in_cycle'] = inCycle;
      details['isolated'] = isolated;
      details['architectural_smell_count'] = smell;
    } else if (dim_id === TheoryDimension.CHAOS) {
      // 初始条件敏感度 / Lyapunov 指数估计
      const ic = getNode(graph_data.input_params);
      const oc = getNode(graph_data.output_vals);
      const se = getNode(graph_data.side_effects);
      const lyapunov = (ic + oc + se) / 20.0;
      score = Math.min(1.0, lyapunov / 2.0);
      details['lyapunov_exponent_estimate'] = lyapunov;
      details['predictability_window'] = 1.0 / Math.max(lyapunov, 0.1);
      details['input_params'] = ic;
      details['output_vals'] = oc;
      details['side_effects'] = se;
    } else {
      // 回退: 基于节点重要性 (pagerank + betweenness)
      // v2.5.1: 直接加权求和 (不再 saturate), 让 severity 锚点完全可见
      const pr = getNode(graph_data.pagerank);
      const bw = getNode(graph_data.betweenness);
      score = Math.min(1.0, pr * 0.7 + bw * 0.3);
      details['pagerank'] = pr;
      details['betweenness'] = bw;
      details['algorithm'] = 'fallback_centrality_v251';
    }

    const risk_level = classifyByScore(score);
    const contribution = score * dim_def.weight;

    return {
      dim_id,
      name: dim_def.name,
      score,
      risk_level,
      contribution,
      calculation_details: details,
    };
  }

  /**
   * 计算所有启用维度的风险得分
   *
   * @param graph_data 图数据上下文
   * @param node 目标节点 ID
   * @returns 按 dim_id 升序排列的 TheoryCalculationResult 列表
   */
  calculate_all_dimensions(
    graph_data: GraphData,
    node: string,
  ): TheoryCalculationResult[] {
    const results: TheoryCalculationResult[] = [];
    for (const id of this.enabled_dims) {
      results.push(this.calculate_dimension_score(id, graph_data, node));
    }
    return results;
  }

  /**
   * 计算统一风险评分 (UVRS 0-1)
   *
   * 算法:
   *  1. 调用 calculate_all_dimensions 得到所有维度的 contribution
   *  2. 求和 → total_score
   *  3. sigmoid(total_score * 10 - 5) → normalized_score
   *
   * @param graph_data 图数据上下文
   * @param node 目标节点 ID
   * @returns [归一化分数, 维度结果列表]
   */
  calculate_unified_risk_score(
    graph_data: GraphData,
    node: string,
  ): UVRS {
    const results = this.calculate_all_dimensions(graph_data, node);
    const total = results.reduce((acc, r) => acc + r.contribution, 0);
    const normalized = sigmoid(total * 10.0 - 5.0);
    const dimContrib: Record<string, number> = {};
    const dimScore: Record<string, number> = {};
    const dimContribById: Record<number, number> = {};
    for (const r of results) {
      const def = THEORY_DEFINITIONS.find(d => d.dim_id === r.dim_id);
      const name = def?.name ?? `dim_${r.dim_id}`;
      dimContrib[name] = r.contribution;
      dimScore[name] = r.score;
      dimContribById[r.dim_id] = r.contribution;
    }
    const dimNames: Record<number, string> = {};
    for (const d of THEORY_DEFINITIONS) dimNames[d.dim_id] = d.name;
    const sorted = Object.entries(dimContrib).sort((a, b) => b[1] - a[1]).map(([n]) => n);
    return {
      unified_score: normalized,
      risk_level: normalized >= 0.7 ? RiskLevel.CRITICAL : normalized >= 0.4 ? RiskLevel.HIGH : normalized >= 0.2 ? RiskLevel.MEDIUM : RiskLevel.LOW,
      top_risk_dimensions: sorted.map(n => THEORY_DEFINITIONS.find(d => d.name === n)?.dim_id).filter((x): x is number => typeof x === 'number'),
      top_risk_dimension_names: sorted,
      dimension_contributions: dimContrib,
      dimension_scores: dimScore,
      dimension_names: dimNames,
      dimension_contributions_by_id: dimContribById,
      metadata: { engine_version: '7.5', computed_at: Date.now(), enabled_dimensions: THEORY_DEFINITIONS.map(d => d.dim_id) },
    };
  }

  /**
   * 生成理论白皮书数据
   *
   * 输出:
   *  - dimensions: 维度元数据列表 (含归一化后权重)
   *  - total_dimensions: 启用维度数
   *  - total_weight: 权重总和 (归一化后 = 1.0)
   *  - version: '7.5'
   */
  get_theory_whitepaper_data(): {
    dimensions: Array<{
      id: number;
      name: string;
      description: string;
      core_formula: string;
      code_risk_mapping: string;
      weight: number;
    }>;
    total_dimensions: number;
    total_weight: number;
    version: string;
  } {
    return {
      dimensions: this.list_dimensions().map((d) => ({
        id: d.dim_id,
        name: d.name,
        description: d.description,
        core_formula: d.core_formula,
        code_risk_mapping: d.code_risk_mapping,
        weight: d.weight,
      })),
      total_dimensions: this.enabled_dims.length,
      total_weight: this.total_weight,
      version: '7.5',
    };
  }

  /**
   * 基于标注的漏洞数据优化维度权重 (TODO: 实际逻辑回归优化)
   *
   * 当前实现：返回当前权重
   *
   * @param _labeled_data 标注的漏洞数据 (保留参数)
   * @returns {dim_id: weight} 映射
   */
  optimize_weights(_labeled_data: Array<Record<string, unknown>>): Record<number, number> {
    const out: Record<number, number> = {};
    for (const id of this.enabled_dims) {
      out[id] = this.definitions.get(id)?.weight ?? 0;
    }
    return out;
  }
}

// ============================================================================
// 第五部分：UVRS — 统一漏洞风险评分
// ============================================================================

/**
 * UVRS 默认权重 (基于理论重要性排序)
 *
 * 核心维度: kepler, gravity, tidal, nbody, perturbation, relativistic,
 *         dark_matter, quantum, entropy, history
 * 扩展维度: 默认权重为 0 (待实证调优)
 */
export const UVRS_DEFAULT_WEIGHTS: Record<string, number> = {
  // 核心维度 (有非零权重)
  kepler: 0.15,
  gravity: 0.20,
  tidal: 0.10,
  nbody: 0.10,
  perturbation: 0.05,
  relativistic: 0.10,
  dark_matter: 0.08,
  quantum: 0.07,
  entropy: 0.05,
  history: 0.10,

  // 扩展维度 (v3.0+, 默认权重为 0，待实证调优)
  differential_geometry: 0.0,
  topology: 0.0,
  chaos: 0.0,
  renormalization: 0.0,
  phase_transition: 0.0,
  field_theory: 0.0,
  information: 0.0,
  category: 0.0,
  fractal: 0.0,
  non_equilibrium: 0.0,
  game_theory: 0.0,
  transfer: 0.0,
};

/**
 * 各维度风险分量的典型值 (用于缺失值填充)
 */
export const UVRS_DIMENSION_DEFAULTS: Record<string, number> = {
  kepler: 0.3,
  gravity: 0.2,
  tidal: 0.15,
  nbody: 0.15,
  perturbation: 0.1,
  relativistic: 0.2,
  dark_matter: 0.1,
  quantum: 0.1,
  entropy: 0.2,
  history: 0.1,
};

/**
 * UVRS 评分统计信息
 */
export interface UVRSStatistics {
  mean: number;
  median: number;
  std: number;
  min: number;
  max: number;
  q25: number;
  q75: number;
  high_risk_ratio: number;
  critical_ratio: number;
}

/**
 * UVRS 导出配置 (export_config / from_config 序列化格式)
 */
export interface UVRSConfigExport {
  weights: Record<string, number>;
  thresholds: Record<string, number>;
}

/**
 * 统一漏洞风险评分系统 (Unified Vulnerability Risk Score)
 *
 * 公式:
 *   UVRS(v) = σ(Σᵢ wᵢ · Rᵢ(v))
 *   σ(x)    = 1 / (1 + e^{-x})
 *
 * 用法:
 * ```ts
 * const scorer = new UVRSCalculator();
 * const score = scorer.compute({ kepler: 0.4, gravity: 0.3, ... });
 * const level = scorer.classify(score);
 * ```
 */
export class UVRSCalculator {
  /** 维度名 → 权重 */
  public weights: Record<string, number>;
  /** 风险等级 → 阈值 */
  public thresholds: Record<RiskLevel, number>;

  /**
   * @param weights 自定义权重 (省略时使用 UVRS_DEFAULT_WEIGHTS)
   * @param thresholds 自定义阈值 (省略时使用 RISK_THRESHOLDS)
   */
  constructor(
    weights?: Record<string, number>,
    thresholds?: Record<RiskLevel, number>,
  ) {
    this.weights = weights ? { ...weights } : { ...UVRS_DEFAULT_WEIGHTS };
    this.thresholds = thresholds ? { ...thresholds } : { ...RISK_THRESHOLDS };
    this._validate_weights();
  }

  /**
   * 验证并自动归一化权重
   *
   * 规则：
   *  - 仅对权重 > 0 的项求和
   *  - 若总和与 1.0 偏差 > 0.01，则归一化
   */
  private _validate_weights(): void {
    const total = Object.values(this.weights).reduce(
      (acc, w) => (w > 0 ? acc + w : acc),
      0,
    );
    if (Math.abs(total - 1.0) > 0.01 && total > 0) {
      for (const k of Object.keys(this.weights)) {
        if (this.weights[k] > 0) {
          this.weights[k] = this.weights[k] / total;
        }
      }
    }
  }

  /**
   * Sigmoid 归一化 (防止溢出)
   */
  private _sigmoid(x: number): number {
    return sigmoid(x);
  }

  /**
   * 计算统一风险评分
   *
   * @param components 各维度的风险分量 (缺失项用 UVRS_DIMENSION_DEFAULTS 填充)
   * @returns 归一化到 [0, 1] 的 UVRS 评分
   */
  compute(components: DimensionComponents): number {
    let weightedSum = 0.0;
    for (const [dim, weight] of Object.entries(this.weights)) {
      if (weight > 0) {
        const value =
          components[dim] !== undefined
            ? components[dim]
            : (UVRS_DIMENSION_DEFAULTS[dim] ?? 0.0);
        weightedSum += weight * value;
      }
    }
    return this._sigmoid(weightedSum);
  }

  /**
   * 批量计算 UVRS
   *
   * @param components_list 多个 components
   * @returns 评分列表
   */
  compute_batch(components_list: DimensionComponents[]): number[] {
    return components_list.map((c) => this.compute(c));
  }

  /**
   * 将评分映射到风险等级
   *
   * @param score UVRS 评分 (0-1)
   * @returns 风险等级
   */
  classify(score: number): RiskLevel {
    // 按阈值从高到低检查
    const order: RiskLevel[] = [
      RiskLevel.CRITICAL,
      RiskLevel.HIGH,
      RiskLevel.MEDIUM,
      RiskLevel.LOW,
    ];
    for (const level of order) {
      if (score >= this.thresholds[level]) {
        return level;
      }
    }
    return RiskLevel.LOW;
  }

  /**
   * 批量分类
   *
   * @param scores 评分列表
   * @returns 风险等级列表
   */
  classify_batch(scores: number[]): RiskLevel[] {
    return scores.map((s) => this.classify(s));
  }

  /**
   * 返回风险最高的 k 个节点
   *
   * @param node_scores {node: score}
   * @param k 返回数量 (默认 10)
   * @returns [node, score, level] 三元组列表
   */
  top_risks(
    node_scores: Record<string, number>,
    k: number = 10,
  ): Array<[string, number, RiskLevel]> {
    const sorted = Object.entries(node_scores).sort(
      (a, b) => b[1] - a[1],
    );
    return sorted
      .slice(0, k)
      .map(
        ([node, score]) => [node, score, this.classify(score)] as [string, number, RiskLevel],
      );
  }

  /**
   * 分析各维度对最终评分的贡献度 (百分比)
   *
   * @param components 各维度风险分量
   * @returns {dim: contribution_ratio} (总和归一化到 1)
   */
  contribution_analysis(components: DimensionComponents): Record<string, number> {
    const contribs: Record<string, number> = {};
    let total = 0.0;

    for (const [dim, weight] of Object.entries(this.weights)) {
      if (weight > 0) {
        const value = components[dim] ?? 0.0;
        const c = weight * value;
        contribs[dim] = c;
        total += c;
      }
    }

    if (total > 0) {
      for (const dim of Object.keys(contribs)) {
        contribs[dim] = contribs[dim] / total;
      }
    }

    return contribs;
  }

  /**
   * 找出贡献最大的维度
   *
   * @param components 各维度风险分量
   * @returns [dimension_name, contribution_ratio]
   */
  dominant_dimension(components: DimensionComponents): [string, number] {
    const contribs = this.contribution_analysis(components);
    const entries = Object.entries(contribs);
    if (entries.length === 0) {
      return ['unknown', 0.0];
    }
    return entries.reduce((best, cur) => (cur[1] > best[1] ? cur : best));
  }

  /**
   * 更新权重 (贝叶斯更新后调用)
   *
   * @param new_weights 新权重的部分覆盖
   */
  update_weights(new_weights: Record<string, number>): void {
    for (const [k, v] of Object.entries(new_weights)) {
      this.weights[k] = v;
    }
    this._validate_weights();
  }

  /**
   * 获取一组评分的风险等级分布
   *
   * @param scores 评分列表
   * @returns {LOW: n, MEDIUM: n, HIGH: n, CRITICAL: n}
   */
  get_risk_distribution(scores: number[]): Record<string, number> {
    const dist: Record<string, number> = {
      [RiskLevel.LOW]: 0,
      [RiskLevel.MEDIUM]: 0,
      [RiskLevel.HIGH]: 0,
      [RiskLevel.CRITICAL]: 0,
    };
    for (const s of scores) {
      const level = this.classify(s);
      dist[level] += 1;
    }
    return dist;
  }

  /**
   * 计算评分列表的统计信息
   *
   * @param scores 评分列表
   * @returns 包含 mean/median/std/min/max/q25/q75/high_risk_ratio/critical_ratio 的统计对象
   */
  compute_statistics(scores: number[]): UVRSStatistics {
    if (scores.length === 0) {
      return {
        mean: 0,
        median: 0,
        std: 0,
        min: 0,
        max: 0,
        q25: 0,
        q75: 0,
        high_risk_ratio: 0,
        critical_ratio: 0,
      };
    }
    const m = mean(scores);
    const med = median(scores);
    const sd = stddev(scores);
    const min = Math.min(...scores);
    const max = Math.max(...scores);
    const q25 = percentile(scores, 25);
    const q75 = percentile(scores, 75);
    const highRiskRatio = scores.filter((s) => s >= 0.5).length / scores.length;
    const criticalRatio = scores.filter((s) => s >= 0.75).length / scores.length;

    return {
      mean: m,
      median: med,
      std: sd,
      min,
      max,
      q25,
      q75,
      high_risk_ratio: highRiskRatio,
      critical_ratio: criticalRatio,
    };
  }

  /**
   * 导出当前配置 (权重 + 阈值)
   *
   * 阈值以字符串键序列化 (如 "CRITICAL": 0.85)，便于 JSON 持久化
   */
  export_config(): UVRSConfigExport {
    const thresholds: Record<string, number> = {};
    for (const level of Object.values(RiskLevel)) {
      thresholds[level] = this.thresholds[level];
    }
    return {
      weights: { ...this.weights },
      thresholds,
    };
  }

  /**
   * 从配置创建新的 UVRS 实例
   *
   * @param config 包含 weights 和 thresholds 的对象
   * @returns 新的 UVRS 实例
   */
  static from_config(config: UVRSConfigExport): UVRSCalculator {
    const thresholds: Record<RiskLevel, number> = { ...RISK_THRESHOLDS };
    if (config.thresholds) {
      for (const level of Object.values(RiskLevel)) {
        const v = config.thresholds[level];
        if (typeof v === 'number') {
          thresholds[level] = v;
        }
      }
    }
    return new UVRSCalculator(config.weights ?? {}, thresholds);
  }
}

// ============================================================================
// 第六部分：默认导出
// ============================================================================

// ============================================================================
// 第七部分：v2.4 集成层 — 供 cosm-x-project-analyzer.ts 使用
// ============================================================================

/**
 * UVRS 评分结果 (含 23 维明细)
 *
 * 与 UVRSCalculator (计算器) 配套使用 — UVRSCalculator 计算纯分数，
 * UVRS 是带维度明细的结果对象，供上层 (CLI/dashboard/JSON 导出) 使用。
 */
export interface UVRS {
  /** 归一化的统一风险评分, 范围 [0, 1] */
  unified_score: number;
  /** 风险等级 */
  risk_level: RiskLevel;
  /** Top 风险维度 ID 列表 (按贡献度降序) */
  top_risk_dimensions: number[];
  /** Top 风险维度名称列表 */
  top_risk_dimension_names: string[];
  /** 维度名 → 该维度贡献度 (0-1, 总和 = 1) */
  dimension_contributions: Record<string, number>;
  /** 维度名 → 该维度原始得分 (0-1) */
  dimension_scores: Record<string, number>;
  /** 维度 ID → 名称的映射 (供展示) */
  dimension_names: Record<number, string>;
  /** 维度 ID → 贡献度的映射 (供展示) */
  dimension_contributions_by_id: Record<number, number>;
  /** 元数据 */
  metadata: {
    engine_version: string;
    computed_at: number;
    enabled_dimensions: number[];
    total_vulnerabilities?: number;
  };
}

/**
 * GraphData 别名 (与 v2.4 集成层命名一致)
 */
export type GraphData23D = GraphData;

/**
 * 将 6 维 cosm-x-galaxy 数据 (CPG/lagrange/orbital/anomaly/perturbation)
 * 转换为 23 维 GraphData 输入
 *
 * @param cpg Code Property Graph (供 PageRank/betweenness 等基础指标提取)
 * @param sixDim 6 维宇宙星系法结果
 * @returns 23 维 GraphData
 */
export function buildGraphData23D(
  cpg: unknown,
  sixDim: {
    orbitalElements?: Map<string, unknown> | Record<string, unknown>;
    lagrangePoints?: Array<{ stability?: string }> | unknown;
    anomalies?: Array<unknown>;
    perturbations?: Array<{ magnitude?: number }> | unknown;
    vulnerabilityScore?: number;
    // v2.5.1: 用于生成 per-node 评分变体
    severity?: string;
    nodeId?: string;
  },
): GraphData23D {
  // v2.5.1: severity → 数值锚点, 不同级别产生不同 UVRS
  // v3.0: 加入 file+line+type 哈希, 每条 finding 产生唯一 per-node 数据
  const SEVERITY_ANCHOR: Record<string, number> = {
    critical: 0.95,
    high: 0.75,
    medium: 0.55,
    low: 0.30,
    info: 0.10,
  };
  const severityScore = SEVERITY_ANCHOR[(sixDim.severity ?? '').toLowerCase()] ?? 0.5;
  const nodeId = sixDim.nodeId ?? '_project_avg';

  // v3.0: 提取 vulnType (从 nodeId 拆出: "file:line:type" → 最后一段为 type)
  const vulnType = nodeId.includes(':') && nodeId.includes('.') === false
    ? nodeId.split(':').pop() ?? 'unknown'
    : (nodeId.split('_').pop() ?? 'unknown');

  // v3.0: file+line 哈希变体 (0-1 范围, 确定性但唯一)
  // 用 DJB2 哈希, 让每条 finding 有不同的 per-node 变体
  const fileLineHash = (() => {
    if (!sixDim.nodeId) return 0.5;
    let hash = 5381;
    for (let i = 0; i < sixDim.nodeId.length; i++) {
      hash = ((hash << 5) + hash + sixDim.nodeId.charCodeAt(i)) & 0x7fffffff;
    }
    return (hash % 10000) / 10000;  // 0.0000 - 0.9999
  })();

  // v3.0: type 加权 (sqli/xss/rce 比 path/info 风险高)
  const TYPE_RISK: Record<string, number> = {
    sql_injection: 0.9,
    sqli: 0.9,
    command_injection: 0.95,
    code_injection: 0.95,
    xss: 0.7,
    rce: 0.9,
    path_traversal: 0.6,
    deserialization: 0.85,
    xxe: 0.8,
    idor: 0.65,
    ssti: 0.85,
    broken_access_control: 0.8,
    insecure_design: 0.5,
    open_redirect: 0.4,
    security_logging_failures: 0.3,
    vulnerable_components: 0.7,
  };
  const typeRisk = TYPE_RISK[vulnType] ?? 0.5;

  // v3.0: line 编号 → 距离变体 (同一文件不同行有不同风险梯度)
  const lineMatch = sixDim.nodeId?.match(/:(\d+)$/);
  const lineNum = lineMatch ? parseInt(lineMatch[1], 10) : 0;
  const lineVariant = (lineNum % 100) / 100;  // 0.00 - 0.99

  const graph: GraphData23D = {
    sinks: [],
    shortest_paths: {},
    in_degree: {},
    out_degree: {},
    cyclomatic_complexity: {},
    cycles: {},
    isolated_nodes: {},
    architectural_smells: {},
    input_params: {},
    output_vals: {},
    side_effects: {},
    pagerank: {},
    betweenness: {},
  };

  // 提取 6 维 lagrange points 作为 sinks (拉格朗日点 = 汇点)
  if (Array.isArray(sixDim.lagrangePoints)) {
    graph.sinks = (sixDim.lagrangePoints as Array<{ id?: string }>)
      .map((lp, i) => lp.id ?? `lagrange_${i}`);
  }

  // 提取 anomalies 作为 architectural_smells
  if (Array.isArray(sixDim.anomalies)) {
    for (let i = 0; i < sixDim.anomalies.length; i++) {
      const a = sixDim.anomalies[i] as { nodeId?: string; score?: number } | undefined;
      const nodeId = a?.nodeId ?? `anomaly_${i}`;
      graph.architectural_smells![nodeId] = a?.score ?? 1;
      graph.cyclomatic_complexity![nodeId] = (a?.score ?? 1) * 5;
    }
  }

  // 提取 perturbations 作为边权重
  if (Array.isArray(sixDim.perturbations)) {
    sixDim.perturbations.forEach((p, i) => {
      const pert = p as { from?: string; to?: string; magnitude?: number };
      if (pert.from) graph.in_degree![pert.from] = pert.magnitude ?? 1;
      if (pert.to) graph.out_degree![pert.to] = pert.magnitude ?? 1;
    });
  }

  // vulnerabilityScore 作为全局 PageRank 锚点
  if (typeof sixDim.vulnerabilityScore === 'number') {
    graph.pagerank!['_project_avg'] = sixDim.vulnerabilityScore / 100;
    graph.betweenness!['_project_avg'] = sixDim.vulnerabilityScore / 100;
  }

  // v2.5.1: 为具体 finding 节点写入 per-node 数据
  // v3.0: 用 severity (锚点) + fileLineHash (变体) + typeRisk (类型) + lineVariant (行号) 组合
  if (nodeId !== '_project_avg') {
    const baseRisk = (sixDim.vulnerabilityScore ?? 0) / 100;

    // pagerank: 30% 基线 + 50% severity + 15% type + 5% hash
    graph.pagerank![nodeId] = Math.min(1,
      baseRisk * 0.30 + severityScore * 0.50 + typeRisk * 0.15 + fileLineHash * 0.05);

    // betweenness: 50% 基线 + 30% severity + 15% type + 5% hash
    graph.betweenness![nodeId] = Math.min(1,
      baseRisk * 0.50 + severityScore * 0.30 + typeRisk * 0.15 + fileLineHash * 0.05);

    // 复杂度维度: severity × type × line
    graph.cyclomatic_complexity![nodeId] = Math.max(1,
      (severityScore * typeRisk + lineVariant * 0.3) * 20);

    // 拓扑缺陷: high severity + 复杂类型 → 容易形成 cycle
    graph.cycles![nodeId] = severityScore * typeRisk > 0.5;

    // architectural_smells: severity + type + 行号变体
    graph.architectural_smells![nodeId] =
      severityScore * typeRisk * 4 + fileLineHash + lineVariant * 0.5;

    // chaos 维度: severity 越高输入参数越多
    graph.input_params![nodeId] = severityScore * typeRisk * 3 + fileLineHash;
    graph.output_vals![nodeId] = severityScore * typeRisk * 2 + lineVariant;
    graph.side_effects![nodeId] = severityScore * typeRisk;

    // entropy 维度: 设 in/out degree 让 (in+out)*cyclo 有效
    graph.in_degree![nodeId] = severityScore * 2 + typeRisk;
    graph.out_degree![nodeId] = severityScore * 1 + fileLineHash;

    // v3.0: 增加 isolated_nodes (低 hash → 孤立节点概率高)
    graph.isolated_nodes![nodeId] = fileLineHash < 0.05;

    // v3.0: 设置 shortest_paths 到 sinks (用 distance 反映行号距离)
    if (graph.sinks && graph.sinks.length > 0) {
      const dist = Math.max(1, lineNum) / 100;  // 行号越远, 距离越大
      if (!graph.shortest_paths![nodeId]) graph.shortest_paths![nodeId] = {};
      graph.shortest_paths![nodeId][graph.sinks[0]] = dist;
    }
  }

  // 如果有 CPG, 提取 nodes/edges 补全
  if (cpg && typeof cpg === 'object') {
    const cpgObj = cpg as { nodes?: Array<{ id: string; type?: string }>; edges?: Array<{ from: string; to: string }> };
    if (Array.isArray(cpgObj.nodes)) {
      for (const node of cpgObj.nodes) {
        if (!graph.pagerank![node.id]) graph.pagerank![node.id] = 0.01;
        if (!graph.in_degree![node.id]) graph.in_degree![node.id] = 0;
        if (!graph.out_degree![node.id]) graph.out_degree![node.id] = 0;
      }
    }
  }

  return graph;
}

// 修改 CosmicTheoryEngine 添加 v2.4 集成方法
declare module './cosm-x-theory-23d.js' {
  // module augmentation 已通过类内方法实现, 此处仅作类型提示
}

// 在 CosmicTheoryEngine 类外附加方法 (通过原型扩展, 保持类本体不变)
// 实际方法在下面通过 Object.assign 注入到原型上

/**
 * 计算项目级 UVRS (从多个漏洞级 UVRS 汇总)
 *  - 取所有 UVRS 的 unified_score 平均值
 *  - 风险等级取最高
 *  - 维度贡献度按权重平均
 */
export function calculateProjectUVRS(perVulnUVRS: UVRS[]): UVRS {
  if (perVulnUVRS.length === 0) {
    return {
      unified_score: 0,
      risk_level: RiskLevel.LOW,
      top_risk_dimensions: [],
      top_risk_dimension_names: [],
      dimension_contributions: {},
      dimension_scores: {},
      dimension_names: {},
      dimension_contributions_by_id: {},
      metadata: {
        engine_version: '7.5',
        computed_at: Date.now(),
        enabled_dimensions: THEORY_DEFINITIONS.map(d => d.dim_id),
        total_vulnerabilities: 0,
      },
    };
  }

  // 平均 unified_score
  const avgScore = perVulnUVRS.reduce((s, u) => s + u.unified_score, 0) / perVulnUVRS.length;

  // 最高风险等级
  const levelOrder: Record<RiskLevel, number> = {
    [RiskLevel.LOW]: 0,
    [RiskLevel.MEDIUM]: 1,
    [RiskLevel.HIGH]: 2,
    [RiskLevel.CRITICAL]: 3,
  };
  const worstLevel = perVulnUVRS.reduce<RiskLevel>((worst, u) => {
    return levelOrder[u.risk_level] > levelOrder[worst] ? u.risk_level : worst;
  }, RiskLevel.LOW);

  // 维度贡献度与得分平均
  const allDims = new Set<string>();
  perVulnUVRS.forEach(u => {
    Object.keys(u.dimension_contributions).forEach(k => allDims.add(k));
    Object.keys(u.dimension_scores).forEach(k => allDims.add(k));
  });

  const dimContrib: Record<string, number> = {};
  const dimScore: Record<string, number> = {};
  for (const d of allDims) {
    const contribs = perVulnUVRS.map(u => u.dimension_contributions[d] ?? 0);
    const scores = perVulnUVRS.map(u => u.dimension_scores[d] ?? 0);
    dimContrib[d] = contribs.reduce((s, v) => s + v, 0) / perVulnUVRS.length;
    dimScore[d] = scores.reduce((s, v) => s + v, 0) / perVulnUVRS.length;
  }

  // 排序维度
  const sortedByContrib = Object.entries(dimContrib)
    .sort((a, b) => b[1] - a[1])
    .map(([name]) => name);

  const dimNames: Record<number, string> = {};
  for (const d of THEORY_DEFINITIONS) dimNames[d.dim_id] = d.name;

  const dimIdMap: Record<number, number> = {};
  for (const d of THEORY_DEFINITIONS) {
    const name = d.name;
    if (name in dimContrib) dimIdMap[d.dim_id] = dimContrib[name] ?? 0;
  }

  return {
    unified_score: avgScore,
    risk_level: worstLevel,
    top_risk_dimensions: sortedByContrib
      .map(name => THEORY_DEFINITIONS.find(d => d.name === name)?.dim_id)
      .filter((x): x is number => typeof x === 'number'),
    top_risk_dimension_names: sortedByContrib,
    dimension_contributions: dimContrib,
    dimension_scores: dimScore,
    dimension_names: dimNames,
    dimension_contributions_by_id: dimIdMap,
    metadata: {
      engine_version: '7.5',
      computed_at: Date.now(),
      enabled_dimensions: THEORY_DEFINITIONS.map(d => d.dim_id),
      total_vulnerabilities: perVulnUVRS.length,
    },
  };
}

// 将 calculate_unified_risk_score 增强为返回 UVRS (而不仅返回 [score, results])
// 原 Python 版返回 (score, results[]), 集成层需要更丰富的 UVRS 对象
// 这里通过扩展 CosmicTheoryEngine 的方法实现

// 重写 CosmicTheoryEngine 的关键方法
const _originalCalculateUnified = CosmicTheoryEngine.prototype.calculate_unified_risk_score;
CosmicTheoryEngine.prototype.calculate_unified_risk_score = function (
  this: CosmicTheoryEngine,
  graph_data: GraphData,
  node: string,
): UVRS {
  const dimResults = this.calculate_all_dimensions(graph_data, node);
  // v2.5.1: 用 max-dim-contribution 归一化, 让变化维度(severity)直接可见
  // 旧公式 sigmoid(total*10-5) 在 22 高 dim 压死变化
  // 新公式: max(contribution) / theoretical_max → 0-1 范围
  const contributions = dimResults.map(r => r.contribution);
  let maxContrib = 0;
  if (contributions.length > 0) {
    maxContrib = Math.max(...contributions);
  }
  // theoretical max contribution = max weight (≈ 0.13 for 万有引力场) * 1.0 score
  // 用 THEORY_DEFINITIONS 中最大权重归一化
  const maxWeight = Math.max(...THEORY_DEFINITIONS.map(d => d.weight), 0.1);
  const normalized = Math.min(1.0, maxContrib / maxWeight);

  const calculator = new UVRSCalculator();
  const riskLevel = calculator.classify(normalized);

  const dimContrib: Record<string, number> = {};
  const dimScore: Record<string, number> = {};
  const dimContribById: Record<number, number> = {};
  for (const r of dimResults) {
    const def = THEORY_DEFINITIONS.find(d => d.dim_id === r.dim_id);
    const name = def?.name ?? `dim_${r.dim_id}`;
    dimContrib[name] = r.contribution;
    dimScore[name] = r.score;
    dimContribById[r.dim_id] = r.contribution;
  }

  const dimNames: Record<number, string> = {};
  for (const d of THEORY_DEFINITIONS) dimNames[d.dim_id] = d.name;

  const sortedByContrib = Object.entries(dimContrib)
    .sort((a, b) => b[1] - a[1])
    .map(([name]) => name);

  // 引用原方法避免未使用警告
  void _originalCalculateUnified;

  return {
    unified_score: normalized,
    risk_level: riskLevel,
    top_risk_dimensions: sortedByContrib
      .map(name => THEORY_DEFINITIONS.find(d => d.name === name)?.dim_id)
      .filter((x): x is number => typeof x === 'number'),
    top_risk_dimension_names: sortedByContrib,
    dimension_contributions: dimContrib,
    dimension_scores: dimScore,
    dimension_names: dimNames,
    dimension_contributions_by_id: dimContribById,
    metadata: {
      engine_version: '7.5',
      computed_at: Date.now(),
      enabled_dimensions: THEORY_DEFINITIONS.map(d => d.dim_id),
    },
  };
};

// 将 calculateProjectUVRS 挂到 CosmicTheoryEngine 实例方法
(CosmicTheoryEngine.prototype as { calculateProjectUVRS?: typeof calculateProjectUVRS }).calculateProjectUVRS = calculateProjectUVRS;

/**
 * 命名导出汇总 (便于 import * as Theory from '...' 用法)
 */
export default {
  TheoryDimension,
  RiskLevel,
  THEORY_DEFINITIONS,
  RISK_THRESHOLDS,
  UVRS_DEFAULT_WEIGHTS,
  UVRS_DIMENSION_DEFAULTS,
  CosmicTheoryEngine,
  UVRSCalculator,
  buildGraphData23D,
  calculateProjectUVRS,
};
