/**
 * application/calibration.ts — GA 校准 (v3 扩展基因空间)
 *
 * v3.0 重新设计后, 修复 #3 优先级:
 *  旧: GA 只优化 minScore (6 维), 找到 minScore=52.52 过滤掉全部 (过拟合)
 *  新: GA 优化 12 维基因空间, 含 dedup 策略 + 规则权重 + 信号开关
 *
 * 实现说明: 本文件提供 GAGeneSpace 类型 + DEFAULT_GAGENE_SPACE + 几个
 *   fitness helpers. 实际 GA 循环在 src/evolution/ (项目历史原因保留在那里,
 *   本文件作为 v3 schema 注入).
 *
 * 抽象层次: L3 漏洞挖掘 + L4 验证闭环
 *
 * @see docs/REDESIGN.md §4.3
 */

/**
 * 12 维 GA 基因空间
 *
 * 索引:
 *  0  min_score         阈值 (0-100)
 *  1  dedup_strategy    0=none, 1=file-type, 2=file-line-type
 *  2  w_sqli            SQL 注入规则权重 (0-2)
 *  3  w_xss             XSS 规则权重 (0-2)
 *  4  w_rce             远程代码执行规则权重 (0-2)
 *  5  w_path            路径遍历规则权重 (0-2)
 *  6  w_auth            认证/凭证规则权重 (0-2)
 *  7  use_kepler        开普勒信号开关 (0/1)
 *  8  use_entropy       熵信号开关 (0/1)
 *  9  use_tda           拓扑数据分析开关 (0/1)
 *  10 use_chaos         混沌信号开关 (0/1)
 *  11 use_gravitational 万有引力信号开关 (0/1)
 */
export interface GAGeneSpace {
  min_score: number;
  dedup_strategy: 'none' | 'file-type' | 'file-line-type';
  rule_weights: {
    sqli: number;
    xss: number;
    rce: number;
    path: number;
    auth: number;
  };
  signal_switches: {
    use_kepler: boolean;
    use_entropy: boolean;
    use_tda: boolean;
    use_chaos: boolean;
    use_gravitational: boolean;
  };
}

/**
 * v3 默认基因 (v2.5.2 收敛点 + 全面打开信号)
 *
 * min_score: 0 (旧 GA 找到 52.52 实际过滤掉全部, v3 用 0 + 后续规则权重 + 信号过滤)
 * dedup: file-type (与 v2.5.2 一致)
 * 规则权重: 默认 1.0 (中性)
 * 信号开关: 全部 true
 */
export const DEFAULT_GAGENE_SPACE: GAGeneSpace = {
  min_score: 0,
  dedup_strategy: 'file-type',
  rule_weights: {
    sqli: 1.0,
    xss: 1.0,
    rce: 1.0,
    path: 1.0,
    auth: 1.0,
  },
  signal_switches: {
    use_kepler: true,
    use_entropy: true,
    use_tda: true,
    use_chaos: true,
    use_gravitational: true,
  },
};

/**
 * 12 维基因向量 (用于遗传算法)
 *
 * 对应 GAGeneSpace 字段顺序:
 *  [0]  min_score
 *  [1]  dedup_strategy (0/1/2)
 *  [2-6] rule_weights (5 个)
 *  [7-11] signal_switches (0/1 × 5)
 */
export type GAGeneVector = [
  number,  // 0: min_score
  number,  // 1: dedup_strategy (0/1/2)
  number,  // 2: w_sqli
  number,  // 3: w_xss
  number,  // 4: w_rce
  number,  // 5: w_path
  number,  // 6: w_auth
  number,  // 7: use_kepler
  number,  // 8: use_entropy
  number,  // 9: use_tda
  number,  // 10: use_chaos
  number,  // 11: use_gravitational
];

/**
 * 向量 → GAGeneSpace 解码
 */
export function decodeGAGene(vec: GAGeneVector): GAGeneSpace {
  return {
    min_score: vec[0],
    dedup_strategy: (['none', 'file-type', 'file-line-type'][Math.round(vec[1])] ?? 'file-type') as
      | 'none'
      | 'file-type'
      | 'file-line-type',
    rule_weights: {
      sqli: vec[2],
      xss: vec[3],
      rce: vec[4],
      path: vec[5],
      auth: vec[6],
    },
    signal_switches: {
      use_kepler: vec[7] > 0.5,
      use_entropy: vec[8] > 0.5,
      use_tda: vec[9] > 0.5,
      use_chaos: vec[10] > 0.5,
      use_gravitational: vec[11] > 0.5,
    },
  };
}

/**
 * 默认 12 维基因向量
 */
export const DEFAULT_GAGENE_VECTOR: GAGeneVector = [
  0,    // min_score
  1,    // dedup: file-type
  1.0,  // w_sqli
  1.0,  // w_xss
  1.0,  // w_rce
  1.0,  // w_path
  1.0,  // w_auth
  1,    // use_kepler
  1,    // use_entropy
  1,    // use_tda
  1,    // use_chaos
  1,    // use_gravitational
];

/**
 * v3 新增: 把 gene space 应用到 findings (filter + weight)
 *
 * 输入: 漏洞报告 + 基因
 * 输出: 过滤 + 加权后的报告
 */
export function applyGAGene<T extends { file: string; line: number; type: string; severity: 'critical' | 'high' | 'medium' | 'low'; score: number }>(
  reports: T[],
  gene: GAGeneSpace,
): T[] {
  // 1. min_score 过滤
  let filtered = reports.filter((r) => r.score >= gene.min_score);

  // 2. dedup
  if (gene.dedup_strategy === 'file-type') {
    const seen = new Set<string>();
    filtered = filtered.filter((r) => {
      const k = `${r.file}::${r.type}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  } else if (gene.dedup_strategy === 'file-line-type') {
    const seen = new Set<string>();
    filtered = filtered.filter((r) => {
      const k = `${r.file}::${r.line}::${r.type}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  // 3. 规则权重 (调整 score)
  const TYPE_TO_WEIGHT: Record<string, keyof GAGeneSpace['rule_weights']> = {
    sql_injection: 'sqli',
    sqli: 'sqli',
    xss: 'xss',
    command_injection: 'rce',
    rce: 'rce',
    code_injection: 'rce',
    path_traversal: 'path',
    broken_access_control: 'auth',
    insecure_design: 'auth',
  };
  return filtered.map((r) => {
    const wKey = TYPE_TO_WEIGHT[r.type];
    if (!wKey) return r;
    const w = gene.rule_weights[wKey];
    return { ...r, score: r.score * w };
  });
}
