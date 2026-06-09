/**
 * 宇宙星系法 - CosmX Galaxy Method for White-Box Vulnerability Mining
 * ================================================================
 * 基于天体物理学/轨道力学的代码漏洞挖掘新范式
 * 
 * 核心映射 (Astrophysics → Code Analysis):
 * -------------------------------------------
 * 宇宙概念              数学方法                   代码分析映射
 * ─────────────────────────────────────────────────────────────
 * 地球 (anchor)       参考系/基准点            被分析的目标函数
 * 星球/恒星            代码实体 (函数/变量)      CFG/DFG 节点
 * 相对距离              轨道距离 (km)              控制流/数据流距离
 * 轨道/轨迹            轨道根数 (a,e,i,Ω,ω,ν)   执行路径/分支/循环
 * 速度/线速度          轨道速度 (km/s)            数据流变化率
 * 轨道周期              T = 2π√(a³/GM)            圈复杂度/循环次数
 * 自转                  自转角动量                局部循环/递归分析
 * 公转                  绕质心的轨道运动          函数调用层次深度
 * 引力/摄动            N体引力 F=GMm/r²           依赖链扰动分析
 * 开普勒定律            Kepler orbital mechanics  代码模式涌现
 * 拉格朗日点           L1-L5 平衡点               CFG汇合点/关键节点
 * 转移轨道              Lambert solver            污点传播路径 (source→sink)
 * 晕轨道                Halo/Lissajous orbit      递归代码的边界振荡
 * 
 * 算法来源 (GitHub Research):
 * ─────────────────────────────────────────────────────────────
 * 【轨道力学】Kepler方程、兰伯特求解器、N体引力
 *   → 映射: 数据流轨道、污点转移、脱靶检测
 *   
 * 【引力模拟】Barnes-Hut树 O(NlogN)、快速多极子
 *   → 映射: 大规模依赖图的层次化分析
 *   
 * 【定位导航】TDOA时差定位、三边测量、扩展卡尔曼滤波
 *   → 映射: 污点源定位、多路径汇合检测、状态估计
 *   
 * 【轨道异常】Z-score/Mahalanobis距离/隔离森林
 *   → 映射: 代码异常模式检测、漏洞评分
 *   
 * 【轨道摄动】微分修正、蒙卡传播、J2摄动
 *   → 映射: 约束条件下的漏洞分析迭代精化
 *   
 * 【光谱分析】FFT周期检测、小波分析
 *   → 映射: 代码中的周期性漏洞模式
 */

import { CPGBuilder, type CodePropertyGraph, type CPGNode, type CPGEdge } from './execution/cpg.js';

/**
 * 第一部分：轨道根数 (Orbital Elements) 
 * 用于描述代码实体的"轨道"属性
 */
export interface OrbitalElements {
  semiMajorAxis: number;      // 半长轴 a → 代码复杂度/嵌套深度
  eccentricity: number;       // 离心率 e → 执行路径偏差度
  inclination: number;        // 倾角 i → 控制流分支角度
  raan: number;               // 升交点赤经 Ω → 代码入口路径
  argPeriapsis: number;       // 近心点幅角 ω → 关键条件判断
  trueAnomaly: number;        // 真近点角 ν → 当前执行位置
  period: number;             // 轨道周期 T → 循环迭代次数
  meanMotion: number;         // 平近点角变化率 → 执行频率
}

/**
 * 第二部分：轨道传播器 (Orbital Propagator)
 * 基于Kepler方程计算代码实体的"轨道位置"
 * 公式: M = E - e*sin(E)  (Kepler方程)
 * 映射: mean_anomaly → 执行进度, eccentric_anomaly → 路径深度
 */

// Kepler方程求解 (使用牛顿迭代)
export function solveKeplerEquation(M: number, e: number, tolerance: number = 1e-12): number {
  M = M % (2 * Math.PI);
  if (M < 0) M += 2 * Math.PI;
  
  let E = M; // 初始猜测: 椭圆轨道 E ≈ M
  if (e > 0.8) E = Math.PI; // 高离心率使用不同初始值
  
  for (let i = 0; i < 100; i++) {
    const dE = (E - e * Math.sin(E) - M) / (1 - e * Math.cos(E));
    E -= dE;
    if (Math.abs(dE) < tolerance) break;
  }
  return E;
}

// 从轨道根数计算位置向量 (轨道坐标系→惯性坐标系)
export function elementsToPosition(
  elements: OrbitalElements,
  GM: number = 1.0 // 标准化引力常数
): { x: number; y: number; z: number } {
  const { semiMajorAxis: a, eccentricity: e, inclination: i, raan: Ω, argPeriapsis: ω, trueAnomaly: ν } = elements;
  
  // 真近点角→轨道平面位置
  const r = a * (1 - e * e) / (1 + e * Math.cos(ν)); // 轨道距离
  const xOrbital = r * Math.cos(ν);
  const yOrbital = r * Math.sin(ν);
  
  // 轨道坐标系→惯性坐标系 (3-1-3欧拉角旋转)
  const cosΩ = Math.cos(Ω), sinΩ = Math.sin(Ω);
  const cosi = Math.cos(i), sini = Math.sin(i);
  const cosω = Math.cos(ω), sinω = Math.sin(ω);
  const cosν = Math.cos(ν), sinν = Math.sin(ν);
  
  // 旋转矩阵元素
  const r11 = cosω*cosΩ - sinω*sinΩ*cosi;
  const r12 = -sinω*cosΩ - cosω*sinΩ*cosi;
  const r21 = cosω*sinΩ + sinω*cosΩ*cosi;
  const r22 = -sinω*sinΩ + cosω*cosΩ*cosi;
  const r31 = sinω*sini;
  const r32 = cosω*sini;
  
  return {
    x: r11*xOrbital + r12*yOrbital,
    y: r21*xOrbital + r22*yOrbital,
    z: r31*xOrbital + r32*yOrbital
  };
}

// Kepler时间方程: 从平近点角计算真近点角
export function meanToTrueAnomaly(M: number, e: number): number {
  const E = solveKeplerEquation(M, e);
  // 从偏近点角转换为真近点角
  // tan(ν/2) = sqrt((1+e)/(1-e)) * tan(E/2)
  const tanHalfE = Math.tan(E / 2);
  const k = Math.sqrt((1 + e) / (1 - e));
  return 2 * Math.atan(k * tanHalfE);
}

/**
 * 第三部分：Lambert转移轨道求解器
 * ================================================================
 * 兰伯特问题: 已知起点P1、终点P2、时间Δt，求解轨道转移
 * 
 * GitHub参考: Siderust/keplerian (⭐2), Curtis & Sabo's Lambert solvers
 * 
 * 映射到代码分析:
 *   - P1 (source) → 污点源节点 (用户输入点)
 *   - P2 (sink) → 危险汇点节点 (漏洞触发点)
 *   - Δt (transfer time) → 数据流传播所需的条件数/路径长度
 *   - 转移轨道 → 污点传播路径
 */
export interface LambertSolution {
  transferTime: number;           // 转移时间
  semiMajorAxis: number;         // 转移轨道半长轴
  eccentricity: number;          // 转移轨道离心率
  timeOfFlight: number;           // 飞行时间 (TOF)
  isRetrograde: boolean;         // 是否逆行
  type: 'elliptic' | 'parabolic' | 'hyperbolic'; // 轨道类型
  deltaV: number;                // 速度增量 (能量消耗)
}

// Lambert求解器主函数
export function solveLambertProblem(
  r1: { x: number; y: number; z: number },
  r2: { x: number; y: number; z: number },
  dt: number,                    // 转移时间
  GM: number = 1.0,
  isRetrograde: boolean = false
): LambertSolution | null {
  // 计算弦长 (chord) 和半弦长 (semi-chord)
  const chord = Math.sqrt((r2.x - r1.x) ** 2 + (r2.y - r1.y) ** 2 + (r2.z - r1.z) ** 2);
  const s = chord / 2; // 半弦长
  
  // 计算转移角 (transfer angle) Δθ
  const cosθ = (r1.x * r2.x + r1.y * r2.y + r1.z * r2.z) / 
               (Math.sqrt(r1.x**2 + r1.y**2 + r1.z**2) * Math.sqrt(r2.x**2 + r2.y**2 + r2.z**2));
  const theta = Math.acos(Math.max(-1, Math.min(1, cosθ)));
  const dtheta = isRetrograde ? 2 * Math.PI - theta : theta;
  
  // 计算每日跳 (mean motion) n = 2π/T
  const aMin = s; // 最小能量转移需要 a >= s
  const n = Math.PI * 2 / Math.sqrt(aMin * aMin * aMin / GM);
  const TOF = dt;
  
  // 简化的Lambert迭代 (使用单圈解)
  const x = 0.5; // 初始猜测
  const a = aMin / (1 - x * x); // 半长轴与x的关系
  
  // 计算飞行时间TOF (使用通用方程)
  const gamma = Math.sqrt(1 - chord * chord / (a * a));
  const y = (gamma * x) - (x > 0 ? gamma : 0) * Math.sqrt(0.5 + 0.5 * x);
  const F = 8 * Math.asin(Math.sqrt(0.5 * (1 + x - gamma))) - 
            Math.sin(2 * Math.asin(Math.sqrt(0.5 * (1 + x - gamma))));
  
  const computedTOF = Math.sqrt(a * a * a / GM) * F;
  
  return {
    transferTime: dt,
    semiMajorAxis: a,
    eccentricity: Math.sqrt(1 - (chord * chord) / (a * a)),
    timeOfFlight: computedTOF,
    isRetrograde,
    type: a > 1e6 ? 'hyperbolic' : a < 1e-6 ? 'parabolic' : 'elliptic',
    deltaV: Math.abs(computedTOF - TOF) // 简化的速度误差
  };
}

/**
 * 第四部分：N体引力模拟 (Barnes-Hut Tree)
 * ================================================================
 * GitHub参考: harrism/mini-nbody (⭐108), beltoforion/Barnes-Hut-Simulator (⭐72)
 * 
 * 算法: O(N log N) 层次化引力求和
 * 树节点: 包含子节点质心位置和总质量
 * 四叉树/八叉树空间划分 + 单极展开 (monopole approx)
 * 
 * 映射到代码分析:
 *   - 质量 m → 代码复杂度/调用频率
 *   - 引力 F=GMm/r² → 依赖关系强度
 *   - 质心位置 → 模块/函数的"引力中心" (核心依赖点)
 *   - 扰动 → 依赖变更导致的级联漏洞传播
 */

interface BHNode {
  id: string;
  centerOfMass: { x: number; y: number; z: number };
  mass: number;
  children: BHNode[];
  bounds: { minX: number; maxX: number; minY: number; maxY: number; minZ: number; maxZ: number };
  totalMass: number;
  isExternal: boolean; // 是否为外部节点 (叶子或质心)
}

// 计算节点质心
function computeCenterOfMass(nodes: BHNode[]): { x: number; y: number; z: number; mass: number } {
  let totalMass = 0;
  let cx = 0, cy = 0, cz = 0;
  
  for (const node of nodes) {
    const m = node.totalMass;
    totalMass += m;
    cx += node.centerOfMass.x * m;
    cy += node.centerOfMass.y * m;
    cz += node.centerOfMass.z * m;
  }
  
  if (totalMass === 0) return { x: 0, y: 0, z: 0, mass: 0 };
  
  return {
    x: cx / totalMass,
    y: cy / totalMass,
    z: cz / totalMass,
    mass: totalMass
  };
}

// Barnes-Hut树构建 (使用四叉树 in 2D for simplicity, extensible to 3D)
export function buildBHTree(
  nodes: Array<{ id: string; position: { x: number; y: number; z: number }; mass: number }>,
  bounds: { minX: number; maxX: number; minY: number; maxY: number; minZ: number; maxZ: number }
): BHNode[] {
  // 构建八叉树
  function buildOctree(
    nodeIds: string[],
    bounds: { minX: number; maxX: number; minY: number; maxY: number; minZ: number; maxZ: number },
    depth: number
  ): BHNode {
    const centerX = (bounds.minX + bounds.maxX) / 2;
    const centerY = (bounds.minY + bounds.maxY) / 2;
    const centerZ = (bounds.minZ + bounds.maxZ) / 2;
    
    if (nodeIds.length <= 1 || depth > 8) {
      // 叶子节点
      const node = nodes.find(n => n.id === nodeIds[0] || nodeIds.length === 0);
      return {
        id: nodeIds[0] || 'empty',
        centerOfMass: node?.position || { x: centerX, y: centerY, z: centerZ },
        mass: node?.mass || 0,
        children: [],
        bounds,
        totalMass: node?.mass || 0,
        isExternal: true
      };
    }
    
    // 划分八个子空间
    const midX = (bounds.minX + bounds.maxX) / 2;
    const midY = (bounds.minY + bounds.maxY) / 2;
    const midZ = (bounds.minZ + bounds.maxZ) / 2;
    
    const children: BHNode[] = [];
    const subBounds = [
      // 8 octants
      { minX: bounds.minX, maxX: midX, minY: bounds.minY, maxY: midY, minZ: bounds.minZ, maxZ: midZ }, // 000
      { minX: midX, maxX: bounds.maxX, minY: bounds.minY, maxY: midY, minZ: bounds.minZ, maxZ: midZ }, // 100
      { minX: bounds.minX, maxX: midX, minY: midY, maxY: bounds.maxY, minZ: bounds.minZ, maxZ: midZ }, // 010
      { minX: midX, maxX: bounds.maxX, minY: midY, maxY: bounds.maxY, minZ: bounds.minZ, maxZ: midZ }, // 110
      { minX: bounds.minX, maxX: midX, minY: bounds.minY, maxY: midY, minZ: midZ, maxZ: bounds.maxZ }, // 001
      { minX: midX, maxX: bounds.maxX, minY: bounds.minY, maxY: midY, minZ: midZ, maxZ: bounds.maxZ }, // 101
      { minX: bounds.minX, maxX: midX, minY: midY, maxY: bounds.maxY, minZ: midZ, maxZ: bounds.maxZ }, // 011
      { minX: midX, maxX: bounds.maxX, minY: midY, maxY: bounds.maxY, minZ: midZ, maxZ: bounds.maxZ }, // 111
    ];
    
    // 分配节点到子空间
    for (let i = 0; i < 8; i++) {
      const childNodeIds = nodeIds.filter(id => {
        const node = nodes.find(n => n.id === id);
        if (!node) return false;
        const { x, y, z } = node.position;
        return x >= subBounds[i].minX && x < subBounds[i].maxX &&
               y >= subBounds[i].minY && y < subBounds[i].maxY &&
               z >= subBounds[i].minZ && z < subBounds[i].maxZ;
      });
      children.push(buildOctree(childNodeIds, subBounds[i], depth + 1));
    }
    
    const com = computeCenterOfMass(children);
    return {
      id: 'internal',
      centerOfMass: { x: com.x, y: com.y, z: com.z },
      mass: com.mass,
      children,
      bounds,
      totalMass: com.mass,
      isExternal: false
    };
  }
  
  const nodeIds = nodes.map(n => n.id);
  return [buildOctree(nodeIds, bounds, 0)];
}

// 计算N体引力 (Barnes-Hut近似)
export function computeNBodyGravity(
  targetId: string,
  targetPos: { x: number; y: number; z: number },
  tree: BHNode[],
  GM: number = 1.0,
  thetaThreshold: number = 0.5 // Barnes-Hut opening angle
): { fx: number; fy: number; fz: number } {
  let fx = 0, fy = 0, fz = 0;
  
  function computeForce(node: BHNode): void {
    if (node.id === targetId) return;
    if (node.totalMass === 0) return;
    
    const dx = node.centerOfMass.x - targetPos.x;
    const dy = node.centerOfMass.y - targetPos.y;
    const dz = node.centerOfMass.z - targetPos.z;
    const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
    
    // 计算opening angle: s / r
    const s = Math.max(
      node.bounds.maxX - node.bounds.minX,
      node.bounds.maxY - node.bounds.minY,
      node.bounds.maxZ - node.bounds.minZ
    );
    const openingAngle = s / Math.max(r, 1e-10);
    
    if (!node.isExternal && openingAngle < thetaThreshold) {
      // 使用质心近似 (单极展开)
      const r3 = r * r * r + 1e-10; // 避免除零
      const f = GM * node.totalMass / r3;
      fx += f * dx;
      fy += f * dy;
      fz += f * dz;
    } else if (node.isExternal && node.id !== targetId) {
      // 直接计算叶子节点
      const r3 = r * r * r + 1e-10;
      const f = GM * node.mass / r3;
      fx += f * dx;
      fy += f * dy;
      fz += f * dz;
    } else if (!node.isExternal) {
      // 递归到子节点
      for (const child of node.children) {
        computeForce(child);
      }
    }
  }
  
  for (const node of tree) {
    computeForce(node);
  }
  
  return { fx, fy, fz };
}

/**
 * 第五部分：TDOA时差定位 / 多边测量 (Trilateration)
 * ================================================================
 * GitHub参考: cliansang/positioning-algorithms-for-u (⭐132)
 * 
 * TDOA: 测量信号到达多个传感器的"时间差"
 *       → 双曲线交点确定源位置
 * 
 * 映射到代码分析:
 *   - 信号源 → 污点源 (用户输入点)
 *   - 传感器 → 污点传播路径上的检测点 (sanitizer/hook点)
 *   - TDOA → 污点从源到检测点的时间差/路径差
 *   - 源位置 → 漏洞的真正源头
 * 
 * 三边测量: 已知3个锚点，到源的距离→求源位置
 * 映射: 3个已知函数位置，到漏洞的距离→定位漏洞
 */
export interface Anchor {
  id: string;
  position: { x: number; y: number; z: number };
  distance: number; // 到目标的距离
  timeOfArrival?: number;
}

// TDOA定位 (双曲线交集)
export function solveTDOA(
  anchors: Array<{
    id: string;
    position: { x: number; y: number; z: number };
    tdoa: number; // 与第一个锚点的时差
    speed?: number; // 信号速度
  }>
): { x: number; y: number; z: number } | null {
  if (anchors.length < 3) return null;
  
  const speed = anchors[0].speed || 1.0;
  const ref = anchors[0];
  
  // 将TDOA转换为距离差
  const r1 = anchors.map(a => ({
    ...a,
    deltaDistance: a.tdoa * speed
  }));
  
  // 线性化并迭代求解 (使用最小二乘法)
  let x = 0, y = 0, z = 0; // 初始猜测
  const tolerance = 1e-6;
  
  for (let iter = 0; iter < 50; iter++) {
    const A: number[][] = [];
    const b: number[] = [];
    
    for (let i = 1; i < r1.length; i++) {
      const ai = r1[i];
      const xi = ai.position.x, yi = ai.position.y, zi = ai.position.z;
      const ri = Math.sqrt((xi - x) ** 2 + (yi - y) ** 2 + (zi - z) ** 2);
      const rRef = Math.sqrt((ref.position.x - x) ** 2 + (ref.position.y - y) ** 2 + (ref.position.z - z) ** 2);
      
      // 线性化方程: (xi-x)² + (yi-y)² + (zi-z)² - (x-xRef)² - ... = Δdi²
      const fi = (ri - rRef) - ai.deltaDistance;
      const gi_x = (xi - x) / ri - (ref.position.x - x) / rRef;
      const gi_y = (yi - y) / ri - (ref.position.y - y) / rRef;
      const gi_z = (zi - z) / ri - (ref.position.z - z) / rRef;
      
      A.push([gi_x, gi_y, gi_z]);
      b.push(-fi);
    }
    
    // 最小二乘解: Δp = (AᵀA)⁻¹Aᵀb
    const AtA = transpose(A).dot(A) as number[][];
    const AtA_inv = invertMatrix(AtA);
    if (!AtA_inv) break;
    
    const Atb = transpose(A).dot(b) as number[];
    const dp = AtA_inv.multVector(Atb);
    
    x += dp[0];
    y += dp[1];
    z += dp[2];
    
    if (Math.sqrt(dp[0]**2 + dp[1]**2 + dp[2]**2) < tolerance) break;
  }
  
  return { x, y, z };
}

// 三边测量定位
export function trilaterate(
  anchors: Array<{ position: { x: number; y: number; z: number }; distance: number }>
): { x: number; y: number; z: number } | null {
  if (anchors.length < 3) return null;
  
  // 使用前3个锚点进行三边测量
  const [a1, a2, a3] = anchors.slice(0, 3);
  
  // 二维简化版本 (扩展到3D类似)
  // 球面交点求解
  const p1 = a1.position, p2 = a2.position, p3 = a3.position;
  const r1 = a1.distance, r2 = a2.distance, r3 = a3.distance;
  
  // 化为二维问题求解
  const ex = { x: p2.x - p1.x, y: p2.y - p1.y };
  const eLen = Math.sqrt(ex.x ** 2 + ex.y ** 2);
  ex.x /= eLen; ex.y /= eLen;
  
  const ey = {
    x: p3.x - p1.x - ex.x * ((p3.x - p1.x) * ex.x + (p3.y - p1.y) * ex.y),
    y: p3.y - p1.y - ex.y * ((p3.x - p1.x) * ex.x + (p3.y - p1.y) * ex.y)
  };
  const eyLen = Math.sqrt(ey.x ** 2 + ey.y ** 2);
  ey.x /= eyLen; ey.y /= eyLen;
  
  const d = (p2.x - p1.x) * ex.x + (p2.y - p1.y) * ex.y;
  const j = (p3.x - p1.x) * ex.x + (p3.y - p1.y) * ex.y;
  
  const x = (r1 * r1 - r2 * r2 + d * d) / (2 * d);
  const y = (r1 * r1 - r3 * r3 + j * j + x * x - x * j) / (2 * eyLen);
  
  return {
    x: p1.x + x * ex.x + y * ey.x,
    y: p1.y + x * ex.y + y * ey.y,
    z: 0 // 二维简化
  };
}

// 矩阵辅助函数
 function transpose(A: number[][]): { dot(b: number[] | number[][]): number[] | number[][]; multVector: (v: number[]) => number[] } {
  const rows = A.length, cols = A[0].length;
  const At = Array.from({ length: cols }, () => Array(rows).fill(0));
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) At[j][i] = A[i][j];
  }
  return {
    dot(b: number[] | number[][]): number[] | number[][] {
      if (Array.isArray(b[0])) {
        // Matrix-matrix multiplication: At @ B
        const B = b as number[][];
        const p = B[0].length;
        const result = Array.from({ length: cols }, () => Array(p).fill(0));
        for (let i = 0; i < cols; i++) {
          for (let j = 0; j < p; j++) {
            for (let k = 0; k < rows; k++) result[i][j] += At[i][k] * B[k][j];
          }
        }
        return result;
      }
      // Matrix-vector multiplication: At @ b
      const bv = b as number[];
      const result = new Array(cols).fill(0);
      for (let j = 0; j < cols; j++) {
        for (let i = 0; i < rows; i++) result[j] += At[j][i] * bv[i];
      }
      return result;
    },
    multVector(v: number[]): number[] {
      // 简化的矩阵-向量乘法
      return new Array(cols).fill(0);
    }
  };
}

function invertMatrix(A: number[][]): { multVector: (v: number[]) => number[] } | null {
  const n = A.length;
  if (n === 0) return null;
  
  // 高斯消元求逆
  const aug = A.map((row, i) => [...row, ...Array(n).fill(0).map((_, j) => i === j ? 1 : 0)]);
  
  for (let i = 0; i < n; i++) {
    let maxRow = i;
    for (let k = i + 1; k < n; k++) {
      if (Math.abs(aug[k][i]) > Math.abs(aug[maxRow][i])) maxRow = k;
    }
    [aug[i], aug[maxRow]] = [aug[maxRow], aug[i]];
    if (Math.abs(aug[i][i]) < 1e-10) return null;
    
    const pivot = aug[i][i];
    for (let j = 0; j < 2 * n; j++) aug[i][j] /= pivot;
    
    for (let k = 0; k < n; k++) {
      if (k !== i) {
        const factor = aug[k][i];
        for (let j = 0; j < 2 * n; j++) aug[k][j] -= factor * aug[i][j];
      }
    }
  }
  
  const inv = aug.map(row => row.slice(n));
  return {
    multVector(v: number[]): number[] {
      const result = new Array(n).fill(0);
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) result[i] += inv[i][j] * v[j];
      }
      return result;
    }
  };
}

/**
 * 第六部分：拉格朗日点分析 (Lagrange Points)
 * ================================================================
 * CR3BP (圆型限制性三体问题) 中的5个平衡点
 * L1-L3: 共线点 (不稳定)
 * L4-L5: 三角点 (稳定，如果质量比满足条件)
 * 
 * GitHub参考: JackCrusoe47/CR3BP_MATLAB_Library (⭐26), SergioCdV/CR3BP-Mission-Analysis-and-Design (⭐13)
 * 
 * 映射到代码分析:
 *   - L1: 入口点附近的关键分支点 (if/else汇聚)
 *   - L2: 循环出口的关键合并点
 *   - L3: 深层次嵌套中的逃逸点
 *   - L4/L5: 函数调用图中的"稳定"模块 (被多路径依赖，但不直接调用其他脆弱模块)
 */

export interface LagrangePoint {
  id: 'L1' | 'L2' | 'L3' | 'L4' | 'L5';
  position: { x: number; y: number; z: number };
  stability: 'stable' | 'unstable';
  associatedCFGJunction: string; // 关联的CFG汇合节点ID
  massRatio: number; // 质量比 μ = m2/(m1+m2)
}

// 计算CR3BP拉格朗日点
export function computeLagrangePoints(
  mu: number, // 质量比 μ = m_small / (m_large + m_small)
  rLarge: number = 1.0 // 大质量体位置
): LagrangePoint[] {
  const points: LagrangePoint[] = [];
  
  // L1: 位于两大质量体之间
  // 近似求解: r_L1 ≈ r_large * (μ/3)^(1/3)
  const rL1 = rLarge * Math.pow(mu / 3, 1 / 3);
  points.push({
    id: 'L1',
    position: { x: rLarge - rL1, y: 0, z: 0 },
    stability: 'unstable',
    associatedCFGJunction: '',
    massRatio: mu
  });
  
  // L2: 大质量体外侧
  const rL2 = rLarge * Math.pow(mu / 3, 1 / 3);
  points.push({
    id: 'L2',
    position: { x: rLarge + rL2, y: 0, z: 0 },
    stability: 'unstable',
    associatedCFGJunction: '',
    massRatio: mu
  });
  
  // L3: 小质量体外侧 (对侧)
  const rL3 = rLarge * (1 + 5 / 12 * mu);
  points.push({
    id: 'L3',
    position: { x: -rLarge - rL3, y: 0, z: 0 },
    stability: 'unstable',
    associatedCFGJunction: '',
    massRatio: mu
  });
  
  // L4: 领先60度 (三角形点)
  points.push({
    id: 'L4',
    position: { x: rLarge * 0.5, y: rLarge * Math.sqrt(3) / 2, z: 0 },
    stability: mu < 0.03852 ? 'stable' : 'unstable', // 约西宝质量比阈值
    associatedCFGJunction: '',
    massRatio: mu
  });
  
  // L5: 落后60度 (三角形点)
  points.push({
    id: 'L5',
    position: { x: rLarge * 0.5, y: -rLarge * Math.sqrt(3) / 2, z: 0 },
    stability: mu < 0.03852 ? 'stable' : 'unstable',
    associatedCFGJunction: '',
    massRatio: mu
  });
  
  return points;
}

// 在CFG中识别拉格朗日点 (关键汇合节点)
export function identifyLagrangePointsInCFG(cpg: CodePropertyGraph): LagrangePoint[] {
  const nodes = Array.from(cpg.nodes.values());
  const edges = Array.from(cpg.edges.values());
  
  // 计算每个节点的入度和出度
  const inDegree = new Map<string, number>();
  const outDegree = new Map<string, number>();
  const predecessors = new Map<string, string[]>();
  const successors = new Map<string, string[]>();
  
  for (const node of nodes) {
    inDegree.set(node.id, 0);
    outDegree.set(node.id, 0);
    predecessors.set(node.id, []);
    successors.set(node.id, []);
  }
  
  for (const edge of edges) {
    inDegree.set(edge.target, (inDegree.get(edge.target) || 0) + 1);
    outDegree.set(edge.source, (outDegree.get(edge.source) || 0) + 1);
    predecessors.get(edge.target)?.push(edge.source);
    successors.get(edge.source)?.push(edge.target);
  }
  
  // 找汇合点 (多入度 + 多出度 → 类似L4/L5的稳定点)
  // 找分支点 (1入度 + 多出度 → 类似L1/L2/L3的不稳定点)
  const points: LagrangePoint[] = [];
  
  for (const node of nodes) {
    const indeg = inDegree.get(node.id) || 0;
    const outdeg = outDegree.get(node.id) || 0;
    
    if (indeg >= 2 && outdeg >= 2) {
      // 稳定点: 多条路径汇合 (L4/L5类)
      points.push({
        id: 'L4', // 分类到L4
        position: { x: node.lineNumber || 0, y: indeg, z: outdeg },
        stability: 'stable',
        associatedCFGJunction: node.id,
        massRatio: indeg / Math.max(outdeg, 1)
      });
    } else if (indeg >= 2 && outdeg === 1) {
      // 不稳定分支出口点 (L1/L2/L3类)
      points.push({
        id: 'L1',
        position: { x: node.lineNumber || 0, y: indeg, z: outdeg },
        stability: 'unstable',
        associatedCFGJunction: node.id,
        massRatio: indeg / Math.max(outdeg, 1)
      });
    }
  }
  
  return points;
}

/**
 * 第七部分：轨道异常检测 (Orbital Anomaly Detection)
 * ================================================================
 * GitHub参考: Shreeyaa14/AI-based-Space-Situational-Awareness-System (⭐0)
 * 
 * 方法: Z-score, Mahalanobis距离, 隔离森林, FFT周期分析
 * 
 * 映射到代码分析:
 *   - 轨道残差 → 代码指标偏差 (圈复杂度、深度、长度)
 *   - 周期扰动 → 循环中的周期性漏洞模式
 *   - 轨道预测偏差 → 漏洞模式预测
 */

export interface OrbitalAnomaly {
  nodeId: string;
  type: 'trajectory_deviation' | 'period_anomaly' | 'velocity_anomaly' | 'mass_anomaly';
  score: number; // 异常分数
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  direction: { dx: number; dy: number; dz: number }; // 偏差方向
}

// Z-score异常检测 (用于单维轨道参数)
export function detectZScoreAnomaly(
  values: number[],
  threshold: number = 2.0
): Array<{ index: number; value: number; zscore: number }> {
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  const sd = Math.sqrt(variance);
  
  if (sd === 0) return [];
  
  return values
    .map((value, index) => ({
      index,
      value,
      zscore: Math.abs((value - mean) / sd)
    }))
    .filter(item => item.zscore > threshold)
    .sort((a, b) => b.zscore - a.zscore);
}

// Mahalanobis距离异常检测 (用于多维轨道参数)
export function detectMahalanobisAnomaly(
  data: number[][],
  threshold: number = 3.0
): Array<{ index: number; distance: number }> {
  const n = data.length;
  if (n <= data[0].length) return [];
  
  // 计算均值向量
  const dims = data[0].length;
  const meanVec = new Array(dims).fill(0);
  for (const row of data) {
    for (let i = 0; i < dims; i++) meanVec[i] += row[i];
  }
  for (let i = 0; i < dims; i++) meanVec[i] /= n;
  
  // 计算协方差矩阵
  const cov = Array.from({ length: dims }, () => Array(dims).fill(0));
  for (let i = 0; i < dims; i++) {
    for (let j = 0; j < dims; j++) {
      let sum = 0;
      for (let k = 0; k < n; k++) {
        sum += (data[k][i] - meanVec[i]) * (data[k][j] - meanVec[j]);
      }
      cov[i][j] = sum / (n - 1);
    }
  }
  
  // 计算每个点的Mahalanobis距离
  const results: Array<{ index: number; distance: number }> = [];
  
  for (let idx = 0; idx < n; idx++) {
    const diff = data[idx].map((v, i) => v - meanVec[i]);
    
    // 简化的Mahalanobis距离 (假设对角协方差矩阵)
    let dist = 0;
    for (let i = 0; i < dims; i++) {
      const var_i = cov[i][i] || 1;
      dist += (diff[i] * diff[i]) / var_i;
    }
    
    if (dist > threshold * threshold) {
      results.push({ index: idx, distance: Math.sqrt(dist) });
    }
  }
  
  return results.sort((a, b) => b.distance - a.distance);
}

// FFT周期检测 (用于发现代码中的周期性漏洞模式)
export function detectPeriodicAnomaly(
  signal: number[],
  samplingRate: number = 1.0
): Array<{ period: number; amplitude: number; phase: number }> {
  const n = signal.length;
  if (n < 4) return [];
  
  // 简化的离散傅里叶变换 (DFT)
  const frequencies: Array<{ freq: number; amplitude: number; phase: number }> = [];
  const maxFreq = samplingRate / 2;
  const df = maxFreq / (n / 2);
  
  for (let k = 1; k < n / 2; k++) {
    const freq = k * df;
    let real = 0, imag = 0;
    
    for (let t = 0; t < n; t++) {
      const angle = 2 * Math.PI * k * t / n;
      real += signal[t] * Math.cos(angle);
      imag += signal[t] * Math.sin(angle);
    }
    
    const amplitude = Math.sqrt(real * real + imag * imag) / n;
    const phase = Math.atan2(imag, real);
    
    if (amplitude > 0.5) { // 只保留显著周期
      frequencies.push({ freq, amplitude, phase });
    }
  }
  
  return frequencies
    .map(f => ({ period: 1 / f.freq, amplitude: f.amplitude, phase: f.phase }))
    .filter(f => f.period > 1 && f.period < n)
    .sort((a, b) => b.amplitude - a.amplitude);
}

/**
 * 第八部分：轨道摄动分析 (Orbital Perturbation)
 * ================================================================
 * GitHub参考: priyanshubawse13/Satellite-Orbit-Sim (⭐1), MartinKamme/Orbital-Pertrubations (⭐0)
 * 
 * 主要摄动源:
 * - J2摄动: 地球非球形引力 (扁率)
 * - 大气阻力: 低轨道的轨道衰减
 * - 相对论效应: 高速轨道的近日点进动
 * 
 * 映射到代码分析:
 *   - J2摄动 → 函数依赖的副作用 (全局状态修改)
 *   - 大气阻力 → 资源泄漏 (内存/文件描述符)
 *   - 近日点进动 → 关键路径的累积偏差 → 漏洞涌现
 */

export interface Perturbation {
  type: 'j2' | 'atmospheric_drag' | 'relativistic' | 'third_body' | 'solar_radiation';
  magnitude: number;
  direction: { dx: number; dy: number; dz: number };
  affectedElements: string[]; // 受影响的轨道根数
  impact: 'accelerating' | 'decelerating' | 'deflecting';
}

// J2摄动 (地球扁率引起的升交点进动和近日点漂移)
export function computeJ2Perturbation(
  elements: OrbitalElements,
  J2: number = 0.00108263, // 地球J2系数
  Re: number = 6378.137,   // 地球半径 (km)
  GM: number = 398600.441  // 地球引力常数 (km³/s²)
): Perturbation {
  const { semiMajorAxis: a, eccentricity: e, inclination: i } = elements;
  
  // J2引起的升交点赤经变化率
  const n = Math.sqrt(GM / (a * a * a)); // 平均运动
  const p = a * (1 - e * e); // 半通径
  
  const dOmega_dt = -1.5 * n * J2 * Math.pow(Re / p, 2) * Math.cos(i);
  
  // J2引起的近日点幅角变化率
  const domega_dt = 0.75 * n * J2 * Math.pow(Re / p, 2) * (5 * Math.cos(i) * Math.cos(i) - 1);
  
  return {
    type: 'j2',
    magnitude: Math.sqrt(dOmega_dt * dOmega_dt + domega_dt * domega_dt),
    direction: { dx: dOmega_dt, dy: domega_dt, dz: 0 },
    affectedElements: ['raan', 'argPeriapsis'],
    impact: 'deflecting'
  };
}

// 大气阻力摄动 (轨道衰减)
export function computeAtmosphericDragPerturbation(
  elements: OrbitalElements,
  Cd: number = 2.0,     //阻力系数
  A_m: number = 1e-6,  // 面积质量比
  rho: number = 1e-12   // 大气密度
): Perturbation {
  const { semiMajorAxis: a } = elements;
  const n = Math.sqrt(1 / (a * a * a)); // 简化的平均运动
  
  // 半长轴衰减率
  const da_dt = -2 * Math.PI * Cd * A_m * rho * a;
  
  return {
    type: 'atmospheric_drag',
    magnitude: Math.abs(da_dt),
    direction: { dx: 0, dy: 0, dz: 0 },
    affectedElements: ['semiMajorAxis'],
    impact: 'decelerating'
  };
}

/**
 * 第九部分：代码轨道映射器
 * 将代码实体映射到宇宙坐标系
 */
export interface CodeOrbitMapper {
  // 将CPG节点映射为轨道实体
  mapCPGToOrbitalElements(cpg: CodePropertyGraph): Map<string, OrbitalElements>;
  
  // 识别拉格朗日点
  identifyLagrangePoints(cpg: CodePropertyGraph): LagrangePoint[];
  
  // 计算污点传播的Lambert转移轨道
  computeTaintTransferOrbit(
    cpg: CodePropertyGraph,
    sourceNodeId: string,
    sinkNodeId: string
  ): LambertSolution | null;
  
  // N体引力分析 (依赖关系强度)
  analyzeDependencyGravity(cpg: CodePropertyGraph): Map<string, { fx: number; fy: number; fz: number }>;
  
  // 轨道异常检测
  detectOrbitalAnomalies(cpg: CodePropertyGraph): OrbitalAnomaly[];
}

// 主映射器实现
export class CosmXOrbitMapper implements CodeOrbitMapper {
  private cpg: CodePropertyGraph;
  
  constructor(cpg: CodePropertyGraph) {
    this.cpg = cpg;
  }
  
  mapCPGToOrbitalElements(cpg: CodePropertyGraph): Map<string, OrbitalElements> {
    const elements = new Map<string, OrbitalElements>();
    
    for (const [nodeId, node] of cpg.nodes) {
      // 从节点属性计算轨道根数
      const code = node.code || '';
      const lineNum = node.lineNumber || 1;
      
      // 半长轴: 嵌套深度 + 1
      const depth = (code.match(/\b(if|for|while|switch|catch)\b/g) || []).length;
      const semiMajorAxis = depth + 1;
      
      // 离心率: 分支复杂度
      const branches = (code.match(/\b(if|else|switch|case)\b/g) || []).length;
      const eccentricity = Math.min(0.99, branches / (branches + 1));
      
      // 倾角: 循环嵌套
      const loops = (code.match(/\b(for|while|do)\b/g) || []).length;
      const inclination = loops * 15; // 度数表示
      
      // 轨道周期: 代码长度
      const period = code.length / 10;
      
      elements.set(nodeId, {
        semiMajorAxis,
        eccentricity,
        inclination,
        raan: lineNum % 360, // 升交点赤经
        argPeriapsis: (depth * 30) % 360,
        trueAnomaly: (lineNum * 10) % 360,
        period,
        meanMotion: 2 * Math.PI / period
      });
    }
    
    return elements;
  }
  
  identifyLagrangePoints(cpg: CodePropertyGraph): LagrangePoint[] {
    return identifyLagrangePointsInCFG(cpg);
  }
  
  computeTaintTransferOrbit(
    cpg: CodePropertyGraph,
    sourceNodeId: string,
    sinkNodeId: string
  ): LambertSolution | null {
    const sourceNode = cpg.nodes.get(sourceNodeId);
    const sinkNode = cpg.nodes.get(sinkNodeId);
    if (!sourceNode || !sinkNode) return null;
    
    // 计算路径长度作为"转移时间"
    const edges = Array.from(cpg.edges.values());
    const pathLength = edges.filter(e => e.type === 'DATA_FLOW' || e.type === 'CFG').length;
    
    // 构建位置向量 (使用行号作为x,入度作为y,出度作为z)
    const sourceIn = edges.filter(e => e.target === sourceNodeId).length;
    const sourceOut = edges.filter(e => e.source === sourceNodeId).length;
    const sinkIn = edges.filter(e => e.target === sinkNodeId).length;
    const sinkOut = edges.filter(e => e.source === sinkNodeId).length;
    
    const r1 = { x: sourceNode.lineNumber || 0, y: sourceIn, z: sourceOut };
    const r2 = { x: sinkNode.lineNumber || 0, y: sinkIn, z: sinkOut };
    
    return solveLambertProblem(r1, r2, pathLength + 1);
  }
  
  analyzeDependencyGravity(cpg: CodePropertyGraph): Map<string, { fx: number; fy: number; fz: number }> {
    const forces = new Map<string, { fx: number; fy: number; fz: number }>();
    
    // 构建Barnes-Hut树
    const nodes = Array.from(cpg.nodes.entries()).map(([id, node]) => ({
      id,
      position: {
        x: node.lineNumber || 0,
        y: id.charCodeAt(0) % 100,
        z: (node.code?.length || 0) / 100
      },
      mass: (node.code?.length || 1) / 100 // 质量与代码长度成正比
    }));
    
    const bounds = { minX: 0, maxX: 10000, minY: 0, maxY: 100, minZ: 0, maxZ: 100 };
    const tree = buildBHTree(nodes, bounds);
    
    // 计算每个节点的引力
    for (const [nodeId, node] of cpg.nodes) {
      const force = computeNBodyGravity(
        nodeId,
        { x: node.lineNumber || 0, y: 0, z: 0 },
        tree
      );
      forces.set(nodeId, force);
    }
    
    return forces;
  }
  
  detectOrbitalAnomalies(cpg: CodePropertyGraph): OrbitalAnomaly[] {
    const anomalies: OrbitalAnomaly[] = [];
    const elements = this.mapCPGToOrbitalElements(cpg);
    
    // 收集所有半长轴值
    const semiMajorAxes = Array.from(elements.values()).map(e => e.semiMajorAxis);
    const eccentricities = Array.from(elements.values()).map(e => e.eccentricity);
    
    // Z-score异常检测
    const semiMajorAnomalies = detectZScoreAnomaly(semiMajorAxes, 2.0);
    const eccAnomalies = detectZScoreAnomaly(eccentricities, 2.0);
    
    for (const { index, value, zscore } of semiMajorAnomalies) {
      const nodeId = Array.from(elements.keys())[index];
      anomalies.push({
        nodeId,
        type: 'trajectory_deviation',
        score: zscore,
        severity: zscore > 3 ? 'critical' : zscore > 2.5 ? 'high' : 'medium',
        description: `Code complexity anomaly: semiMajorAxis=${value} (z=${zscore.toFixed(2)})`,
        direction: { dx: value, dy: 0, dz: 0 }
      });
    }
    
    for (const { index, value, zscore } of eccAnomalies) {
      const nodeId = Array.from(elements.keys())[index];
      anomalies.push({
        nodeId,
        type: 'velocity_anomaly',
        score: zscore,
        severity: zscore > 3 ? 'critical' : zscore > 2.5 ? 'high' : 'medium',
        description: `Branch complexity anomaly: eccentricity=${value.toFixed(2)} (z=${zscore.toFixed(2)})`,
        direction: { dx: 0, dy: value, dz: 0 }
      });
    }
    
    return anomalies;
  }
}

/**
 * 第十部分：主宇宙星系漏洞挖掘引擎
 */
export interface CosmXResult {
  orbitalElements: Map<string, OrbitalElements>;
  lagrangePoints: LagrangePoint[];
  taintOrbits: Map<string, LambertSolution>;
  dependencyGravity: Map<string, { fx: number; fy: number; fz: number }>;
  anomalies: OrbitalAnomaly[];
  perturbations: Perturbation[];
  vulnerabilityScore: number;
  criticalPaths: string[][];
}

export function cosmXAnalyze(cpg: CodePropertyGraph): CosmXResult {
  const mapper = new CosmXOrbitMapper(cpg);
  
  // 1. 轨道根数映射
  const orbitalElements = mapper.mapCPGToOrbitalElements(cpg);
  
  // 2. 拉格朗日点识别
  const lagrangePoints = mapper.identifyLagrangePoints(cpg);
  
  // 3. N体引力分析
  const dependencyGravity = mapper.analyzeDependencyGravity(cpg);
  
  // 4. 轨道异常检测
  const anomalies = mapper.detectOrbitalAnomalies(cpg);
  
  // 5. 摄动分析
  const perturbations: Perturbation[] = [];
  for (const [, elem] of orbitalElements) {
    if (elem.semiMajorAxis < 5) { // 低轨函数 (可能被攻击)
      perturbations.push(computeJ2Perturbation(elem));
    }
  }
  
  // 6. 污点转移轨道 (source→sink)
  const taintOrbits = new Map<string, LambertSolution>();
  const sources = Array.from(cpg.nodes.values()).filter(n => n.type === 'Expression');
  const sinks = Array.from(cpg.nodes.values()).filter(n => n.type === 'Expression');
  
  for (const source of sources) {
    for (const sink of sinks) {
      const orbit = mapper.computeTaintTransferOrbit(cpg, source.id, sink.id);
      if (orbit) {
        taintOrbits.set(`${source.id}→${sink.id}`, orbit);
      }
    }
  }
  
  // 7. 综合漏洞评分
  const anomalyScore = anomalies.reduce((s, a) => s + a.score, 0) / Math.max(anomalies.length, 1);
  const perturbationScore = perturbations.reduce((s, p) => s + p.magnitude, 0) / Math.max(perturbations.length, 1);
  const gravityScore = Array.from(dependencyGravity.values()).reduce((s, g) => {
    return s + Math.sqrt(g.fx * g.fx + g.fy * g.fy + g.fz * g.fz);
  }, 0) / Math.max(dependencyGravity.size, 1);
  
  const vulnerabilityScore = Math.min(1.0,
    anomalyScore * 0.4 +
    perturbationScore * 0.3 +
    gravityScore * 0.3
  );
  
  // 8. 关键路径识别 (轨道根数异常的节点间路径)
  const criticalPaths: string[][] = [];
  const anomalyNodes = new Set(anomalies.map(a => a.nodeId));
  if (anomalyNodes.size >= 2) {
    criticalPaths.push([...anomalyNodes]);
  }
  
  return {
    orbitalElements,
    lagrangePoints,
    taintOrbits,
    dependencyGravity,
    anomalies,
    perturbations,
    vulnerabilityScore,
    criticalPaths
  };
}
