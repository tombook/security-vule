#!/usr/bin/env bun
/**
 * CosmX Galaxy Method - CLI
 * 宇宙星系法白盒漏洞挖掘
 */
import { cosmXAnalyze, CosmXOrbitMapper, type CosmXResult } from './cosm-x-galaxy.js';
import { CPGBuilder } from './execution/cpg.js';

// 演示用的测试代码
const TEST_CODE = `
def process_user_input(data):
    if data:
        query = "SELECT * FROM users WHERE id = " + data
        result = db.execute(query)
        return result
    return None

def check_permission(user_id, resource):
    for role in user_id.roles:
        if role.can_access(resource):
            return True
    return False

def calculate_total(items, tax_rate):
    total = 0
    for item in items:
        total += item.price
    total *= (1 + tax_rate)
    return total
`;

// 从测试代码构建CPG并分析
function buildCPGFromCode(code: string) {
  const cpgBuilder = new CPGBuilder();
  cpgBuilder.setLanguage('python').setProjectPath('test.py');
  cpgBuilder.addFile('file_1', 'test.py', code);
  
  const lines = code.split('\n');
  let nodeId = 1;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;
    if (!line || line.startsWith('#')) continue;
    
    if (/^def\s+\w+/.test(line)) {
      const match = line.match(/def\s+(\w+)/);
      cpgBuilder.addFunction(`func_${nodeId}`, match?.[1] || 'anon', lineNum);
    } else if (line.includes('SELECT') || line.includes('execute') || line.includes('query')) {
      cpgBuilder.addStatement(`stmt_${nodeId}`, line, lineNum);
      cpgBuilder.addDataFlowEdge(`stmt_${nodeId}`, `stmt_${nodeId}`);
    } else if (line.startsWith('if ') || line.startsWith('for ') || line.startsWith('while ') || line.startsWith('return ') || line.startsWith('return')) {
      cpgBuilder.addStatement(`stmt_${nodeId}`, line, lineNum);
      cpgBuilder.addCFGEdge(`stmt_${nodeId}`, `stmt_${nodeId}`);
    } else {
      cpgBuilder.addExpression(`expr_${nodeId}`, line, lineNum);
    }
    nodeId++;
  }
  
  return cpgBuilder.build();
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  🌌 CosmX Galaxy Method - 宇宙星系法白盒漏洞挖掘  🌌');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  console.log('📡 构建测试代码的Code Property Graph...');
  const cpg = buildCPGFromCode(TEST_CODE);
  console.log(`   CPG节点数: ${cpg.nodes.size}, CPG边数: ${cpg.edges.size}\n`);
  
  console.log('🪐 启动轨道力学分析...\n');
  const result = cosmXAnalyze(cpg);
  
  console.log('━' .repeat(60));
  console.log('📊 轨道根数分析 (Orbital Elements)');
  console.log('━' .repeat(60));
  
  for (const [nodeId, elem] of result.orbitalElements) {
    console.log(`\n  🔹 ${nodeId}`);
    console.log(`     半长轴 a = ${elem.semiMajorAxis} (复杂度/嵌套深度)`);
    console.log(`     离心率 e = ${elem.eccentricity.toFixed(3)} (路径偏差度)`);
    console.log(`     轨道周期 T = ${elem.period.toFixed(1)} (代码长度)`);
  }
  
  console.log('\n' + '━' .repeat(60));
  console.log('🪐 拉格朗日点 (Lagrange Points)');
  console.log('━' .repeat(60));
  
  if (result.lagrangePoints.length === 0) {
    console.log('  (无显著汇合点)');
  }
  for (const lp of result.lagrangePoints) {
    console.log(`\n  ⭐ ${lp.id} (${lp.stability})`);
    console.log(`     位置: L=${lp.position.x}, indeg=${lp.position.y.toFixed(0)}, outdeg=${lp.position.z.toFixed(0)}`);
    console.log(`     关联节点: ${lp.associatedCFGJunction || '(未关联)'}`);
  }
  
  console.log('\n' + '━' .repeat(60));
  console.log('🌍 N体引力分析 (依赖关系强度)');
  console.log('━' .repeat(60));
  
  for (const [nodeId, force] of result.dependencyGravity) {
    const magnitude = Math.sqrt(force.fx ** 2 + force.fy ** 2 + force.fz ** 2);
    if (magnitude > 0.01) {
      console.log(`  ${nodeId}: |F| = ${magnitude.toFixed(4)}`);
    }
  }
  
  console.log('\n' + '━' .repeat(60));
  console.log('🔍 轨道异常检测');
  console.log('━' .repeat(60));
  
  if (result.anomalies.length === 0) {
    console.log('  ✓ 未检测到显著异常');
  }
  for (const anomaly of result.anomalies) {
    const emoji = anomaly.severity === 'critical' ? '🚨' : anomaly.severity === 'high' ? '⚠️' : '📊';
    console.log(`\n  ${emoji} [${anomaly.severity.toUpperCase()}] ${anomaly.nodeId}`);
    console.log(`     类型: ${anomaly.type}`);
    console.log(`     评分: ${anomaly.score.toFixed(3)}`);
    console.log(`     ${anomaly.description}`);
  }
  
  console.log('\n' + '━' .repeat(60));
  console.log('🛤 污点转移轨道 (Lambert Solver)');
  console.log('━' .repeat(60));
  
  let orbitCount = 0;
  for (const [path, orbit] of result.taintOrbits) {
    if (orbitCount++ < 3) {
      console.log(`\n  📡 ${path}`);
      console.log(`     类型: ${orbit.type}`);
      console.log(`     半长轴: ${orbit.semiMajorAxis.toFixed(2)}`);
      console.log(`     飞行时间: ${orbit.timeOfFlight.toFixed(2)}`);
    }
  }
  if (result.taintOrbits.size > 3) {
    console.log(`\n  ... 还有 ${result.taintOrbits.size - 3} 条轨道`);
  }
  
  console.log('\n' + '━' .repeat(60));
  console.log('📈 综合漏洞评分');
  console.log('━' .repeat(60));
  
  const score = result.vulnerabilityScore;
  const bar = '█'.repeat(Math.floor(score * 20)) + '░'.repeat(20 - Math.floor(score * 20));
  const label = score > 0.7 ? '🔴 HIGH' : score > 0.4 ? '🟡 MEDIUM' : '🟢 LOW';
  console.log(`\n  综合评分: [${bar}] ${(score * 100).toFixed(1)}% ${label}\n`);
  
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Analysis complete - 宇宙星系法分析完成');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

main().catch(e => { console.error(e); process.exit(1); });
