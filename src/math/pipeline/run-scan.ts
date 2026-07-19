/**
 * pipeline/run-scan.ts — CLI 入口 (单次扫描)
 *
 * v3.0 重新设计后, 命令行入口从此处导出.
 * 原 cosm-x-project-analyzer.ts 1180-1218 行.
 *
 * 用法: bun src/math/pipeline/run-scan.ts [选项] <项目路径...>
 *
 * 抽象层次: L3 漏洞挖掘 + L4 验证闭环
 *
 * @see docs/REDESIGN.md §2
 */

import { analyzeProjects, scanProjectWithUVRS, scanProjectsWithUVRS } from '../application/scanner.js';

function parseArgs(argv: string[]): { projectPaths: string[]; minScore: number; dedupMode: 'none' | 'file-type' | 'file-line-type' } {
  const projectPaths: string[] = [];
  // v2.6.0: GA 最优参数 (1M 轮真实 F1 评估, 收敛于 bestF1=0.1765)
  // 旧值 0 → 552 FP, 新值 52.52 → 9 FP, F1 0.0970 → 0.1765 (+82%)
  // 警告: 52.52 阈值在 cosm-x-project-analyzer 的 scanFile 中可能过滤掉全部 findings
  // (UVRS < 0.1 fallback 到 6 维 score, 6 维 score 实际范围未对齐 0-100)
  // 真实稳健值需重新校准
  let minScore = 0;
  let dedupMode: 'none' | 'file-type' | 'file-line-type' = 'file-type';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--min-score' && argv[i + 1]) {
      minScore = parseFloat(argv[++i]);
    } else if (a === '--dedup' && argv[i + 1]) {
      const v = argv[++i];
      if (v === 'none' || v === 'file-type' || v === 'file-line-type') dedupMode = v;
    } else if (a === '--no-dedup') {
      dedupMode = 'none';
    } else if (!a.startsWith('--')) {
      projectPaths.push(a);
    }
  }
  return { projectPaths, minScore, dedupMode };
}

const cliArgs = parseArgs(process.argv.slice(2));
const projects = cliArgs.projectPaths;
if (projects.length === 0) {
  console.log('用法: bun src/math/cosm-x-project-analyzer.ts [选项] <项目路径1> [项目路径2] ...');
  console.log('选项:');
  console.log('  --min-score <N>     最小置信度分数阈值 (0-100, 默认 52.52 = GA 最优)');
  console.log('  --dedup <mode>      去重模式: none | file-type | file-line-type (默认 file-type)');
  console.log('  --no-dedup          禁用去重 (等同 --dedup none)');
  console.log('GA 推荐配置 (F1=0.1765, v2.5.2 1M 轮收敛):');
  console.log('  --min-score 52.52 --dedup file-type');
  console.log('示例: bun src/math/cosm-x-project-analyzer.ts /tmp/vuln-projects/DVWA');
  process.exit(1);
}
