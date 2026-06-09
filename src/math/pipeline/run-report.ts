/**
 * pipeline/run-report.ts — 报告生成入口
 *
 * v3.0 重新设计后, 报告生成入口从此处导出.
 * 把 ProjectScanReport 渲染为人类可读的报告 (markdown / json).
 *
 * 用法: bun src/math/pipeline/run-report.ts <scan-report.json> [--format md|json]
 *
 * 抽象层次: L3 漏洞挖掘 + L4 验证闭环
 *
 * @see docs/REDESIGN.md §2
 */

import type { ProjectScanReport } from '../application/patterns.js';

function formatMarkdown(report: ProjectScanReport): string {
  const lines: string[] = [];
  lines.push(`# 漏洞扫描报告: ${report.project}`);
  lines.push('');
  lines.push(`**总漏洞数**: ${report.total_vulnerabilities}`);
  lines.push(`**项目级 UVRS**: ${report.project_uvrs.unified_score.toFixed(4)}`);
  lines.push(`**风险等级**: ${report.project_uvrs.risk_level}`);
  lines.push('');
  lines.push('## 6 维 cosm-x 上下文');
  lines.push(`- 拉格朗日点: ${report.cosmx_summary.lagrange_points}`);
  lines.push(`- 异常: ${report.cosmx_summary.anomalies}`);
  lines.push(`- 摄动: ${report.cosmx_summary.perturbations}`);
  lines.push(`- 基础风险分数: ${report.cosmx_summary.base_vulnerability_score.toFixed(4)}`);
  lines.push('');
  lines.push('## 漏洞清单');
  lines.push('');
  for (const v of report.vulnerabilities.slice(0, 50)) {
    lines.push(`### ${v.type} [${v.severity}]`);
    lines.push(`- 文件: \`${v.file}:${v.line}\``);
    lines.push(`- 描述: ${v.description}`);
    lines.push(`- 分数: ${v.score.toFixed(2)}`);
    if (v.uvrs) lines.push(`- UVRS: ${v.uvrs.unified_score.toFixed(4)}`);
    lines.push('');
  }
  if (report.vulnerabilities.length > 50) {
    lines.push(`... 还有 ${report.vulnerabilities.length - 50} 条未显示`);
  }
  return lines.join('\n');
}

function main() {
  const args = process.argv.slice(2);
  const reportPath = args[0];
  const format = args.includes('--format') ? args[args.indexOf('--format') + 1] : 'md';
  if (!reportPath) {
    console.log('用法: bun run-report.ts <scan-report.json> [--format md|json]');
    process.exit(1);
  }
  const fs = require('fs') as typeof import('fs');
  const report: ProjectScanReport = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
  if (format === 'md') {
    console.log(formatMarkdown(report));
  } else {
    console.log(JSON.stringify(report, null, 2));
  }
}

main();
