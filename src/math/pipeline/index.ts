/**
 * pipeline — 端到端管道
 *
 * L3 漏洞挖掘 + L4 验证闭环.
 *
 * 模块:
 *  - run-scan     单次扫描入口 (CLI)
 *  - run-evolve   GA 进化入口 (12 维基因空间)
 *  - run-evaluate 真实 GT 评估入口
 *  - run-report   报告生成入口
 *
 * @see docs/REDESIGN.md §2
 */

export * from './run-scan.js';
export * from './run-evolve.js';
export * from './run-evaluate.js';
export * from './run-report.js';
