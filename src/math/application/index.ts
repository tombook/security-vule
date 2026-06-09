/**
 * application — L3 漏洞挖掘应用层
 *
 * 数学对代码的同构应用: CPG/扫描器/12 类漏洞规则/GA 校准.
 *
 * 模块:
 *  - scanner          项目扫描器 (scanFile/scanProject/...)
 *  - patterns         12 类漏洞规则 (VULN_PATTERNS)
 *  - dedup            去重 + 置信度过滤
 *  - calibration      GA 校准 (v3 12 维基因空间)
 *  - gnn-classifier   GNN 漏洞分类器
 *  - training-pipeline 训练管道
 *
 * @see docs/REDESIGN.md §2, §3
 */

export * from './patterns.js';
export * from './dedup.js';
export * from './scanner.js';
export * from './matching.js';
export * from './calibration.js';
export * from './gnn-classifier.js';
export * from './training-pipeline.js';
