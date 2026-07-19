import { describe, test, expect } from 'bun:test';
import {
  analyzeFile,
  type AnalysisResult,
  type VulnerabilityFinding,
} from '../../../src/engine/analyzer.js';

describe('analyzer: analyzeFile happy path', () => {
  test('analyzes a simple Python file end-to-end', async () => {
    const code = `def greet(name):\n    return "hi " + name\n`;
    const result: AnalysisResult = await analyzeFile('/tmp/sample.py', code, 'python');

    // 顶层结构齐全
    expect(result.filePath).toBe('/tmp/sample.py');
    expect(result.language).toBe('python');
    expect(result.cpg).toBeDefined();
    expect(result.cpg.nodes.size).toBeGreaterThan(0);
    expect(result.metrics).toBeDefined();
    expect(typeof result.duration).toBe('number');
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(result.vulnerabilities)).toBe(true);
    // 简单加法不应触发任何漏洞
    expect(result.vulnerabilities.length).toBe(0);
  });

  test('detects eval sink reached from user input (taint path)', async () => {
    const code = `def run():\n    data = input()\n    eval(data)\n`;
    const result = await analyzeFile('/tmp/eval.py', code, 'python');

    expect(result.taint.isTainted).toBe(true);
    // 至少一条 eval 漏洞
    const evalVuln = result.vulnerabilities.find(v => v.type === 'eval');
    expect(evalVuln).toBeDefined();
    expect(evalVuln!.severity).toBe('CRITICAL');
    expect(evalVuln!.cwe).toBe('CWE-95');
    expect(evalVuln!.line).toBeGreaterThan(0);
    expect(evalVuln!.confidence).toBeGreaterThan(0);
  });

  test('detects weakrand pattern via regex fallback (PHP mt_rand)', async () => {
    const code = `<?php\nmt_rand(1, 100);\n`;
    const result = await analyzeFile('/tmp/rand.php', code, 'php');

    const weakrand = result.vulnerabilities.find(v => v.type === 'weakrand');
    expect(weakrand).toBeDefined();
    expect(weakrand!.cwe).toBe('CWE-330');
    expect(weakrand!.severity).toBe('MEDIUM');
  });
});

describe('analyzer: analyzeFile edge cases', () => {
  test('handles empty source code without throwing', async () => {
    const result = await analyzeFile('/tmp/empty.py', '', 'python');
    expect(result.language).toBe('python');
    expect(result.vulnerabilities.length).toBe(0);
    expect(result.metrics.linesOfCode).toBe(1);
    // 无函数时 dfg 为 null
    expect(result.dfg).toBeNull();
    // CFG 即使对空源码也能构造
    expect(result.cfg).not.toBeNull();
  });

  test('respects explicit language override over extension', async () => {
    // 扩展名是 .py 但显式指定 javascript
    const result = await analyzeFile('/tmp/mismatch.py', 'var x = 1;', 'javascript');
    expect(result.language).toBe('javascript');
  });

  test('auto-detects language from file extension when not specified', async () => {
    const py = await analyzeFile('/tmp/a.py', 'x = 1');
    expect(py.language).toBe('python');

    const rs = await analyzeFile('/tmp/a.rs', 'fn main() {}');
    expect(rs.language).toBe('rust');

    const java = await analyzeFile('/tmp/A.java', 'class A {}');
    expect(java.language).toBe('java');
  });
});

describe('analyzer: error path / robustness', () => {
  test('survives severely malformed source code', async () => {
    // 解析器应当兜底,即使源码不合法也不抛异常
    const malformed = '@@@ !!! not valid code @@@ )))}}}';
    const result = await analyzeFile('/tmp/bad.py', malformed, 'python');
    expect(result).toBeDefined();
    expect(result.language).toBe('python');
    expect(Array.isArray(result.vulnerabilities)).toBe(true);
  });

  test('returns well-formed VulnerabilityFinding shape', async () => {
    const code = `def run():\n    data = input()\n    eval(data)\n`;
    const result = await analyzeFile('/tmp/shape.py', code, 'python');
    const v: VulnerabilityFinding = result.vulnerabilities[0];

    // 字段存在且类型正确
    expect(typeof v.id).toBe('string');
    expect(v.id.startsWith('VULN-')).toBe(true);
    expect(typeof v.type).toBe('string');
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(v.severity);
    expect(typeof v.title).toBe('string');
    expect(typeof v.description).toBe('string');
    expect(v.file).toBe('/tmp/shape.py');
    expect(typeof v.line).toBe('number');
    expect(typeof v.confidence).toBe('number');
  });

  test('dedup collapses same (file, type) to single finding', async () => {
    // 同一文件多次命中同一弱模式 (例如多行 echo $_GET) 应被去重
    const code = `<?php\necho "a" . $_GET["a"];\necho "b" . $_GET["b"];\necho "c" . $_GET["c"];\n`;
    const result = await analyzeFile('/tmp/dedup.php', code, 'php');
    const xss = result.vulnerabilities.filter(v => v.type === 'xss');
    // 不论命中多少行,去重后只保留 1 条 (file, type) 维度
    expect(xss.length).toBeLessThanOrEqual(1);
  });
});
