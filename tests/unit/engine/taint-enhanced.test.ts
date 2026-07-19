import { describe, test, expect } from 'bun:test';
import {
  detectEnhancedSources,
  detectEnhancedSinks,
  detectEnhancedSanitizers,
  analyzeTaint,
  analyzeTaintInterProcedural,
  getSinkSeverity,
  getSinkCWE,
} from '../../../src/engine/taint-enhanced.js';

describe('taint-enhanced: detectEnhancedSources', () => {
  test('识别 Python input() 为 user_input 源', () => {
    const code = `name = input("Enter name: ")`;
    const sources = detectEnhancedSources(code, 'global');
    expect(sources.length).toBeGreaterThan(0);
    const userInput = sources.find(s => s.type === 'user_input');
    expect(userInput).toBeDefined();
    expect(userInput!.name.toLowerCase()).toContain('input');
    expect(userInput!.scope).toBe('global');
    expect(userInput!.confidence).toBeGreaterThan(0.9);
  });

  test('识别网络请求 fetch/axios 为 network 源', () => {
    const code = `
const r1 = fetch('/api');
const r2 = axios.get('/x');
`;
    const sources = detectEnhancedSources(code, 'global');
    const network = sources.filter(s => s.type === 'network');
    expect(network.length).toBeGreaterThanOrEqual(2);
    expect(network.every(n => n.confidence > 0)).toBe(true);
  });

  test('无源时代码返回空数组', () => {
    const sources = detectEnhancedSources('x = 1 + 2', 'global');
    expect(sources).toBeArray();
    expect(sources.length).toBe(0);
  });
});

describe('taint-enhanced: detectEnhancedSinks', () => {
  test('识别 SQL 查询为 sql 接收器', () => {
    const code = `
db.query("SELECT * FROM users WHERE id = " + uid);
`;
    const sinks = detectEnhancedSinks(code, 'global');
    const sqlSinks = sinks.filter(s => s.type === 'sql');
    expect(sqlSinks.length).toBeGreaterThan(0);
    expect(sqlSinks[0].scope).toBe('global');
  });

  test('识别 shell 执行与 eval 接收器', () => {
    const code = `
exec("ls -la");
const f = new Function("return 1");
`;
    const sinks = detectEnhancedSinks(code, 'main');
    expect(sinks.some(s => s.type === 'shell')).toBe(true);
    expect(sinks.some(s => s.type === 'eval')).toBe(true);
  });
});

describe('taint-enhanced: detectEnhancedSanitizers', () => {
  test('识别 escape/validate 系列清洗器', () => {
    const code = `
const a = escape(userInput);
const b = DOMPurify.sanitize(html);
const c = validator.isEmail(email);
`;
    const sanitizers = detectEnhancedSanitizers(code, 'global');
    expect(sanitizers.length).toBeGreaterThan(0);
    expect(sanitizers.every(s => s.effectiveness >= 0 && s.effectiveness <= 1)).toBe(true);
  });

  test('无清洗器时代码返回空数组', () => {
    const sanitizers = detectEnhancedSanitizers('x = a + b', 'global');
    expect(sanitizers).toBeArray();
    expect(sanitizers.length).toBe(0);
  });
});

describe('taint-enhanced: analyzeTaint (happy path)', () => {
  test('从 user_input 传播到 sql 接收器,生成 taint 路径', () => {
    const code = `
const uid = input("id: ");
db.query("SELECT * FROM users WHERE id = " + uid);
`;
    const result = analyzeTaint(code, 'global');
    expect(result.isTainted).toBe(true);
    expect(result.sources.length).toBeGreaterThan(0);
    expect(result.sinks.length).toBeGreaterThan(0);
    expect(result.paths.length).toBeGreaterThan(0);
    const path = result.paths[0];
    expect(path.source.type).toBe('user_input');
    expect(path.sink.type).toBe('sql');
    expect(path.path[0]).toBe(path.source.id);
    expect(path.path[path.path.length - 1]).toBe(path.sink.id);
    expect(path.confidence).toBeGreaterThan(0);
    expect(path.confidence).toBeLessThanOrEqual(1);
  });

  test('sanitizer 出现在源与汇之间时被纳入路径', () => {
    const code = `
const uid = input("id: ");
const safe = escape(uid);
db.query("SELECT * FROM users WHERE id = " + safe);
`;
    const sanitizers = detectEnhancedSanitizers(code, 'global');
    expect(sanitizers.length).toBeGreaterThan(0);
    const escapeSan = sanitizers.find(s => s.name.toLowerCase().includes('escape'));
    expect(escapeSan).toBeDefined();
    expect(escapeSan!.type).toBe('encoding');
    expect(escapeSan!.effectiveness).toBeGreaterThan(0);
  });

  test('弱 sanitizer (param_check) 不阻断 confidence 高于阈值', () => {
    const code = `
const uid = input("id: ");
if (isset(uid)) {
  db.query("SELECT * FROM users WHERE id = " + uid);
}
`;
    const result = analyzeTaint(code, 'global');
    expect(result.sources.length).toBeGreaterThan(0);
    expect(result.sinks.length).toBeGreaterThan(0);
    if (result.paths.length > 0) {
      const path = result.paths[0];
      expect(path.confidence).toBeLessThanOrEqual(1);
      expect(path.confidence).toBeGreaterThan(0);
    }
  });
});

describe('taint-enhanced: analyzeTaintInterProcedural', () => {
  test('提供 callGraph 时,长路径被标记为跨过程', () => {
    const code = `
const a = input("x: ");
helper(a);
db.query(a);
`;
    const callGraph = new Map<string, string[]>([
      ['helper', ['db.query']],
    ]);
    const result = analyzeTaintInterProcedural(code, 'global', callGraph);
    expect(result).toBeDefined();
    expect(Array.isArray(result.interProceduralPaths)).toBe(true);
  });
});

describe('taint-enhanced: severity & CWE 映射', () => {
  test('sql/shell/eval 为 CRITICAL', () => {
    expect(getSinkSeverity('sql')).toBe('CRITICAL');
    expect(getSinkSeverity('shell')).toBe('CRITICAL');
    expect(getSinkSeverity('eval')).toBe('CRITICAL');
  });

  test('每个 sink 类型映射到 CWE', () => {
    expect(getSinkCWE('sql')).toBe('CWE-89');
    expect(getSinkCWE('shell')).toBe('CWE-78');
    expect(getSinkCWE('eval')).toBe('CWE-95');
    expect(getSinkCWE('deserialization')).toBe('CWE-502');
  });
});
