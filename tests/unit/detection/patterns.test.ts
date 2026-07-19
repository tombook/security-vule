import { describe, test, expect } from 'bun:test';
import {
  ALL_RULES,
  detectPattern,
  getRulesByCategory,
  getRulesBySeverity,
  validateRule,
  type PatternRule,
  type PatternMatch,
  type Severity,
} from '../../../src/detection/patterns.js';

// ============================================================
// 1) pattern 库加载
// ============================================================
describe('patterns: 模式库加载', () => {
  test('ALL_RULES 存在且至少包含 20 条规则', () => {
    expect(Array.isArray(ALL_RULES)).toBe(true);
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(20);
  });

  test('每条规则都包含必需的字段(rule_id / name / description / severity / confidence)', () => {
    for (const rule of ALL_RULES) {
      expect(typeof rule.rule_id).toBe('string');
      expect(rule.rule_id.length).toBeGreaterThan(0);
      expect(typeof rule.name).toBe('string');
      expect(rule.name.length).toBeGreaterThan(0);
      expect(typeof rule.description).toBe('string');
      expect(rule.description.length).toBeGreaterThan(0);
      expect(typeof rule.severity).toBe('string');
      expect(typeof rule.confidence).toBe('number');
      expect(rule.confidence).toBeGreaterThanOrEqual(0);
      expect(rule.confidence).toBeLessThanOrEqual(1);
    }
  });

  test('所有 rule_id 在库内唯一', () => {
    const ids = ALL_RULES.map(r => r.rule_id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});

// ============================================================
// 2) pattern 匹配 —— 不同 CWE 类型
// ============================================================
describe('patterns: 模式匹配 (按 CWE 类型)', () => {
  test('CWE-327: Weak Crypto pattern 能匹配 md5/sha1/des/rc4', () => {
    const samples = [
      'const h = crypto.createHash("md5");',
      'let digest = sha1(input);',
      'Cipher.getInstance("DES");',
      'RC4 cipher suite enabled',
    ];
    for (const code of samples) {
      const matches = detectPattern(code);
      const ids = matches.map(m => m.rule_id);
      expect(ids).toContain('CRYPTO-001');
    }
  });

  test('CWE-798: Hardcoded Credentials pattern 能匹配 password/secret/api_key/token', () => {
    const samples = [
      'const password = "hunter2";',
      'API_KEY = "sk-xxx";',
      'let secret = req.body.secret;',
      'auth_token = "abc";',
    ];
    for (const code of samples) {
      const matches = detectPattern(code);
      const auth002 = matches.find(m => m.rule_id === 'AUTH-002');
      expect(auth002).toBeDefined();
      expect(auth002!.severity).toBe('critical');
      expect(auth002!.cwe).toContain('CWE-798');
    }
  });

  test('CWE-119: Buffer Overflow pattern 能匹配 strcpy/sprintf/gets', () => {
    const code = 'strcpy(buf, user_input);\nsprintf(dst, "%s", src);\ngets(buf);';
    const matches = detectPattern(code);
    const mem001 = matches.find(m => m.rule_id === 'MEM-001');
    expect(mem001).toBeDefined();
    expect(mem001!.cwe).toContain('CWE-119');
    // 至少命中 3 行
    const mem001Hits = matches.filter(m => m.rule_id === 'MEM-001');
    expect(mem001Hits.length).toBeGreaterThanOrEqual(3);
  });

  test('CWE-338: Insecure Random 命中 Math.random', () => {
    const code = 'const nonce = Math.random().toString(36);';
    const matches = detectPattern(code);
    const ids = matches.map(m => m.rule_id);
    expect(ids).toContain('CRYPTO-002');
    const hit = matches.find(m => m.rule_id === 'CRYPTO-002')!;
    expect(hit.cwe).toContain('CWE-338');
  });

  test('CWE-347: JWT 命中 AUTH-005', () => {
    const code = 'const token = jwt.sign(payload, key);';
    const matches = detectPattern(code);
    const ids = matches.map(m => m.rule_id);
    expect(ids).toContain('AUTH-005');
    const hit = matches.find(m => m.rule_id === 'AUTH-005')!;
    expect(hit.cwe).toContain('CWE-347');
  });
});

// ============================================================
// 3) false positive 边界
// ============================================================
describe('patterns: false positive 边界', () => {
  test('完全无敏感关键字的纯计算代码不应产生匹配', () => {
    // 避免使用任何可能被 pattern 子串误中的词(如 positive 中的 "iv")
    const code = [
      'let y = 1;',
      'let z = 2;',
      'let w = y + z;',
    ].join('\n');
    const matches = detectPattern(code);
    expect(matches).toEqual([]);
  });

  test('大小写不敏感的 pattern 不会被同义但不命中词误报', () => {
    // CRYPTO-001 规则使用 /i 标志,验证大小写一致命中
    const code = '// sha256 is fine';
    const matches = detectPattern(code);
    // sha256 不在 CRYPTO-001 的白名单(md5|sha1|des|rc4)内
    const crypto001 = matches.find(m => m.rule_id === 'CRYPTO-001');
    expect(crypto001).toBeUndefined();
  });

  test('空字符串输入不抛异常且返回空数组', () => {
    const matches = detectPattern('');
    expect(matches).toEqual([]);
  });
});

// ============================================================
// 4) severity 字段
// ============================================================
describe('patterns: severity 字段', () => {
  const ALLOWED: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  test('所有规则的 severity 都在合法枚举内', () => {
    for (const rule of ALL_RULES) {
      expect(ALLOWED).toContain(rule.severity);
    }
  });

  test('getRulesBySeverity("critical") 仅返回 critical 规则', () => {
    const criticals = getRulesBySeverity('critical');
    expect(criticals.length).toBeGreaterThan(0);
    for (const rule of criticals) {
      expect(rule.severity).toBe('critical');
    }
  });

  test('getRulesBySeverity("high") 仅返回 high 规则', () => {
    const highs = getRulesBySeverity('high');
    expect(highs.length).toBeGreaterThan(0);
    for (const rule of highs) {
      expect(rule.severity).toBe('high');
    }
  });

  test('detectPattern 返回的匹配项 severity 与对应规则一致', () => {
    const code = 'strcpy(buf, input);';
    const matches = detectPattern(code);
    const mem001 = matches.find(m => m.rule_id === 'MEM-001')!;
    expect(mem001).toBeDefined();
    expect(mem001.severity).toBe('critical');
  });
});

// ============================================================
// 辅助 API: getRulesByCategory / validateRule
// ============================================================
describe('patterns: 辅助 API', () => {
  test('getRulesByCategory("injection") 仅返回 INJ 前缀', () => {
    const inj = getRulesByCategory('injection');
    expect(inj.length).toBeGreaterThan(0);
    for (const r of inj) {
      expect(r.rule_id.startsWith('INJ')).toBe(true);
    }
  });

  test('getRulesByCategory("auth") 仅返回 AUTH 前缀', () => {
    const auth = getRulesByCategory('auth');
    expect(auth.length).toBeGreaterThan(0);
    for (const r of auth) {
      expect(r.rule_id.startsWith('AUTH')).toBe(true);
    }
  });

  test('getRulesByCategory("unknown") 默认走 MEM 分支', () => {
    const mem = getRulesByCategory('something-else');
    for (const r of mem) {
      expect(r.rule_id.startsWith('MEM')).toBe(true);
    }
  });

  test('validateRule 对合法规则返回 valid=true', () => {
    const valid: PatternRule = {
      rule_id: 'TEST-001',
      name: 'Test',
      description: 'desc',
      severity: 'medium',
      confidence: 0.5,
      pattern: /x/,
    };
    const r = validateRule(valid);
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
  });

  test('validateRule 能识别缺失字段与非法 confidence', () => {
    const bad: PatternRule = {
      rule_id: '',
      name: '',
      description: '',
      severity: 'high',
      confidence: 1.5,
    };
    const r = validateRule(bad);
    expect(r.valid).toBe(false);
    expect(r.errors.length).toBeGreaterThanOrEqual(4);
    expect(r.errors).toContain('Missing rule_id');
    expect(r.errors).toContain('Missing name');
    expect(r.errors).toContain('Missing description');
    expect(r.errors).toContain('Confidence must be 0-1');
  });

  test('detectPattern 返回的 location 包含正确的行号(从 1 开始)', () => {
    const code = ['// line1 safe', '// line2 md5', '// line3 safe'].join('\n');
    const matches = detectPattern(code, 'sample.ts');
    const crypto001 = matches.filter(m => m.rule_id === 'CRYPTO-001');
    expect(crypto001.length).toBeGreaterThan(0);
    expect(crypto001[0].location.line).toBe(2);
    expect(crypto001[0].location.file).toBe('sample.ts');
    expect(typeof crypto001[0].location.column).toBe('number');
  });

  test('detectPattern 不修改返回值(每次调用产生新数组)', () => {
    const code = 'md5(x);';
    const a = detectPattern(code);
    const b = detectPattern(code);
    expect(a).not.toBe(b);
    expect(a.length).toBe(b.length);
  });
});