import { describe, it, expect } from 'bun:test';
import { LineLocator, locateLines, type FunctionDetection } from '../../../src/detection/line-locator.js';

describe('LineLocator', () => {
  it('locates SQL injection to the correct line', () => {
    const locator = new LineLocator();
    const code = [
      'app.get("/user", (req, res) => {',
      '  const query = "SELECT * FROM users WHERE id = " + req.params.id;',
      '  db.query(query, (err, result) => {',
      '    res.json(result);',
      '  });',
      '});',
    ].join('\n');

    const detection: FunctionDetection = {
      ruleId: 'INJ-001',
      name: 'SQL Injection',
      severity: 'critical',
      confidence: 0.9,
      startLine: 1,
      endLine: 6,
      cwe: ['CWE-89'],
      message: 'SQL injection',
    };

    const location = locator.locate(detection, code, 'test.js');
    expect(location).not.toBeNull();
    expect(location!.startLine).toBeLessThanOrEqual(3);
    expect(location!.endLine).toBeGreaterThanOrEqual(2);
    expect(location!.confidence).toBeGreaterThan(0);
  });

  it('locates command injection via sink keywords', () => {
    const locator = new LineLocator();
    const code = [
      'function ping(host) {',
      '  exec("ping " + host, callback);',
      '  return result;',
      '}',
    ].join('\n');

    const detection: FunctionDetection = {
      ruleId: 'INJ-002',
      name: 'Command Injection',
      severity: 'critical',
      confidence: 0.95,
      startLine: 1,
      endLine: 4,
      cwe: ['CWE-78'],
      message: 'Command injection',
    };

    const location = locator.locate(detection, code);
    expect(location).not.toBeNull();
    expect(location!.startLine).toBeLessThanOrEqual(2);
    expect(location!.reason).toContain('keyword');
  });

  it('locates hardcoded credentials', () => {
    const locator = new LineLocator();
    const code = [
      'const API_KEY = "sk-abc123";',
      'function connect() {',
      '  return db.connect(API_KEY);',
      '}',
    ].join('\n');

    const detection: FunctionDetection = {
      ruleId: 'AUTH-002',
      name: 'Hardcoded Credentials',
      severity: 'critical',
      confidence: 0.95,
      startLine: 1,
      endLine: 4,
      cwe: ['CWE-798'],
      message: 'Hardcoded credentials',
    };

    const location = locator.locate(detection, code);
    expect(location).not.toBeNull();
    expect(location!.startLine).toBeLessThanOrEqual(2);
  });

  it('falls back to function range when no precise match', () => {
    const locator = new LineLocator();
    const code = 'function safe() { return 42; }';

    const detection: FunctionDetection = {
      ruleId: 'CUSTOM-001',
      name: 'Unknown Issue',
      severity: 'medium',
      confidence: 0.5,
      startLine: 1,
      endLine: 1,
      message: 'Something odd',
    };

    const location = locator.locate(detection, code);
    expect(location).not.toBeNull();
    expect(location!.confidence).toBeLessThan(detection.confidence);
  });

  it('locateBatch processes multiple detections', () => {
    const locator = new LineLocator();
    const code = [
      'const password = "hardcoded";',
      'db.query("SELECT * FROM " + table);',
    ].join('\n');

    const detections: FunctionDetection[] = [
      { ruleId: 'AUTH-002', name: 'Hardcoded Credentials', severity: 'critical', confidence: 0.95, startLine: 1, endLine: 2, cwe: ['CWE-798'], message: 'Hardcoded' },
      { ruleId: 'INJ-001', name: 'SQL Injection', severity: 'critical', confidence: 0.9, startLine: 1, endLine: 2, cwe: ['CWE-89'], message: 'SQLi' },
    ];

    const results = locator.locateBatch(detections, code, 'test.js');
    expect(results.length).toBe(2);
    expect(results.every(r => r.lineLocation !== null)).toBe(true);
  });
});
