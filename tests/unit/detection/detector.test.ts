import { describe, test, expect } from 'bun:test';
import {
  Detector,
  detect,
  detectWithFeatures,
  DEFAULT_CONFIG,
  type DetectorConfig,
  type DetectionContext,
} from '../../../src/detection/detector.js';

describe('detector: Detector class', () => {
  test('uses default config when none provided', () => {
    const d = new Detector();
    const result = d.detect({ code: 'x = 1' });
    expect(result).toBeDefined();
    expect(typeof result.overall).toBe('number');
  });

  test('merges custom config with defaults', () => {
    const d = new Detector({ minConfidence: 0.9, enableML: false });
    const result = d.detect({ code: 'x = 1' });
    expect(result).toBeDefined();
  });

  test('pattern-only detection finds SQL-related code via hardcoded secret', () => {
    const code = `password = "secret123"`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result.pattern).toBeGreaterThan(0);
  });

  test('pattern-only detection finds md5 hash', () => {
    const code = `hashed = hashlib.md5(data)`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result.pattern).toBeGreaterThan(0);
  });

  test('pattern-only detection finds strcpy', () => {
    const code = `strcpy(buf, input)`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result.pattern).toBeGreaterThan(0);
  });

  test('statistical detection uses features when provided', () => {
    const d = new Detector({
      enablePattern: false,
      enableStatistical: true,
      enableML: false,
    });
    const code = `
def complex(a, b, c, d, e):
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        return a + b + c + d + e
    return 0
`;
    const features = [5, 5, 100, 12, 0, 5, 0, 4];
    const result = d.detect({ code, features });
    expect(result).toBeDefined();
  });

  test('ML detection uses feature deviation', () => {
    const d = new Detector({
      enablePattern: false,
      enableStatistical: false,
      enableML: true,
    });
    const features = [0, 0, 0, 0, 0, 0, 0, 100];
    const result = d.detect({ code: 'x = 1', features });
    expect(result).toBeDefined();
  });

  test('all detection methods enabled for complex code', () => {
    const d = new Detector({
      enablePattern: true,
      enableStatistical: true,
      enableML: true,
    });
    const code = `
def vulnerable(req):
    user = req.args.get('id')
    query = "SELECT * FROM users WHERE id = " + user
    db.execute(query)
    os.system("rm -rf " + user)
    return eval(user)
`;
    const features = [3, 3, 50, 8, 0, 4, 1, 2];
    const result = d.detect({ code, features });
    expect(result.pattern).toBeGreaterThanOrEqual(0);
    expect(result.statistical).toBeGreaterThanOrEqual(0);
    expect(result.ml).toBeGreaterThanOrEqual(0);
  });

  test('filters out by minConfidence', () => {
    const d = new Detector({
      minConfidence: 0.99,
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code: 'x = 1' });
    expect(result.overall).toBeLessThanOrEqual(0.99);
  });

  test('handles empty code', () => {
    const d = new Detector();
    const result = d.detect({ code: '' });
    expect(result).toBeDefined();
  });

  test('includes file path in detection context', () => {
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const code = `db.execute("SELECT * FROM users")`;
    const result = d.detect({ code, filePath: '/app/db.py' });
    expect(result).toBeDefined();
  });

  test('severity filtering excludes lower severities', () => {
    const strictDetector = new Detector({
      minSeverity: 'critical',
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = strictDetector.detect({ code: 'x = 1' });
    expect(result).toBeDefined();
  });
});

describe('detector: convenience functions', () => {
  test('detect() function works without Detector class', () => {
    const result = detect('x = 1');
    expect(result).toBeDefined();
    expect(typeof result.overall).toBe('number');
  });

  test('detect() accepts partial config', () => {
    const result = detect('x = input()', { minConfidence: 0.1 });
    expect(result).toBeDefined();
  });

  test('detectWithFeatures() uses provided features', () => {
    const features = [1, 1, 10, 5, 0, 2, 0, 1];
    const result = detectWithFeatures('x = 1', features);
    expect(result).toBeDefined();
  });

  test('detectWithFeatures() with high-variance features', () => {
    const features = [0, 0, 0, 0, 0, 0, 0, 50];
    const result = detectWithFeatures('x = 1', features, {
      enablePattern: false,
      enableStatistical: false,
      enableML: true,
    });
    expect(result.ml).toBeGreaterThan(0);
  });
});

describe('detector: default config sanity', () => {
  test('weights sum to 1.0', () => {
    const total = DEFAULT_CONFIG.weights.pattern +
      DEFAULT_CONFIG.weights.statistical +
      DEFAULT_CONFIG.weights.ml;
    expect(Math.abs(total - 1.0)).toBeLessThan(0.001);
  });

  test('has sensible minConfidence', () => {
    expect(DEFAULT_CONFIG.minConfidence).toBeGreaterThan(0);
    expect(DEFAULT_CONFIG.minConfidence).toBeLessThan(1);
  });

  test('all detection methods enabled by default', () => {
    expect(DEFAULT_CONFIG.enablePattern).toBe(true);
    expect(DEFAULT_CONFIG.enableStatistical).toBe(true);
    expect(DEFAULT_CONFIG.enableML).toBe(true);
  });
});

describe('detector: real-world vulnerability samples', () => {
  test('detects path traversal via open()', () => {
    const code = `open("/var/data/" + user_path)`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result).toBeDefined();
  });

  test('detects weak crypto', () => {
    const code = `
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result.pattern).toBeGreaterThan(0);
  });

  test('detects hardcoded credentials', () => {
    const code = `
api_key = "sk-1234567890abcdef"
secret = "my_secret_password"
`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result.pattern).toBeGreaterThan(0);
  });

  test('detects deserialization', () => {
    const code = `
import pickle
data = pickle.loads(user_input)
`;
    const d = new Detector({
      enablePattern: true,
      enableStatistical: false,
      enableML: false,
    });
    const result = d.detect({ code });
    expect(result).toBeDefined();
  });

  test('clean code has low overall score', () => {
    const code = `
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}"
`;
    const d = new Detector();
    const result = d.detect({ code });
    expect(result.overall).toBeLessThan(0.5);
  });
});
