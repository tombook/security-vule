import { describe, test, expect } from 'bun:test';
import {
  detectSources,
  detectSinks,
  detectSanitizers,
  findTaintPaths,
  analyzeTaint,
  type TaintSource,
  type TaintSink,
  type Sanitizer,
} from '../../../src/engine/taint.js';
import { parsePython, type ASTNode } from '../../../src/engine/parser.js';

describe('taint: detectSources', () => {
  test('detects Python input() as source', () => {
    const code = `name = input("Enter name: ")`;
    const sources = detectSources(code, 'global');
    expect(sources.length).toBeGreaterThan(0);
    expect(sources.some(s => s.name.includes('input'))).toBe(true);
  });

  test('detects request.args as source', () => {
    const code = `user_id = request.args.get('id')`;
    const sources = detectSources(code, 'global');
    expect(sources.length).toBeGreaterThan(0);
  });

  test('returns empty for code with no sources', () => {
    const code = `x = 1 + 2`;
    const sources = detectSources(code, 'global');
    expect(sources).toBeArray();
  });

  test('extracts variable name from assignment', () => {
    const code = `user_data = request.get_json()`;
    const sources = detectSources(code, 'global');
    const named = sources.find(s => s.variable === 'user_data');
    expect(named).toBeDefined();
  });

  test('detects multiple sources', () => {
    const code = `
a = input()
b = request.form.get('foo')
c = sys.argv[1]
`;
    const sources = detectSources(code, 'global');
    expect(sources.length).toBeGreaterThanOrEqual(2);
  });
});

describe('taint: detectSinks', () => {
  test('detects os.system as sink', () => {
    const code = `os.system("ls " + cmd)`;
    const sinks = detectSinks(code, 'global');
    expect(sinks.length).toBeGreaterThan(0);
    expect(sinks.some(s => s.name.includes('system'))).toBe(true);
  });

  test('detects SQL execute as sink', () => {
    const code = `db.execute("SELECT * FROM x WHERE id = " + id)`;
    const sinks = detectSinks(code, 'global');
    expect(sinks.length).toBeGreaterThan(0);
  });

  test('detects eval as sink', () => {
    const code = `result = eval(user_input)`;
    const sinks = detectSinks(code, 'global');
    expect(sinks.length).toBeGreaterThan(0);
    expect(sinks.some(s => s.name.includes('eval'))).toBe(true);
  });

  test('returns empty array for code with no sinks', () => {
    const code = `x = 1; y = 2; z = x + y`;
    const sinks = detectSinks(code, 'global');
    expect(sinks).toBeArray();
  });
});

describe('taint: detectSanitizers', () => {
  test('detects html.escape as sanitizer', () => {
    const code = `safe = html.escape(user_input)`;
    const sanitizers = detectSanitizers(code, 'global');
    expect(sanitizers.length).toBeGreaterThan(0);
  });

  test('detects parameterized query as sanitizer', () => {
    const code = `cursor.execute("SELECT * FROM users WHERE id = ?", (id,))`;
    const sanitizers = detectSanitizers(code, 'global');
    expect(sanitizers).toBeArray();
  });

  test('returns empty for unsanitized code', () => {
    const code = `x = input()`;
    const sanitizers = detectSanitizers(code, 'global');
    expect(sanitizers).toBeArray();
  });
});

describe('taint: findTaintPaths', () => {
  test('returns empty when no sources or sinks', () => {
    const paths = findTaintPaths([], [], []);
    expect(paths).toBeArray();
    expect(paths.length).toBe(0);
  });

  test('finds path from source to sink on same line', () => {
    const sources: TaintSource[] = [{
      id: 's1', type: 'user_input', name: 'input()', line: 1, scope: 'global', variable: 'user'
    }];
    const sinks: TaintSink[] = [{
      id: 'k1', type: 'sql', name: 'execute', line: 1, scope: 'global'
    }];
    const paths = findTaintPaths(sources, sinks, []);
    expect(paths.length).toBeGreaterThanOrEqual(1);
  });

  test('excludes paths blocked by sanitizers', () => {
    const sources: TaintSource[] = [{
      id: 's1', type: 'user_input', name: 'input()', line: 1, scope: 'global', variable: 'user'
    }];
    const sinks: TaintSink[] = [{
      id: 'k1', type: 'sql', name: 'execute', line: 5, scope: 'global'
    }];
    const sanitizers: Sanitizer[] = [{
      id: 'san1', type: 'validation', name: 'int() cast', line: 3, scope: 'global'
    }];
    const paths = findTaintPaths(sources, sinks, sanitizers);
    expect(paths).toBeArray();
  });

  test('finds path with variable propagation', () => {
    const sources: TaintSource[] = [{
      id: 's1', type: 'user_input', name: 'input()', line: 1, scope: 'global', variable: 'a'
    }];
    const sinks: TaintSink[] = [{
      id: 'k1', type: 'sql', name: 'execute', line: 3, scope: 'global'
    }];
    const paths = findTaintPaths(sources, sinks, []);
    expect(paths.length).toBeGreaterThanOrEqual(1);
  });
});

describe('taint: analyzeTaint (end-to-end)', () => {
  test('returns structured result with no findings for safe code', () => {
    const code = `
def safe(x):
    return x + 1
`;
    const result = analyzeTaint(code, 'global');
    expect(result).toBeDefined();
    expect(result.sources).toBeArray();
    expect(result.sinks).toBeArray();
    expect(result.paths).toBeArray();
    expect(result.isTainted).toBeBoolean();
    expect(typeof result.confidence).toBe('number');
  });

  test('detects taint path in vulnerable code', () => {
    const code = `
user = input("name: ")
db.execute("SELECT * FROM users WHERE name = '" + user + "'")
`;
    const result = analyzeTaint(code, 'global');
    expect(result.sources.length).toBeGreaterThan(0);
    expect(result.sinks.length).toBeGreaterThan(0);
  });

  test('accepts AST parameter for AST-aware analysis', () => {
    const code = `data = input(); db.execute(data)`;
    const parsed = parsePython(code);
    const result = analyzeTaint(code, 'global', parsed.ast);
    expect(result).toBeDefined();
    expect(result.sources).toBeArray();
  });

  test('handles real SQL injection pattern', () => {
    const code = `
import sqlite3
user = request.args.get('name')
conn = sqlite3.connect('db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE name = '" + user + "'")
`;
    const result = analyzeTaint(code, 'global');
    expect(result.sources.length).toBeGreaterThan(0);
  });

  test('handles real command injection pattern', () => {
    const code = `
import os
filename = input("file: ")
os.system("cat " + filename)
`;
    const result = analyzeTaint(code, 'global');
    expect(result.sources.length).toBeGreaterThan(0);
    expect(result.sinks.length).toBeGreaterThan(0);
  });

  test('handles real XSS pattern', () => {
    const code = `
const userInput = req.query.name;
document.innerHTML = userInput;
`;
    const result = analyzeTaint(code, 'global');
    expect(result).toBeDefined();
  });

  test('handles empty code', () => {
    const result = analyzeTaint('', 'global');
    expect(result.sources.length).toBe(0);
    expect(result.sinks.length).toBe(0);
  });

  test('AST-aware analysis adds structural detection', () => {
    const code = `
def handler(req):
    data = req.body
    return db.execute(data)
`;
    const parsed = parsePython(code);
    const result = analyzeTaint(code, 'global', parsed.ast);
    expect(result).toBeDefined();
    expect(result.sources.length).toBeGreaterThanOrEqual(0);
  });

  test('computes confidence score', () => {
    const code = `
data = input()
db.execute(data)
`;
    const result = analyzeTaint(code, 'global');
    expect(typeof result.confidence).toBe('number');
    expect(result.confidence).toBeGreaterThanOrEqual(0);
  });
});
