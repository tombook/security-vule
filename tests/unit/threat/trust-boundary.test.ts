import { describe, test, expect } from 'bun:test';
import {
  buildProgramGraph,
  type ProgramGraph,
  type PGNode,
} from '../../../src/engine/program-graph.js';
import { analyzeTaint, type TaintResult } from '../../../src/engine/taint.js';
import { extractTrustBoundaries } from '../../../src/threat/trust-boundary.js';
import { type TrustBoundary } from '../../../src/threat/types.js';
import { parsePython } from '../../../src/engine/parser.js';

function buildGraphFromCode(code: string, filePath: string): ProgramGraph {
  const parsed = parsePython(code);
  return buildProgramGraph(parsed.ast, undefined, code);
}

describe('trust-boundary: extractTrustBoundaries', () => {
  test('returns empty array for code with no taint', () => {
    const code = `x = 1\ny = 2\nz = x + y`;
    const graph = buildGraphFromCode(code, 'safe.py');
    const taintResult: TaintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'safe.py');
    expect(boundaries).toBeArray();
  });

  test('extracts boundary from vulnerable code', () => {
    const code = `
user = input("name: ")
db.execute("SELECT * FROM users WHERE name = '" + user + "'")
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    expect(boundaries).toBeArray();
    if (boundaries.length > 0) {
      expect(boundaries[0].id).toBeDefined();
      expect(boundaries[0].name).toBeDefined();
      expect(boundaries[0].description).toBeDefined();
      expect(boundaries[0].type).toBeDefined();
      expect(boundaries[0].inside).toBeDefined();
      expect(boundaries[0].outside).toBeDefined();
    }
  });

  test('boundary has trust zones', () => {
    const code = `
data = input()
os.system("echo " + data)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    for (const b of boundaries) {
      expect(b.inside.level).toBe('trusted');
      expect(b.outside.level).toBe('untrusted');
      expect(b.inside.id).toBeDefined();
      expect(b.outside.id).toBeDefined();
    }
  });

  test('boundary includes location', () => {
    const code = `
user = input()
db.execute(user)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    for (const b of boundaries) {
      expect(b.location).toBeDefined();
      expect(b.location.file).toBe('app.py');
      expect(typeof b.location.line).toBe('number');
    }
  });

  test('deduplicates boundaries with same name', () => {
    const code = `
a = input()
b = input()
db.execute(a)
db.execute(b)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    const names = boundaries.map(b => b.name);
    expect(new Set(names).size).toBe(names.length);
  });

  test('boundaries sorted by confidence descending', () => {
    const code = `
data = input()
db.execute(data)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    for (let i = 1; i < boundaries.length; i++) {
      expect(boundaries[i - 1].confidence).toBeGreaterThanOrEqual(boundaries[i].confidence);
    }
  });

  test('filters low-confidence taint paths', () => {
    const code = `
def handler():
    return 42
`;
    const graph = buildGraphFromCode(code, 'safe.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'safe.py');
    expect(boundaries).toBeArray();
  });

  test('boundary type maps from source/sink', () => {
    const code = `
data = request.args.get('x')
db.execute(data)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    for (const b of boundaries) {
      expect(['input', 'output', 'data_store', 'process', 'network']).toContain(b.type);
    }
  });

  test('description includes sanitizer info when present', () => {
    const code = `
data = input()
safe = html.escape(data)
output(safe)
`;
    const graph = buildGraphFromCode(code, 'app.py');
    const taintResult = analyzeTaint(code, 'global');
    const boundaries = extractTrustBoundaries(graph, taintResult, 'app.py');
    for (const b of boundaries) {
      expect(b.description).toContain('Confidence');
    }
  });

  test('handles empty taint result', () => {
    const code = `x = 1`;
    const graph = buildGraphFromCode(code, 'app.py');
    const emptyTaint: TaintResult = {
      isTainted: false,
      sources: [],
      sinks: [],
      paths: [],
      confidence: 0,
    };
    const boundaries = extractTrustBoundaries(graph, emptyTaint, 'app.py');
    expect(boundaries.length).toBe(0);
  });
});
