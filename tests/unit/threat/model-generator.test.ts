import { describe, test, expect } from 'bun:test';
import {
  buildProgramGraph,
  type ProgramGraph,
} from '../../../src/engine/program-graph.js';
import { analyzeTaint, type TaintResult } from '../../../src/engine/taint.js';
import { generateThreatModel } from '../../../src/threat/model-generator.js';
import { parsePython } from '../../../src/engine/parser.js';

function buildInputs(code: string, filePath: string): { graph: ProgramGraph; taint: TaintResult } {
  const parsed = parsePython(code);
  const graph = buildProgramGraph(parsed.ast, undefined, code);
  const taint = analyzeTaint(code, 'global');
  return { graph, taint };
}

describe('model-generator: generateThreatModel', () => {
  test('generates threat model for safe code', () => {
    const code = `x = 1\ny = 2\nz = x + y`;
    const { graph, taint } = buildInputs(code, 'safe.py');
    const model = generateThreatModel(graph, taint, 'safe.py');
    expect(model).toBeDefined();
    expect(model.id).toBeDefined();
    expect(model.scope).toBe('safe.py');
    expect(model.method).toBe('auto_graph');
  });

  test('model includes trust boundaries', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.trustBoundaries).toBeArray();
  });

  test('model includes attack surfaces', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.attackSurfaces).toBeArray();
  });

  test('model includes threats', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.threats).toBeArray();
  });

  test('model includes graph stats', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.graphStats!).toBeDefined();
    expect(typeof model.graphStats!.nodeCount).toBe('number');
  });

  test('generates threats for vulnerable code', () => {
    const code = `
user = input("name: ")
db.execute("SELECT * FROM users WHERE name = '" + user + "'")
`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model).toBeDefined();
    expect(model.threats).toBeArray();
  });

  test('STRIDE coverage is computed', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.strideCoverage).toBeDefined();
  });

  test('risk assessment is computed', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const model = generateThreatModel(graph, taint, 'app.py');
    expect(model.riskAssessment).toBeDefined();
  });

  test('timestamp is set', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const before = Date.now();
    const model = generateThreatModel(graph, taint, 'app.py');
    const after = Date.now();
    expect(model.timestamp).toBeGreaterThanOrEqual(before);
    expect(model.timestamp).toBeLessThanOrEqual(after);
  });

  test('id is unique across multiple calls', () => {
    const code = `x = 1`;
    const { graph, taint } = buildInputs(code, 'app.py');
    const m1 = generateThreatModel(graph, taint, 'app.py');
    const m2 = generateThreatModel(graph, taint, 'app.py');
    expect(m1.id).not.toBe(m2.id);
  });
});
