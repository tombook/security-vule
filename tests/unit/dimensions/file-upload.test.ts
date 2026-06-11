/**
 * Tests for FileUploadDimension (SOP v1.0 iteration).
 */
import { describe, expect, test } from 'bun:test';
import { FileUploadDimension } from '../../../src/engine/dimensions/file-upload.js';
import { DIMENSIONS } from '../../../src/engine/dimensions/registry.js';
import type { CPG, CPGNode } from '../../../src/engine/cpg/types.js';

function makeNode(code: string, line = 1): CPGNode {
  return {
    id: `n${line}`,
    type: 'expr',
    file: 'upload.php',
    line,
    col: 0,
    code,
    language: 'php',
    features: {},
  };
}

function makeCpg(nodes: CPGNode[]): CPG {
  return {
    nodes: new Map(nodes.map((n) => [n.id, n])),
    edges: [],
    language: 'php',
    stats: { nodeCount: nodes.length, edgeCount: 0 },
  };
}

describe('FileUploadDimension — registry', () => {
  test('registered in DIMENSIONS', () => {
    expect(DIMENSIONS.fileUpload).toBeDefined();
    expect(DIMENSIONS.fileUpload.name).toBe('fileUpload');
    expect(DIMENSIONS.fileUpload.weight).toBe(0.08);
  });
});

describe('FileUploadDimension — detection', () => {
  const dim = new FileUploadDimension();

  test('detects move_uploaded_file without extension check', () => {
    const node = makeNode(
      '$path = "uploads/" . $_FILES["file"]["name"];\nmove_uploaded_file($_FILES["file"]["tmp_name"], $path);'
    );
    const cpg = makeCpg([node]);
    const score = dim.compute(node, cpg);
    expect(score).toBeGreaterThan(0.5);
    const explain = dim.explain(node, cpg);
    expect(explain).toContain('File upload');
    expect(explain).toContain('no_extension_check');
  });

  test('returns0 for non-upload code', () => {
    const node = makeNode('echo "hello world";');
    const cpg = makeCpg([node]);
    expect(dim.compute(node, cpg)).toBe(0);
  });

  test('detects chmod777 on uploads dir', () => {
    const node = makeNode('chmod("/var/www/uploads",0777);');
    const cpg = makeCpg([node]);
    const score = dim.compute(node, cpg);
    expect(score).toBeGreaterThan(0.3);
    const explain = dim.explain(node, cpg);
    expect(explain).toContain('uploads_dir_writable');
  });

  test('detects double extension risk (shell.php.jpg)', () => {
    const node = makeNode(
      '$name = "shell.php.jpg";\nmove_uploaded_file($_FILES["f"]["tmp_name"], $name);'
    );
    const cpg = makeCpg([node]);
    const score = dim.compute(node, cpg);
    expect(score).toBeGreaterThan(0.3);
    const explain = dim.explain(node, cpg);
    expect(explain).toContain('double_extension_risk');
  });

  test('LLM prompt includes risk explanation', () => {
    const node = makeNode(
      'move_uploaded_file($_FILES["f"]["tmp_name"], "uploads/" . $_FILES["f"]["name"]);'
    );
    const cpg = makeCpg([node]);
    dim.compute(node, cpg);
    const prompt = dim.llmPrompt(node, cpg);
    expect(prompt).toContain('File upload at line');
    expect(prompt).toContain('uploads');
  });
});

describe('FileUploadDimension — runtime check', () => {
  test('runtimeCheck returns mode for existing dir', async () => {
    const dim = new FileUploadDimension();
    const result = await dim.runtimeCheck('/tmp');
    expect(result).toHaveProperty('mode');
    expect(result).toHaveProperty('gid');
  });

  test('runtimeCheck returns ok=false for nonexistent dir', async () => {
    const dim = new FileUploadDimension();
    const result = await dim.runtimeCheck('/nonexistent/path');
    expect(result.ok).toBe(false);
    expect(result.mode).toBe('unknown');
  });
});
