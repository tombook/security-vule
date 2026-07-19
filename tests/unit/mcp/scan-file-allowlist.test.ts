import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { tmpdir } from 'os';
import { join } from 'path';
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from 'fs';

describe('MCP scan_file path allowlist', () => {
  let allowedDir: string;

  beforeEach(() => {
    allowedDir = mkdtempSync(join(tmpdir(), 'mcp-allow-'));
    process.env.MCP_ALLOWED_DIRS = allowedDir;
    process.env.MCP_MAX_FILE_SIZE_MB = '10';
  });

  afterEach(() => {
    rmSync(allowedDir, { recursive: true, force: true });
    delete process.env.MCP_ALLOWED_DIRS;
    delete process.env.MCP_MAX_FILE_SIZE_MB;
  });

  it('rejects path outside allowlist', async () => {
    const { isPathAllowed } = await import('../../../src/mcp/security.js');
    expect(isPathAllowed('/etc/hosts', [allowedDir])).toBe(false);
  });

  it('accepts path inside allowlist', async () => {
    const { isPathAllowed } = await import('../../../src/mcp/security.js');
    const f = join(allowedDir, 'test.js');
    writeFileSync(f, 'x');
    expect(isPathAllowed(f, [allowedDir])).toBe(true);
  });

  it('rejects symlinks pointing outside allowlist', async () => {
    const { isPathAllowed } = await import('../../../src/mcp/security.js');
    const outsideDir = mkdtempSync(join(tmpdir(), 'mcp-outside-'));
    const outsideFile = join(outsideDir, 'secret.txt');
    writeFileSync(outsideFile, 'secret');
    const link = join(allowedDir, 'evil');
    let symlinkCreated = false;
    try {
      symlinkSync(outsideFile, link);
      symlinkCreated = true;
    } catch {
      symlinkCreated = false;
    }
    if (symlinkCreated) {
      expect(isPathAllowed(link, [allowedDir])).toBe(false);
    }
    rmSync(outsideDir, { recursive: true, force: true });
  });

  it('rejects when allowlist is empty', async () => {
    const { isPathAllowed } = await import('../../../src/mcp/security.js');
    expect(isPathAllowed(join(allowedDir, 'foo.js'), [])).toBe(false);
  });
});

describe('MCP file size check', () => {
  it('throws when file exceeds max size', async () => {
    const { checkFileSize } = await import('../../../src/mcp/security.js');
    expect(() => checkFileSize(2 * 1024 * 1024, 1)).toThrow(/exceeds|size/i);
    expect(() => checkFileSize(1024, 1)).not.toThrow();
  });
});
