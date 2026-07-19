import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

describe('MCP Authentication', () => {
  beforeEach(() => {
    process.env.MCP_SHARED_SECRET = 'test-secret-12345';
  });
  afterEach(() => {
    delete process.env.MCP_SHARED_SECRET;
  });

  it('verifyAuth returns true on match', async () => {
    const { verifyAuth } = await import('../../../src/mcp/security.js');
    expect(verifyAuth('test-secret-12345', 'test-secret-12345')).toBe(true);
  });

  it('verifyAuth returns false on mismatch', async () => {
    const { verifyAuth } = await import('../../../src/mcp/security.js');
    expect(verifyAuth('test-secret-12345', 'wrong')).toBe(false);
  });

  it('verifyAuth returns false on undefined inputs', async () => {
    const { verifyAuth } = await import('../../../src/mcp/security.js');
    expect(verifyAuth(undefined, 'secret')).toBe(false);
    expect(verifyAuth('secret', undefined)).toBe(false);
  });

  it('verifyAuth rejects different length inputs', async () => {
    const { verifyAuth } = await import('../../../src/mcp/security.js');
    expect(verifyAuth('a', 'ab')).toBe(false);
  });
});
