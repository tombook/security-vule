import { describe, it, expect } from 'bun:test';

describe('MCP Server Module', () => {
  it('exports MCPServer class and runMCP function', async () => {
    const mod = await import('../../../src/mcp/server.js');
    expect(mod.MCPServer).toBeDefined();
    expect(typeof mod.MCPServer).toBe('function');
    expect(mod.runMCP).toBeDefined();
    expect(typeof mod.runMCP).toBe('function');
  });

  it('MCPServer can be instantiated', async () => {
    const { MCPServer } = await import('../../../src/mcp/server.js');
    const server = new MCPServer();
    expect(server).toBeDefined();
  });
});
