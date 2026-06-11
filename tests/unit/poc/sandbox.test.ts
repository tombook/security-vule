/**
 * Tests for PocSandbox — uses a local Bun.serve mock target (no Docker needed).
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PocSandbox, TARGETS } from '../../../src/poc/sandbox.js';

let mockServer: ReturnType<typeof Bun.serve> | null = null;
const MOCK_PORT = 19234;

beforeAll(() => {
  mockServer = Bun.serve({
    port: MOCK_PORT,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === '/login.php') {
        return new Response('Welcome admin', {
          status: 302,
          headers: { 'set-cookie': 'PHPSESSID=testcookie; Path=/' },
        });
      }
      if (url.pathname === '/vulns/sqli' && url.searchParams.get('id') === "' OR '1'='1") {
        return new Response('<pre>ID:1\nUser: admin\nUser: gordonbeers\nUser: pablo\n</pre>', {
          status: 200,
        });
      }
      if (url.pathname === '/safe') {
        return new Response('safe output', { status: 200 });
      }
      if (url.pathname === '/404') {
        return new Response('Not Found', { status: 404 });
      }
      return new Response('OK', { status: 200 });
    },
  });
});

afterAll(() => {
  mockServer?.stop();
});

describe('PocSandbox — target resolution', () => {
  test('TARGETS registry has5 entries', () => {
    expect(Object.keys(TARGETS)).toHaveLength(5);
    expect(TARGETS.dvwa.baseUrl).toBe('http://localhost:8080');
    expect(TARGETS.bwapp.credentials?.user).toBe('bee');
    expect(TARGETS.pikachu.credentials).toBeUndefined();
  });

  test('constructor accepts string target name', () => {
    const sb = new PocSandbox({ target: 'dvwa', isolation: 'process' });
    expect(sb['target'].baseUrl).toBe('http://localhost:8080');
  });

  test('constructor accepts custom PocTarget object', () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    expect(sb['target'].baseUrl).toBe(`http://localhost:${MOCK_PORT}`);
  });
});

describe('PocSandbox — execute against mock target', () => {
  test('success: expected content found', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'sqli-1',
      method: 'GET',
      url: '/vulns/sqli?id=%27%20OR%20%271%27%3D%271',
      expected: { statusCode: 200, contains: 'admin' },
    });
    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(result.body).toContain('admin');
    expect(result.isolation).toBe('process');
    expect(result.responseTimeMs).toBeGreaterThanOrEqual(0);
  });

  test('failure: expected content not found', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'sqli-fail',
      method: 'GET',
      url: '/safe',
      expected: { contains: 'NONEXISTENT_TOKEN_XYZ' },
      timeoutMs: 2000,
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('expectation not met');
  });

  test('success: containsUser (multi-token)', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'sqli-multi',
      method: 'GET',
      url: '/vulns/sqli?id=%27%20OR%20%271%27%3D%271',
      expected: { containsUser: ['admin', 'pablo'] },
    });
    expect(result.success).toBe(true);
  });

  test('failure: status code mismatch', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: '404',
      method: 'GET',
      url: '/404',
      expected: { statusCode: 200 },
      timeoutMs: 2000,
    });
    expect(result.success).toBe(false);
  });

  test('success: regex match', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'regex',
      method: 'GET',
      url: '/vulns/sqli?id=%27%20OR%20%271%27%3D%271',
      expected: { matches: /User:\s*\w+/g },
    });
    expect(result.success).toBe(true);
  });
});

describe('PocSandbox — retries', () => {
  test('retries on failure up to N times', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
      retries: 3,
    });
    const start = Date.now();
    const result = await sb.execute({
      id: 'will-fail',
      method: 'GET',
      url: '/safe',
      expected: { contains: 'NEVER_PRESENT' },
      timeoutMs: 1000,
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/expectation not met|all retries/);
    expect(result.responseTimeMs).toBeLessThan(8000);
  });
});

describe('PocSandbox — result shape', () => {
  test('result includes all required fields', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'shape',
      method: 'GET',
      url: '/safe',
      expected: { contains: 'safe' },
    });
    expect(result.id).toBe('shape');
    expect(typeof result.success).toBe('boolean');
    expect(typeof result.responseTimeMs).toBe('number');
    expect(typeof result.completedAt).toBe('number');
    expect(result.isolation).toBe('process');
  });
});
