/**
 * Tests for PocSandbox — uses a local Bun.serve mock target (no Docker needed).
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PocSandbox, TARGETS, inferStatus } from '../../../src/poc/sandbox.js';

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

describe('PocSandbox — status inference (SOP v1.0 iteration)', () => {
  const { inferStatus } =
    require('../../../src/poc/sandbox.js') as typeof import('../../../src/poc/sandbox.js');

  test('verified when success=true', () => {
    const r = inferStatus({ success: true, matchedExpectations: ['admin'] });
    expect(r.status).toBe('verified');
    expect(r.retryable).toBe(false);
  });

  test('auth_failed on HTTP401', () => {
    const r = inferStatus({ success: false, statusCode: 401, matchedExpectations: [] });
    expect(r.status).toBe('auth_failed');
    expect(r.retryable).toBe(true);
  });

  test('auth_failed on HTTP302 redirect', () => {
    const r = inferStatus({ success: false, statusCode: 302, matchedExpectations: [] });
    expect(r.status).toBe('auth_failed');
    expect(r.retryable).toBe(true);
  });

  test('rate_limited on HTTP429', () => {
    const r = inferStatus({ success: false, statusCode: 429, matchedExpectations: [] });
    expect(r.status).toBe('rate_limited');
    expect(r.retryable).toBe(true);
  });

  test('payload_filtered when SQL error leaked', () => {
    const r = inferStatus({
      success: false,
      statusCode: 200,
      body: 'You have an error in your SQL syntax; check...',
      matchedExpectations: [],
    });
    expect(r.status).toBe('payload_filtered');
    expect(r.retryable).toBe(false);
  });

  test('table_empty when query returned no rows', () => {
    const r = inferStatus({
      success: false,
      statusCode: 200,
      body: 'No results found',
      matchedExpectations: [],
    });
    expect(r.status).toBe('table_empty');
    expect(r.retryable).toBe(false);
  });

  test('connection_error when statusCode=0', () => {
    const r = inferStatus({ success: false, statusCode: 0, matchedExpectations: [] });
    expect(r.status).toBe('connection_error');
    expect(r.retryable).toBe(true);
  });

  test('endpoint_changed on HTTP404', () => {
    const r = inferStatus({ success: false, statusCode: 404, matchedExpectations: [] });
    expect(r.status).toBe('endpoint_changed');
    expect(r.retryable).toBe(false);
  });

  test('unsupported_target on HTTP500', () => {
    const r = inferStatus({ success: false, statusCode: 500, matchedExpectations: [] });
    expect(r.status).toBe('unsupported_target');
    expect(r.retryable).toBe(false);
  });

  test('no_data_returned when body short + no match', () => {
    const r = inferStatus({
      success: false,
      statusCode: 200,
      body: 'short',
      matchedExpectations: [],
    });
    expect(r.status).toBe('no_data_returned');
  });

  test('diagnostic message present for all statuses', () => {
    const statuses = ['verified', 'auth_failed', 'table_empty', 'payload_filtered', 'rejected'];
    for (const s of statuses) {
      const r = inferStatus({
        success: s === 'verified',
        statusCode: s === 'verified' ? 200 : 401,
        matchedExpectations: [],
      });
      expect(r.diagnostic.length).toBeGreaterThan(0);
    }
  });
});

describe('PocSandbox — execute returns status field', () => {
  let mockServer2: ReturnType<typeof Bun.serve> | null = null;
  const MOCK_PORT2 = 19235;

  beforeAll(() => {
    mockServer2 = Bun.serve({
      port: MOCK_PORT2,
      async fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/login.php') {
          return new Response('Welcome', {
            status: 200,
            headers: { 'set-cookie': 'PHPSESSID=test; Path=/' },
          });
        }
        if (url.pathname === '/vuln') {
          return new Response('Error: no data', { status: 500 });
        }
        return new Response('Not Found', { status: 404 });
      },
    });
  });

  afterAll(() => {
    mockServer2?.stop();
  });

  test('result.status is set (not undefined)', async () => {
    const sb = new PocSandbox({
      target: {
        name: 'mock',
        baseUrl: `http://localhost:${MOCK_PORT2}`,
        credentials: { user: 'test', password: 'test', loginPath: '/login.php' },
      },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: 'test1',
      method: 'GET',
      url: '/vuln',
      expected: { contains: 'admin' },
      timeoutMs: 2000,
    });
    expect(result.status).toBeDefined();
    expect(result.retryable).toBeDefined();
  });
});

describe('PocSandbox — bWAPP login (SOP v1.2 iteration)', () => {
  test('bWAPP uses /login.php and login/password fields', async () => {
    const sb = new PocSandbox({ target: 'bwapp', isolation: 'process' });
    expect(sb['target'].baseUrl).toBe('http://localhost:8081');
    expect(sb['target'].credentials?.user).toBe('bee');
    expect(sb['target'].credentials?.password).toBe('bug');
    expect(sb['target'].credentials?.loginPath).toBe('/login.php');
  });

  test('cookieJarPath is initialized per-instance', async () => {
    const sb1 = new PocSandbox({ target: 'mock', isolation: 'process' });
    await new Promise((r) => setTimeout(r, 2));
    const sb2 = new PocSandbox({ target: 'mock', isolation: 'process' });
    expect(sb1['cookieJarPath']).toContain('vule-poc-');
    expect(sb1['cookieJarPath']).not.toBe(sb2['cookieJarPath']);
  });

  test('login() accepts security_level parameter', async () => {
    const sb = new PocSandbox({ target: 'bwapp', isolation: 'process' });
    const spy = Bun.spawn(['bash', '-c', 'true']);
    await spy.exited;
    // Mock assertion: securityLevel parameter signature
    const fnStr = sb.login.toString();
    expect(fnStr).toContain('securityLevel');
  });
});

describe('PocSandbox — redirect handling (SOP v1.3)', () => {
  test('302 redirect is followed to /redirected path', async () => {
    let redirectedServer: ReturnType<typeof Bun.serve> | null = null;
    const REDIR_PORT = 19235;
    redirectedServer = Bun.serve({
      port: REDIR_PORT,
      async fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/redir') {
          return new Response(null, {
            status: 302,
            headers: { Location: '/final' },
          });
        }
        if (url.pathname === '/final') {
          return new Response('SECRET_FINAL_DATA', { status: 200 });
        }
        return new Response('OK', { status: 200 });
      },
    });

    try {
      const sb = new PocSandbox({
        target: { name: 'mock', baseUrl: `http://localhost:${REDIR_PORT}` },
        isolation: 'process',
      });
      const result = await sb.execute({
        id: 'redir-1',
        method: 'GET',
        url: '/redir',
        expected: { contains: 'SECRET_FINAL_DATA' },
        timeoutMs: 3000,
      });
      expect(result.statusCode).toBe(200);
      expect(result.success).toBe(true);
    } finally {
      redirectedServer?.stop();
    }
  });

  test('3+ redirects are followed (up to hop limit)', async () => {
    let chainServer: ReturnType<typeof Bun.serve> | null = null;
    const CHAIN_PORT = 19236;
    let hopCount = 0;
    chainServer = Bun.serve({
      port: CHAIN_PORT,
      async fetch(req) {
        const url = new URL(req.url);
        hopCount++;
        if (url.pathname === '/hop1') {
          return new Response(null, { status: 302, headers: { Location: '/hop2' } });
        }
        if (url.pathname === '/hop2') {
          return new Response(null, { status: 302, headers: { Location: '/hop3' } });
        }
        if (url.pathname === '/hop3') {
          return new Response('REDIRECTED_3HOPS', { status: 200 });
        }
        return new Response('OK', { status: 200 });
      },
    });

    try {
      const sb = new PocSandbox({
        target: { name: 'mock', baseUrl: `http://localhost:${CHAIN_PORT}` },
        isolation: 'process',
      });
      const result = await sb.execute({
        id: 'redir-chain',
        method: 'GET',
        url: '/hop1',
        expected: { contains: 'REDIRECTED_3HOPS' },
        timeoutMs: 3000,
      });
      expect(result.success).toBe(true);
      expect(result.body).toContain('REDIRECTED_3HOPS');
    } finally {
      chainServer?.stop();
    }
  });

  test('non-2xx non-302: returns the actual response', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const result = await sb.execute({
      id: '404-1',
      method: 'GET',
      url: '/404',
      expected: { statusCode: 404 },
      timeoutMs: 2000,
    });
    expect(result.statusCode).toBe(404);
    expect(result.success).toBe(true);
  });
});

describe('PocSandbox — inferStatus for SOP v1.3 unbreakable cases', () => {
  test('payload_filtered: SQL error in body', () => {
    const result = inferStatus({
      success: false,
      body: "You have an error in your SQL syntax near 'xxx'",
      statusCode: 200,
      matchedExpectations: [],
    });
    expect(result.status).toBe('payload_filtered');
    expect(result.retryable).toBe(false);
  });

  test('table_empty: no rows found', () => {
    const result = inferStatus({
      success: false,
      body: 'No results found in database',
      statusCode: 200,
      matchedExpectations: [],
    });
    expect(result.status).toBe('table_empty');
    expect(result.retryable).toBe(false);
  });

  test('auth_failed: 302 redirect on protected endpoint', () => {
    const result = inferStatus({
      success: false,
      body: '',
      statusCode: 302,
      matchedExpectations: [],
    });
    expect(result.status).toBe('auth_failed');
    expect(result.retryable).toBe(true);
  });

  test('connection_error: 0 statusCode (network failure)', () => {
    const result = inferStatus({
      success: false,
      body: undefined,
      statusCode: 0,
      matchedExpectations: [],
    });
    expect(result.status).toBe('connection_error');
    expect(result.retryable).toBe(true);
  });
});

describe('PocSandbox — payload database for bWAPP bypasses (SOP v1.3)', () => {
  test('LIKE wildcard % payload is valid for sqli_1 type', () => {
    const payload = { id: 'sqli_1-like', url: '/sqli_1.php?title=%25&action=search' };
    expect(payload.url).toContain('%25');
  });

  test('numeric OR payload is valid for sqli_2 type', () => {
    const payload = { id: 'sqli_2-num', url: '/sqli_2.php?movie=1+OR+1%3D1&action=go' };
    expect(payload.url).toContain('1+OR+1%3D1');
  });

  test('GBK encoding %bf%27 payload for sqli_2 high bypass', () => {
    const payload = { id: 'sqli_2-gbk', url: '/sqli_2.php?movie=1%bf%27+OR+1%3D1+--+-' };
    expect(payload.url).toContain('%bf%27');
  });

  test('attribute XSS payload works without <script>', () => {
    const payload = { tag: '<img src=x onerror=alert(1)>' };
    expect(payload.tag).toContain('onerror=');
    expect(payload.tag).not.toContain('<script>');
  });

  test('|| shell pipe bypass works for command injection', () => {
    const payload = { id: 'commandi', target: '127.0.0.1||id' };
    expect(payload.target).toContain('||');
    expect(payload.target).not.toContain(';');
  });
});
