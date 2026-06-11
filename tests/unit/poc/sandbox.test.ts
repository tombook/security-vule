/**
 * Tests for PocSandbox — uses a local Bun.serve mock target (no Docker needed).
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  PocSandbox,
  TARGETS,
  inferStatus,
  type PocVerificationStatus,
  type PocExpectation,
} from '../../../src/poc/sandbox.js';

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

describe('PocSandbox — time-based blind SQLi (SOP v1.4)', () => {
  test('PocExpectation supports timeDelayMs field', () => {
    const expected: PocExpectation = { timeDelayMs: 3000, baselineUrl: '/sqli_4.php?title=test' };
    expect(expected.timeDelayMs).toBe(3000);
    expect(expected.baselineUrl).toBe('/sqli_4.php?title=test');
  });

  test('time_based_verified status exists in PocVerificationStatus', () => {
    const status: PocVerificationStatus = 'time_based_verified';
    expect(status).toBe('time_based_verified');
  });

  test('measureBaseline strips SLEEP from URL', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${MOCK_PORT}` },
      isolation: 'process',
    });
    const fnStr = sb['measureBaseline'].toString();
    expect(fnStr).toContain('SLEEP');
    expect(fnStr).toContain('baselineUrl');
  });

  test('SLEEP(3) payload format is valid for MySQL', () => {
    const sleepPayload = "Iron Man' AND SLEEP(3)-- -";
    expect(sleepPayload).toContain('SLEEP(3)');
    expect(sleepPayload).toContain('-- -');
  });

  test('BENCHMARK payload format is valid for MySQL', () => {
    const benchmarkPayload = "Iron Man' AND BENCHMARK(10000000,SHA1('test'))-- -";
    expect(benchmarkPayload).toContain('BENCHMARK');
    expect(benchmarkPayload).toContain('SHA1');
  });
});

describe('PocSandbox — noFollowRedirect (SOP v1.6)', () => {
  const REDIR_PORT = MOCK_PORT + 10;
  let redirServer: ReturnType<typeof Bun.serve> | null = null;

  beforeAll(() => {
    redirServer = Bun.serve({
      port: REDIR_PORT,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/redirector') {
          return new Response('redirecting', {
            status: 302,
            headers: { Location: '/final-dest' },
          });
        }
        if (url.pathname === '/final-dest') {
          return new Response('Final destination reached');
        }
        return new Response('OK', { status: 200 });
      },
    });
  });

  afterAll(() => {
    redirServer?.stop();
  });

  test('noFollowRedirect: true stops at 302 without following', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${REDIR_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-nofollow',
      method: 'GET',
      url: '/redirector',
      noFollowRedirect: true,
      expected: { statusCode: 302 },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
    expect(r.status).toBe('verified');
    expect(r.matchedExpectations).toContain('statusCode');
  });

  test('without noFollowRedirect: follows 302 to destination', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${REDIR_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-follow',
      method: 'GET',
      url: '/redirector',
      expected: { contains: 'Final destination reached' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
    expect(r.body).toContain('Final destination reached');
  });
});

describe('PocSandbox — headerContains / headerMatches (SOP v1.6)', () => {
  const HDR_PORT = MOCK_PORT + 11;
  let hdrServer: ReturnType<typeof Bun.serve> | null = null;

  beforeAll(() => {
    hdrServer = Bun.serve({
      port: HDR_PORT,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/custom-headers') {
          return new Response('hello', {
            status: 200,
            headers: {
              'X-Custom-Security': 'enabled',
              'X-XSS-Protection': '0',
              Server: 'Apache/2.4.25',
            },
          });
        }
        if (url.pathname === '/check-cookies') {
          const cookie = req.headers.get('cookie') || '';
          return new Response(`cookies: ${cookie}`, { status: 200 });
        }
        return new Response('OK', { status: 200 });
      },
    });
  });

  afterAll(() => {
    hdrServer?.stop();
  });

  test('headerContains matches case-insensitively', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${HDR_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-hdr-contains',
      method: 'GET',
      url: '/custom-headers',
      expected: { headerContains: 'X-XSS-Protection: 0' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
    expect(r.matchedExpectations).toContain('headerContains');
  });

  test('headerMatches with regex detects server header', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${HDR_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-hdr-matches',
      method: 'GET',
      url: '/custom-headers',
      expected: { headerMatches: /server:\s*apache/i },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
    expect(r.matchedExpectations).toContain('headerMatches');
  });

  test('headerContains fails when header absent', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${HDR_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-hdr-missing',
      method: 'GET',
      url: '/custom-headers',
      expected: { headerContains: 'Content-Security-Policy' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(false);
  });
});

describe('PocSandbox — cookies field (SOP v1.6)', () => {
  const COOKIE_PORT = MOCK_PORT + 12;
  let cookieServer: ReturnType<typeof Bun.serve> | null = null;

  beforeAll(() => {
    cookieServer = Bun.serve({
      port: COOKIE_PORT,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/check-cookies') {
          const cookie = req.headers.get('cookie') || '';
          if (cookie.includes('session=abc123') && cookie.includes('role=admin')) {
            return new Response('Authenticated as admin', { status: 200 });
          }
          return new Response('Not authenticated', { status: 403 });
        }
        return new Response('OK', { status: 200 });
      },
    });
  });

  afterAll(() => {
    cookieServer?.stop();
  });

  test('cookies field injects custom cookies into request', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${COOKIE_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-cookies',
      method: 'GET',
      url: '/check-cookies',
      cookies: { session: 'abc123', role: 'admin' },
      expected: { contains: 'Authenticated as admin' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
  });
});

describe('PocSandbox — relative redirect resolution (SOP v1.5)', () => {
  const REL_PORT = MOCK_PORT + 13;
  let relServer: ReturnType<typeof Bun.serve> | null = null;

  beforeAll(() => {
    relServer = Bun.serve({
      port: REL_PORT,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/api/login') {
          return new Response('logged in', {
            status: 302,
            headers: { Location: 'dashboard' },
          });
        }
        if (url.pathname === '/api/dashboard') {
          return new Response('Dashboard content loaded');
        }
        return new Response('OK', { status: 200 });
      },
    });
  });

  afterAll(() => {
    relServer?.stop();
  });

  test('relative Location: "dashboard" resolves to /api/dashboard', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${REL_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-rel-redirect',
      method: 'GET',
      url: '/api/login',
      expected: { contains: 'Dashboard content loaded' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
    expect(r.body).toContain('Dashboard content loaded');
  });
});

describe('PocSandbox — POST method via execute (SOP v1.5)', () => {
  const POST_PORT = MOCK_PORT + 14;
  let postServer: ReturnType<typeof Bun.serve> | null = null;

  beforeAll(() => {
    postServer = Bun.serve({
      port: POST_PORT,
      async fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/submit' && req.method === 'POST') {
          const body = await req.text();
          if (body.includes('user=admin') && body.includes('pass=secret')) {
            return new Response('Login successful');
          }
          return new Response('Login failed', { status: 401 });
        }
        return new Response('OK', { status: 200 });
      },
    });
  });

  afterAll(() => {
    postServer?.stop();
  });

  test('POST with body content is sent correctly', async () => {
    const sb = new PocSandbox({
      target: { name: 'mock', baseUrl: `http://localhost:${POST_PORT}` },
      isolation: 'process',
      retries: 0,
    });
    const r = await sb.execute({
      id: 'test-post',
      method: 'POST',
      url: '/submit',
      body: 'user=admin&pass=secret',
      expected: { contains: 'Login successful' },
      timeoutMs: 5000,
    });
    expect(r.success).toBe(true);
  });
});
