/**
 * Tests for product-grade HTTP server (landing + scan + report + settings).
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { healthCheck } from '../../../src/utils/health.js';
import { getMetricsText } from '../../../src/utils/metrics.js';
import { serverCommand } from '../../../src/integration/commands/server.js';
import { RiskLevel } from '../../../src/engine/uvrs.js';
import type { VuleReport } from '../../../src/engine/vule-report.js';

const TEST_PORT = 18766;
let baseUrl: string;

beforeAll(async () => {
  await serverCommand({ port: TEST_PORT });
  baseUrl = `http://localhost:${TEST_PORT}`;
});

afterAll(() => {});

describe('Product UI — landing page', () => {
  test('GET / returns value-prop HTML', async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('security-vule');
    expect(html).toContain('Find vulnerabilities');
    expect(html).toContain('Start a scan');
    expect(html).toContain('How it compares');
  });

  test('landing has trust strip + features grid', async () => {
    const res = await fetch(`${baseUrl}/`);
    const html = await res.text();
    expect(html).toContain('948 tests passing');
    expect(html).toContain('OWASP Agentic AI Top10');
    expect(html).toContain('100% PoC-verified');
    expect(html).toContain('29-dimension risk score');
  });

  test('landing has CTA banner', async () => {
    const res = await fetch(`${baseUrl}/`);
    const html = await res.text();
    expect(html).toContain('Ready to scan?');
    expect(html).toContain('AGPL-3.0');
  });

  test('landing has sticky nav header', async () => {
    const res = await fetch(`${baseUrl}/`);
    const html = await res.text();
    expect(html).toContain('<div class="header">');
    expect(html).toContain('<a href="/scan">');
    expect(html).toContain('<a href="/settings">');
  });
});

describe('Product UI — scan page', () => {
  test('GET /scan returns scan interface', async () => {
    const res = await fetch(`${baseUrl}/scan`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Run a scan');
    expect(html).toContain('Drop a file here');
    expect(html).toContain('Paste code');
    expect(html).toContain('Sample');
  });

  test('scan page has tabs for upload/paste/sample', async () => {
    const res = await fetch(`${baseUrl}/scan`);
    const html = await res.text();
    expect(html).toContain('data-tab="upload"');
    expect(html).toContain('data-tab="paste"');
    expect(html).toContain('data-tab="sample"');
    expect(html).toContain('id="drop"');
  });
});

describe('Product UI — settings page', () => {
  test('GET /settings returns configuration page', async () => {
    const res = await fetch(`${baseUrl}/settings`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Settings');
    expect(html).toContain('LLM Providers');
    expect(html).toContain('Scan modes');
    expect(html).toContain('Incremental scan');
    expect(html).toContain('Output formats');
  });
});

describe('Product UI — scan API', () => {
  test('POST /api/scan with JSON body creates scan job', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: 'test.php',
        language: 'php',
        code: '<?php eval($_GET["c"]);',
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; id: string; reportUrl: string };
    expect(body.ok).toBe(true);
    expect(body.id).toMatch(/^scan-/);
    expect(body.reportUrl).toBe(`/report/${body.id}`);
  });

  test('POST /api/scan with vulnerable code returns findings', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: 'sqli.php',
        language: 'php',
        code: '<?php\n$id = $_GET["id"];\n$result = mysql_query("SELECT * FROM x WHERE id=" . $id);\necho $result;',
      }),
    });
    const body = (await res.json()) as { id: string };
    const reportRes = await fetch(`${baseUrl}/report/${body.id}`);
    expect(reportRes.status).toBe(200);
    const html = await reportRes.text();
    expect(html).toContain('mysql_query');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('Use parameterized queries');
  });

  test('GET /api/scan/:id returns scan status', async () => {
    const post = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'a.php', language: 'php', code: '<?php $x =1;' }),
    });
    const postBody = (await post.json()) as { id: string };

    const get = await fetch(`${baseUrl}/api/scan/${postBody.id}`);
    expect(get.status).toBe(200);
    const status = (await get.json()) as { status: string };
    expect(['running', 'completed']).toContain(status.status);
  });

  test('GET /api/scan/:id for unknown id returns404', async () => {
    const res = await fetch(`${baseUrl}/api/scan/no-such-id`);
    expect(res.status).toBe(404);
  });
});

describe('Product UI — report viewer', () => {
  test('GET /report/:id renders risk cards', async () => {
    const post = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: 'vuln.php',
        language: 'php',
        code: '<?php\n$x = $_GET["x"];\neval($x);\nmysql_query($x);\n',
      }),
    });
    const body = (await post.json()) as { id: string };
    await new Promise((r) => setTimeout(r, 200));

    const reportRes = await fetch(`${baseUrl}/report/${body.id}`);
    expect(reportRes.status).toBe(200);
    const html = await reportRes.text();
    expect(html).toContain('Scan Report');
    expect(html).toContain('risk-card');
    expect(html).toContain('Show fix');
    expect(html).toContain('D3');
  });

  test('GET /report/:id for unknown id returns404', async () => {
    const res = await fetch(`${baseUrl}/report/no-such-scan`);
    expect(res.status).toBe(404);
  });

  test('GET /share/:id renders shareable summary card', async () => {
    const post = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'a.php', language: 'php', code: '<?php eval($_GET["c"]);' }),
    });
    const body = (await post.json()) as { id: string };
    await new Promise((r) => setTimeout(r, 200));

    const res = await fetch(`${baseUrl}/share/${body.id}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('security-vule scan report');
  });
});

describe('Product UI — health/metrics endpoints', () => {
  test('GET /healthz returns JSON status', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    expect(res.status).toBeLessThanOrEqual(503);
    const body = (await res.json()) as { status: string };
    expect(['ok', 'degraded', 'unhealthy']).toContain(body.status);
  });

  test('GET /metrics returns Prometheus text format', async () => {
    const res = await fetch(`${baseUrl}/metrics`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/plain');
    const text = await res.text();
    expect(text).toMatch(/^# HELP /m);
  });

  test('Unknown route returns404 error page', async () => {
    const res = await fetch(`${baseUrl}/no-such-page`);
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain('404');
  });
});

describe('Product UI — health/metrics util functions (unit)', () => {
  test('healthCheck returns proper status shape', () => {
    const h = healthCheck();
    expect(h).toHaveProperty('status');
    expect(h).toHaveProperty('version');
    expect(h).toHaveProperty('uptime');
    expect(h).toHaveProperty('checks');
  });

  test('getMetricsText returns Prometheus format', async () => {
    const text = await getMetricsText();
    expect(text).toMatch(/^# HELP /m);
    expect(text).toMatch(/^# TYPE /m);
  });
});
