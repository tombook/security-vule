/**
 * Tests for HTTP server endpoints (dashboard + report viewer + API).
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { healthCheck } from '../../../src/utils/health.js';
import { getMetricsText } from '../../../src/utils/metrics.js';
import { serverCommand } from '../../../src/integration/commands/server.js';
import { RiskLevel } from '../../../src/engine/uvrs.js';
import type { VuleReport } from '../../../src/engine/vule-report.js';

const TEST_PORT = 18765;
let baseUrl: string;
const shutdownFn: (() => void) | null = null;

const sampleReport: VuleReport = {
  version: '1.0.0',
  generatedAt: '2026-06-10T22:00:00Z',
  nodeCount: 2,
  topRisk: [
    {
      nodeId: 'n1',
      file: 'test.php',
      line: 8,
      code: '$x = $_GET["id"];',
      uvrs: 0.92,
      level: RiskLevel.CRITICAL,
      dominantDimension: 'gravity',
      contributions: { gravity: 0.95, kepler: 0.6, entropy: 0.4 },
    },
    {
      nodeId: 'n2',
      file: 'test.php',
      line: 5,
      code: 'echo $x;',
      uvrs: 0.6,
      level: RiskLevel.MEDIUM,
      dominantDimension: 'kepler',
      contributions: { gravity: 0.3, kepler: 0.7, entropy: 0.2 },
    },
  ],
};

beforeAll(async () => {
  await serverCommand({ port: TEST_PORT });
  baseUrl = `http://localhost:${TEST_PORT}`;
  await new Promise((r) => setTimeout(r, 100));
});

afterAll(() => {
  if (shutdownFn) shutdownFn();
});

describe('server endpoints (unit-level)', () => {
  test('healthCheck returns proper status shape', () => {
    const h = healthCheck();
    expect(h).toHaveProperty('status');
    expect(h).toHaveProperty('version');
    expect(h).toHaveProperty('uptime');
    expect(h).toHaveProperty('checks');
  });

  test('health returns ok or degraded status when all checks pass', () => {
    const h = healthCheck();
    expect(['ok', 'degraded']).toContain(h.status);
  });

  test('getMetricsText returns Prometheus format', async () => {
    const text = await getMetricsText();
    expect(text).toMatch(/^# HELP /m);
    expect(text).toMatch(/^# TYPE /m);
  });
});

describe('HTTP server live endpoints', () => {
  test('GET / returns HTML dashboard', async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('VuleEngine Web UI');
    expect(html).toContain('/healthz');
    expect(html).toContain('/metrics');
  });

  test('GET /report without submission returns 404 with helpful message', async () => {
    const res = await fetch(`${baseUrl}/report`);
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain('No report submitted yet');
  });

  test('POST /api/report accepts valid VuleReport and GET returns it', async () => {
    const post = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(sampleReport),
    });
    expect(post.status).toBe(200);
    const body = (await post.json()) as { ok: boolean; nodeCount: number; topRisk: number };
    expect(body.ok).toBe(true);
    expect(body.nodeCount).toBe(2);

    const get = await fetch(`${baseUrl}/api/report`);
    expect(get.status).toBe(200);
    const data = (await get.json()) as VuleReport;
    expect(data.version).toBe('1.0.0');
    expect(data.topRisk).toHaveLength(2);
  });

  test('POST /api/report rejects invalid JSON', async () => {
    const res = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ foo: 'bar' }),
    });
    expect(res.status).toBe(400);
  });

  test('GET /report renders HTML with D3 + Plotly after submission', async () => {
    const res = await fetch(`${baseUrl}/report`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('VuleEngine Cosmic-Galaxy Risk Report');
    expect(html).toContain('Risk Star Map');
    expect(html).toContain('test.php:8');
    expect(html).toContain('d3@7');
    expect(html).toContain('plotly');
  });

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

  test('Unknown route returns 404', async () => {
    const res = await fetch(`${baseUrl}/unknown`);
    expect(res.status).toBe(404);
  });
});
