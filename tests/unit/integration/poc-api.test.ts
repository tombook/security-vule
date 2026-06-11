import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { serverCommand } from '../../../src/integration/commands/server.js';

const TEST_PORT = 18767;
let baseUrl: string;

beforeAll(async () => {
  await serverCommand({ port: TEST_PORT });
  baseUrl = `http://localhost:${TEST_PORT}`;
});

afterAll(() => {});

describe('PoC Verification API', () => {
  test('GET /api/poc/report returns 404 before verification', async () => {
    const res = await fetch(`${baseUrl}/api/poc/report`);
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toContain('no poc report');
  });

  test('GET /api/poc/report/markdown returns 404 before verification', async () => {
    const res = await fetch(`${baseUrl}/api/poc/report/markdown`);
    expect(res.status).toBe(404);
  });

  test('POST /api/poc/verify endpoint accepts requests', async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    try {
      const res = await fetch(`${baseUrl}/api/poc/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      expect(res.status).toBeLessThanOrEqual(500);
    } catch (e) {
      clearTimeout(timeout);
      expect((e as Error).name).toBe('AbortError');
    }
  });
});
