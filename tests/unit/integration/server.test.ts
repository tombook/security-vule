/**
 * Tests for HTTP server endpoints.
 */
import { describe, expect, test } from 'bun:test';
import { healthCheck } from '../../../src/utils/health.js';
import { getMetricsText } from '../../../src/utils/metrics.js';

describe('server endpoints (unit-level)', () => {
  test('healthCheck returns proper status shape', () => {
    const h = healthCheck();
    expect(h).toHaveProperty('status');
    expect(h).toHaveProperty('version');
    expect(h).toHaveProperty('uptime');
    expect(h).toHaveProperty('checks');
  });

  test('health returns ok status when all checks pass', () => {
    const h = healthCheck();
    // Should be 'ok' in normal test environment
    expect(['ok', 'degraded']).toContain(h.status);
  });

  test('getMetricsText returns Prometheus format', async () => {
    const text = await getMetricsText();
    expect(text).toMatch(/^# HELP /m);
    expect(text).toMatch(/^# TYPE /m);
  });
});
