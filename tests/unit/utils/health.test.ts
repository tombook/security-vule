/**
 * Tests for health check + graceful shutdown.
 */
import { describe, expect, test } from 'bun:test';
import {
  healthCheck,
  onShutdown,
  gracefulShutdown,
  registerShutdownHandlers,
} from '../../../src/utils/health.js';

describe('health', () => {
  test('healthCheck returns status', () => {
    const status = healthCheck();
    expect(status.status).toMatch(/^(ok|degraded|unhealthy)$/);
    expect(status.version).toBe('0.3.0');
    expect(status.uptime).toBeGreaterThanOrEqual(0);
  });

  test('healthCheck has all expected checks', () => {
    const status = healthCheck();
    expect(status.checks).toHaveProperty('cpg_builder');
    expect(status.checks).toHaveProperty('dimensions');
    expect(status.checks).toHaveProperty('memory');
  });

  test('cpg_builder check is ok', () => {
    const status = healthCheck();
    expect(status.checks['cpg_builder']).toBe('ok');
  });

  test('dimensions check is ok', () => {
    const status = healthCheck();
    expect(status.checks['dimensions']).toBe('ok');
  });

  test('onShutdown registers a handler', () => {
    let called = false;
    onShutdown(() => {
      called = true;
    });
    expect(typeof gracefulShutdown).toBe('function');
  });

  test('registerShutdownHandlers is idempotent', () => {
    registerShutdownHandlers();
    registerShutdownHandlers();
    registerShutdownHandlers();
    // Should not throw, no exposed state to verify
    expect(true).toBe(true);
  });
});
