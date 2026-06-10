/**
 * Tests for OpenTelemetry tracing setup.
 */
import { describe, expect, test } from 'bun:test';
import { getTracer, withSpan, initTracing, shutdownTracing } from '../../../src/utils/tracing.js';

describe('tracing', () => {
  // Use console exporter throughout to avoid OTLP network timeouts
  process.env['OTEL_CONSOLE'] = 'true';

  test('getTracer returns a Tracer instance', () => {
    const tracer = getTracer();
    expect(typeof tracer.startSpan).toBe('function');
  });

  test('withSpan wraps async function and returns value', async () => {
    const result = await withSpan('test.span', async () => {
      return 42;
    });
    expect(result).toBe(42);
  });

  test('withSpan propagates exceptions', async () => {
    let caught = false;
    try {
      await withSpan('test.error', async () => {
        throw new Error('test');
      });
    } catch (e) {
      caught = true;
      expect((e as Error).message).toBe('test');
    }
    expect(caught).toBe(true);
  });

  test('withSpan supports custom attributes', async () => {
    const result = await withSpan('test.attrs', async () => 'ok', {
      provider: 'test',
      model: 'm1',
    });
    expect(result).toBe('ok');
  });

  test('initTracing is idempotent', () => {
    initTracing();
    initTracing();
    initTracing();
    expect(getTracer()).toBeDefined();
  });

  test('shutdownTracing does not throw', async () => {
    await shutdownTracing();
    initTracing();
  });
});
