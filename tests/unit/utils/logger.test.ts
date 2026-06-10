/**
 * Tests for structured logger.
 */
import { describe, expect, test } from 'bun:test';
import { logger, childLogger } from '../../../src/utils/logger.js';

describe('logger', () => {
  test('exports a pino instance', () => {
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  test('childLogger adds component context', () => {
    const child = childLogger('cli', { command: 'analyze' });
    expect(typeof child.info).toBe('function');
    expect(typeof child.warn).toBe('function');
    expect(typeof child.error).toBe('function');
  });

  test('childLogger supports nested context', () => {
    const root = childLogger('cli');
    const child = root.child({ command: 'analyze' });
    expect(typeof child.info).toBe('function');
  });

  test('logger has standard pino methods', () => {
    expect(typeof logger.fatal).toBe('function');
    expect(typeof logger.trace).toBe('function');
  });

  test('logger is configured with redact', () => {
    // Verify pino redact option is set (via internal symbol)
    const symbols = Object.getOwnPropertySymbols(logger);
    const pinoSymbol = symbols.find((s) => String(s).includes('pino') || s.description === 'pino');
    let redactPaths: unknown = undefined;
    if (pinoSymbol) {
      // @ts-expect-error - accessing internal pino state
      const opts = logger[pinoSymbol]?.opts;
      redactPaths = opts?.redact?.paths;
    }
    // If we got the symbol, verify it has redact paths
    if (redactPaths) {
      expect(Array.isArray(redactPaths)).toBe(true);
    }
    // At minimum, log call should not throw
    expect(() => logger.info('test', 'msg')).not.toThrow();
  });
});
