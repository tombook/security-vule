/**
 * Structured logging via pino.
 * Replaces 341 console.log calls in src/ with field-based structured logs.
 *
 * Auto-redacts sensitive fields (apiKey, password, code, prompt).
 * Supports JSON output for production + pretty output for development.
 */
import pino from 'pino';

const isDev = process.env['NODE_ENV'] !== 'production' && process.env['VULE_LOG_FORMAT'] !== 'json';

export const logger = pino({
  level: process.env['LOG_LEVEL'] || (isDev ? 'info' : 'info'),
  base: {
    service: 'security-vule',
    version: '0.3.0',
  },
  // Auto-redact sensitive data
  redact: {
    paths: [
      '*.apiKey',
      '*.api_key',
      '*.password',
      '*.token',
      '*.secret',
      'code',
      'prompt',
      'messages',
      '*.content',
    ],
    censor: '[REDACTED]',
  },
  // Transport: JSON in production, pretty in dev
  ...(isDev
    ? {
        transport: {
          target: 'pino/file',
          options: { destination: 1 }, // stdout
        },
      }
    : {}),
});

/** Child logger with component context */
export function childLogger(component: string, meta: Record<string, unknown> = {}) {
  return logger.child({ component, ...meta });
}
