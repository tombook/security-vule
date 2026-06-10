/**
 * Health check endpoint for Kubernetes liveness/readiness probes.
 */
import { CPGBuilder, createCPG } from '../engine/cpg/builder.js';
import { DIMENSIONS } from '../engine/dimensions/registry.js';

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  checks: Record<string, 'ok' | 'fail' | 'degraded'>;
}

const VERSION = '0.3.0';
const startTime = Date.now();

export function healthCheck(): HealthStatus {
  const checks: HealthStatus['checks'] = {
    cpg_builder:
      typeof CPGBuilder === 'function' && typeof createCPG === 'function' ? 'ok' : 'fail',
    dimensions: Object.keys(DIMENSIONS).length > 0 ? 'ok' : 'fail',
    memory: process.memoryUsage().heapUsed < 1024 * 1024 * 1024 ? 'ok' : 'degraded',
  };

  const allOk = Object.values(checks).every((c) => c === 'ok');
  const hasFail = Object.values(checks).some((c) => c === 'fail');

  return {
    status: hasFail ? 'unhealthy' : allOk ? 'ok' : 'degraded',
    version: VERSION,
    uptime: (Date.now() - startTime) / 1000,
    checks,
  };
}

/** Graceful shutdown handler. */
const shutdownHandlers: Array<() => Promise<void> | void> = [];

export function onShutdown(handler: () => Promise<void> | void): void {
  shutdownHandlers.push(handler);
}

export async function gracefulShutdown(signal: string): Promise<void> {
  // Use a logger if available
  try {
    const { logger } = await import('./logger.js');
    logger.info({ signal }, 'graceful shutdown initiated');
  } catch {
    console.log(`[shutdown] received ${signal}`);
  }
  for (const handler of shutdownHandlers) {
    try {
      await handler();
    } catch (e) {
      console.error(`[shutdown] handler error:`, e);
    }
  }
  process.exit(0);
}

// Auto-register signal handlers (only once)
let registered = false;
export function registerShutdownHandlers(): void {
  if (registered) return;
  registered = true;
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}
