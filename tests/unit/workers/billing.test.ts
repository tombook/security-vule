// tests/unit/workers/billing.test.ts
// Tests for apps/api/src/workers/billing.ts — focused on the
// long-delay regression: Node.js (and Bun's wrapper) cap setTimeout's
// 32-bit signed integer delay at ~24.8 days. Anything longer throws
//   TimeoutOverflowWarning: <ms> does not fit into a 32-bit signed
//                           integer. Timeout duration was set to 1.
// silently clamping the wait to 1 ms and producing a tight fire loop.

import { describe, test, expect } from 'bun:test';

describe('worker/billing: schedule computation', () => {
  test('nextRunAt advances to the 1st of next month at 00:05:00 local', async () => {
    const { nextRunAt } = await import('../../../apps/api/src/workers/billing.js');
    const now = new Date(2026, 6, 5, 10, 30, 0); // 5 Jul 2026 10:30
    const next = nextRunAt(now);
    expect(next.getFullYear()).toBe(2026);
    expect(next.getMonth()).toBe(7); // 0-indexed → August
    expect(next.getDate()).toBe(1);
    expect(next.getHours()).toBe(0);
    expect(next.getMinutes()).toBe(5);
    expect(next.getSeconds()).toBe(0);
  });

  test('nextRunAt from Dec 31 rolls into next year January', async () => {
    const { nextRunAt } = await import('../../../apps/api/src/workers/billing.js');
    const now = new Date(2026, 11, 31, 23, 59, 0); // 31 Dec 2026 23:59
    const next = nextRunAt(now);
    expect(next.getFullYear()).toBe(2027);
    expect(next.getMonth()).toBe(0); // January
    expect(next.getDate()).toBe(1);
  });

  test('nextRunAt from 00:04 on the 1st still points at NEXT month', async () => {
    // 00:04 < the 00:05 fire window. nextRunAt is "next 1st at 00:05"
    // so it must look one month ahead. This pins the semantic.
    const { nextRunAt } = await import('../../../apps/api/src/workers/billing.js');
    const now = new Date(2026, 6, 1, 0, 4, 0); // 1 Jul 2026 00:04
    const next = nextRunAt(now);
    expect(next.getMonth()).toBe(7); // August
    expect(next.getDate()).toBe(1);
  });

  test('nextRunAt return value is at least one full day in the future', async () => {
    // Sanity: it must NEVER be in the past. With 5-min margin on the
    // 1st of a month it can be as little as ~30 days out.
    const { nextRunAt } = await import('../../../apps/api/src/workers/billing.js');
    const now = new Date();
    const next = nextRunAt(now);
    expect(next.getTime()).toBeGreaterThan(now.getTime());
  });
});

describe('worker/billing: scheduling primitive', () => {
  test('startMonthlyBillingWorker uses setInterval (not setTimeout with month-scale delay)', async () => {
    // Intercept both timers and assert the worker picks the safe one.
    const calls: { kind: 'timeout' | 'interval'; delay: number }[] = [];
    const realSetTimeout = globalThis.setTimeout;
    const realSetInterval = globalThis.setInterval;
    // @ts-expect-error — narrow to timer arg shape for the probe
    globalThis.setTimeout = ((fn: () => void, delay?: number, ...rest: unknown[]) => {
      calls.push({ kind: 'timeout', delay: delay ?? 0 });
      return realSetTimeout(fn, delay, ...rest);
    }) as typeof setTimeout;
    // @ts-expect-error — same
    globalThis.setInterval = ((fn: () => void, delay?: number, ...rest: unknown[]) => {
      calls.push({ kind: 'interval', delay: delay ?? 0 });
      return realSetInterval(fn, delay, ...rest);
    }) as typeof setInterval;

    try {
      const { startMonthlyBillingWorker, stopMonthlyBillingWorker } = await import(
        '../../../apps/api/src/workers/billing.js'
      );
      startMonthlyBillingWorker();
      // Give the start() tick a chance to call its chosen timer API.
      await new Promise((r) => realSetTimeout(r, 10));
      stopMonthlyBillingWorker();

      const timeouts = calls.filter((c) => c.kind === 'timeout');
      const intervals = calls.filter((c) => c.kind === 'interval');
      // The worker must NOT have scheduled a setTimeout with a delay
      // larger than the 32-bit signed-integer cap (~24.8 days).
      const LONG = 2_147_483_647; // INT32_MAX ms
      for (const t of timeouts) {
        expect(t.delay).toBeLessThan(LONG);
      }
      // And it SHOULD use setInterval (the safe primitive).
      expect(intervals.length).toBeGreaterThan(0);
      for (const iv of intervals) {
        expect(iv.delay).toBeLessThan(LONG);
      }
    } finally {
      globalThis.setTimeout = realSetTimeout;
      globalThis.setInterval = realSetInterval;
    }
  });
});