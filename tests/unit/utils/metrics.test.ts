/**
 * Tests for Prometheus metrics.
 */
import { describe, expect, test } from 'bun:test';
import {
  registry,
  llmCalls,
  llmLatency,
  findings,
  filesScanned,
  getMetricsText,
  resetMetrics,
} from '../../../src/utils/metrics.js';

async function getMetricLine(metricName: string, labels?: string): Promise<string | null> {
  const text = await getMetricsText();
  const lines = text.split('\n').filter((l) => l.startsWith(metricName));
  if (labels) {
    const match = lines.find((l) => l.includes(labels));
    return match ?? null;
  }
  return lines[0] ?? null;
}

describe('metrics', () => {
  test('exports a Prometheus registry', () => {
    expect(registry).toBeDefined();
  });

  test('llmCalls counter increments', async () => {
    resetMetrics();
    llmCalls.inc({ provider: 'test', model: 'm1', outcome: 'success' });
    llmCalls.inc({ provider: 'test', model: 'm1', outcome: 'success' });
    const line = await getMetricLine('vule_llm_calls_total', 'provider="test"');
    expect(line).toBeTruthy();
    expect(line!).toMatch(/vule_llm_calls_total\{provider="test"[^}]*\}\s+2/);
  });

  test('llmLatency histogram observes', async () => {
    resetMetrics();
    llmLatency.observe({ provider: 'minimax', model: 'm1' }, 1.5);
    const line = await getMetricLine('vule_llm_latency_seconds_count', 'provider="minimax"');
    expect(line).toBeTruthy();
    expect(line!).toMatch(/vule_llm_latency_seconds_count\{provider="minimax"[^}]*\}\s+1/);
  });

  test('findings counter increments', async () => {
    resetMetrics();
    findings.inc({ severity: 'critical', type: 'SQL Injection' });
    const line = await getMetricLine('vule_findings_total', 'severity="critical"');
    expect(line).toBeTruthy();
    expect(line!).toMatch(/vule_findings_total\{[^}]*severity="critical"[^}]*\}\s+1/);
  });

  test('filesScanned tracks outcomes', async () => {
    resetMetrics();
    filesScanned.inc({ outcome: 'success' });
    const line = await getMetricLine('vule_scan_files_total', 'outcome="success"');
    expect(line).toBeTruthy();
  });

  test('getMetricsText returns Prometheus format', async () => {
    const text = await getMetricsText();
    expect(typeof text).toBe('string');
    expect(text).toContain('# HELP vule_');
    expect(text).toContain('# TYPE vule_');
  });

  test('resetMetrics clears counters', async () => {
    llmCalls.inc({ provider: 'reset', model: 'm1', outcome: 'success' });
    resetMetrics();
    const line = await getMetricLine('vule_llm_calls_total', 'provider="reset"');
    expect(line).toBeNull();
  });
});
