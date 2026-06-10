/**
 * Prometheus metrics for security-vule.
 *
 * Exposed via /metrics endpoint (Prometheus format) or scraped by
 * Grafana / Prometheus / Datadog.
 *
 * Metrics tracked:
 *   - vule_llm_calls_total: LLM API calls by provider/model/outcome
 *   - vule_llm_latency_seconds: LLM call latency histogram
 *   - vule_findings_total: Total findings by severity/type
 *   - vule_scan_files_total: Files scanned (success/error/skipped)
 *   - vule_dimensions_evaluated_total: Dimension evaluations by name
 *   - vule_cpg_nodes: CPG node count histogram
 *   - vule_cpg_edges: CPG edge count histogram
 *   - vule_active_spans: OpenTelemetry active spans gauge
 */
import { Counter, Histogram, Gauge, Registry, collectDefaultMetrics } from 'prom-client';

export const registry = new Registry();

// Collect default Node.js metrics (CPU, memory, GC, etc.)
collectDefaultMetrics({ register: registry });

// === LLM Metrics ===

export const llmCalls = new Counter({
  name: 'vule_llm_calls_total',
  help: 'Total LLM API calls',
  labelNames: ['provider', 'model', 'outcome'] as const,
  registers: [registry],
});

export const llmLatency = new Histogram({
  name: 'vule_llm_latency_seconds',
  help: 'LLM call latency in seconds',
  labelNames: ['provider', 'model'] as const,
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300],
  registers: [registry],
});

export const llmTokens = new Counter({
  name: 'vule_llm_tokens_total',
  help: 'Total LLM tokens used',
  labelNames: ['provider', 'model', 'type'] as const, // type: prompt/completion
  registers: [registry],
});

export const llmCost = new Counter({
  name: 'vule_llm_cost_usd_total',
  help: 'Total LLM cost in USD',
  labelNames: ['provider', 'model'] as const,
  registers: [registry],
});

// === Finding Metrics ===

export const findings = new Counter({
  name: 'vule_findings_total',
  help: 'Total findings by severity and type',
  labelNames: ['severity', 'type'] as const,
  registers: [registry],
});

export const dimensionsEvaluated = new Counter({
  name: 'vule_dimensions_evaluated_total',
  help: 'Total dimension evaluations by dimension name',
  labelNames: ['dimension'] as const,
  registers: [registry],
});

// === Scan Metrics ===

export const filesScanned = new Counter({
  name: 'vule_scan_files_total',
  help: 'Files scanned',
  labelNames: ['outcome'] as const, // success/error/skipped
  registers: [registry],
});

export const scanDuration = new Histogram({
  name: 'vule_scan_duration_seconds',
  help: 'Full scan duration in seconds',
  labelNames: ['mode'] as const, // ast/llm/consensus
  buckets: [0.5, 1, 5, 10, 30, 60, 120, 300, 600],
  registers: [registry],
});

// === CPG Metrics ===

export const cpgNodes = new Histogram({
  name: 'vule_cpg_nodes',
  help: 'CPG node count per file',
  buckets: [0, 10, 50, 100, 500, 1000, 5000, 10000],
  registers: [registry],
});

export const cpgEdges = new Histogram({
  name: 'vule_cpg_edges',
  help: 'CPG edge count per file',
  buckets: [0, 10, 50, 100, 500, 1000, 5000, 10000],
  registers: [registry],
});

// === UVRS Metrics ===

export const uvrsScore = new Histogram({
  name: 'vule_uvrs_score',
  help: 'UVRS score distribution',
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  registers: [registry],
});

// === HTTP server metrics (for web UI) ===

export const httpRequests = new Counter({
  name: 'vule_http_requests_total',
  help: 'HTTP requests',
  labelNames: ['method', 'path', 'status'] as const,
  registers: [registry],
});

/** Render metrics in Prometheus text format */
export function getMetricsText(): Promise<string> {
  return registry.metrics();
}

/** Reset all metrics (for tests) */
export function resetMetrics(): void {
  registry.resetMetrics();
}
