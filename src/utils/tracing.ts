/**
 * OpenTelemetry tracing initialization for security-vule.
 *
 * Provides distributed tracing for LLM calls, dimension evaluations, and
 * multi-stage analysis pipelines. Exports via OTLP HTTP to a collector
 * (e.g., Grafana Tempo, Jaeger, Honeycomb).
 *
 * Usage:
 *   const span = tracer.startSpan('llm.call', { attributes: { provider, model } });
 *   try { ... } finally { span.end(); }
 */
import { trace, type Tracer } from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import {
  BatchSpanProcessor,
  ConsoleSpanExporter,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';

const SERVICE_NAME = 'security-vule';
const SERVICE_VERSION = '0.3.0';
const OTLP_ENDPOINT =
  process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] || 'http://localhost:4318/v1/traces';

let provider: NodeTracerProvider | null = null;
let initialized = false;

/** Initialize OpenTelemetry tracing (idempotent). */
export function initTracing(): void {
  if (initialized) return;
  initialized = true;

  const resource = resourceFromAttributes({
    [ATTR_SERVICE_NAME]: SERVICE_NAME,
    [ATTR_SERVICE_VERSION]: SERVICE_VERSION,
  });

  const exporter =
    process.env['OTEL_CONSOLE'] === 'true'
      ? new ConsoleSpanExporter()
      : new OTLPTraceExporter({ url: OTLP_ENDPOINT });

  const processor =
    process.env['OTEL_CONSOLE'] === 'true'
      ? new SimpleSpanProcessor(exporter)
      : new BatchSpanProcessor(exporter);

  provider = new NodeTracerProvider({ resource, spanProcessors: [processor] });
  provider.register();
}

/** Get tracer instance (auto-initializes on first use). */
export function getTracer(name = SERVICE_NAME): Tracer {
  if (!initialized) initTracing();
  return trace.getTracer(name, SERVICE_VERSION);
}

/** Convenience: wrap async fn in a span. */
export async function withSpan<T>(
  name: string,
  fn: () => Promise<T>,
  attributes: Record<string, string | number | boolean> = {}
): Promise<T> {
  const span = getTracer().startSpan(name, { attributes });
  try {
    return await fn();
  } catch (err) {
    span.recordException(err as Error);
    span.setStatus({ code: 2, message: (err as Error).message });
    throw err;
  } finally {
    span.end();
  }
}

/** Shutdown tracing (flushes pending spans). */
export async function shutdownTracing(): Promise<void> {
  if (provider) {
    await provider.shutdown();
    provider = null;
    initialized = false;
  }
}
