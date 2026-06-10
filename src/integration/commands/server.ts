/**
 * vule server — minimal HTTP server for live VuleEngine exploration.
 * Spec: §5.2 Web UI + Sprint E4 observability
 */
import { healthCheck, onShutdown, registerShutdownHandlers } from '../../utils/health.js';
import { getMetricsText } from '../../utils/metrics.js';
import { shutdownTracing } from '../../utils/tracing.js';

export interface ServerOptions {
  port: number;
}

export async function serverCommand(options: ServerOptions): Promise<void> {
  const port = options.port;
  const server = Bun.serve({
    port,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === '/') {
        return new Response(
          `<!DOCTYPE html><html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px">
          <h1>🌌 VuleEngine Web UI</h1>
          <p>Server running on port ${port}</p>
          <p>POST analysis results to <code>/api/report</code> (JSON VuleReport).</p>
          <p>Endpoints:</p>
          <ul>
            <li>GET <code>/healthz</code> — health check (Kubernetes probes)</li>
            <li>GET <code>/metrics</code> — Prometheus metrics</li>
            <li>GET <code>/api/health</code> — legacy health (deprecated)</li>
          </ul>
        </body></html>`,
          { headers: { 'content-type': 'text/html' } }
        );
      }
      if (url.pathname === '/healthz' || url.pathname === '/api/health') {
        const health = healthCheck();
        return Response.json(health, {
          status: health.status === 'unhealthy' ? 503 : 200,
        });
      }
      if (url.pathname === '/metrics') {
        return new Response(await getMetricsText(), {
          headers: { 'content-type': 'text/plain; version=0.0.4' },
        });
      }
      return new Response('Not Found', { status: 404 });
    },
  });
  console.log(`🌌 VuleEngine Web UI: http://localhost:${server.port}`);

  // Register graceful shutdown
  onShutdown(() => {
    server.stop();
    void shutdownTracing();
  });
  registerShutdownHandlers();
}
