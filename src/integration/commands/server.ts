/**
 * vule server — minimal HTTP server for live VuleEngine exploration.
 * Spec: §5.2 Web UI
 */
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
        return new Response(`<!DOCTYPE html><html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px">
          <h1>🌌 VuleEngine Web UI</h1>
          <p>Server running on port ${port}</p>
          <p>POST analysis results to <code>/api/report</code> (JSON VuleReport).</p>
          <p>GET <code>/api/health</code> for status.</p>
        </body></html>`, { headers: { 'content-type': 'text/html' } });
      }
      if (url.pathname === '/api/health') {
        return Response.json({ status: 'ok', version: '0.3.0' });
      }
      return new Response('Not Found', { status: 404 });
    },
  });
  console.log(`🌌 VuleEngine Web UI: http://localhost:${server.port}`);
}