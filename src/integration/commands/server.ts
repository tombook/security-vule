/**
 * vule server — HTTP server with live VuleEngine visualization.
 * Spec: §5.2 Web UI + Sprint E4 observability
 *
 * Endpoints:
 *   GET  /             → VuleEngine dashboard
 *   GET  /report       → Interactive HTML report (reads latest /api/report)
 *   POST /api/report   → Submit VuleReport JSON; rendered at /report
 *   GET  /api/report   → Latest submitted VuleReport (JSON)
 *   GET  /healthz      → Kubernetes health probe
 *   GET  /metrics      → Prometheus metrics (13 metrics)
 */
import { healthCheck, onShutdown, registerShutdownHandlers } from '../../utils/health.js';
import { getMetricsText } from '../../utils/metrics.js';
import { shutdownTracing } from '../../utils/tracing.js';
import { generateHTMLReport } from '../../visualization/html-report.js';
import type { VuleReport } from '../../engine/vule-report.js';

export interface ServerOptions {
  port: number;
}

const DASHBOARD_HTML = (port: number): string => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🌌 VuleEngine Web UI</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      margin: 0;
      padding: 32px;
    }
    h1 { color: #58a6ff; margin: 0 0 8px; }
    .tag { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
      max-width: 1100px;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      transition: border-color 0.2s;
    }
    .card:hover { border-color: #58a6ff; }
    .card h3 { color: #58a6ff; margin: 0 0 8px; font-size: 16px; }
    .card p { margin: 4px 0; font-size: 14px; color: #8b949e; }
    .card code {
      display: block;
      margin-top: 10px;
      padding: 8px 10px;
      background: #0d1117;
      border-radius: 4px;
      font-size: 12px;
      color: #c9d1d9;
    }
    .section { margin-top: 32px; max-width: 1100px; }
    .upload {
      background: #161b22;
      border: 2px dashed #30363d;
      border-radius: 8px;
      padding: 32px;
      text-align: center;
      cursor: pointer;
    }
    .upload.dragover { border-color: #58a6ff; background: #1c2128; }
    .upload p { margin: 8px 0; }
    .btn {
      display: inline-block;
      background: #238636;
      color: #fff;
      padding: 10px 20px;
      border-radius: 6px;
      border: none;
      cursor: pointer;
      font-size: 14px;
      margin-top: 12px;
    }
    .btn:hover { background: #2ea043; }
    .status { font-size: 13px; margin-top: 12px; }
    .status.ok { color: #56d364; }
    .status.err { color: #f85149; }
  </style>
</head>
<body>
  <h1>🌌 VuleEngine Web UI</h1>
  <p class="tag">Cosmic-galaxy aligned vulnerability scanner · port ${port}</p>

  <div class="grid">
    <div class="card">
      <h3>GET /healthz</h3>
      <p>Kubernetes health probe</p>
      <code>curl http://localhost:${port}/healthz</code>
    </div>
    <div class="card">
      <h3>GET /metrics</h3>
      <p>Prometheus metrics (13 series)</p>
      <code>curl http://localhost:${port}/metrics</code>
    </div>
    <div class="card">
      <h3>GET /report</h3>
      <p>Interactive HTML report (D3 + Plotly)</p>
      <code><a href="/report" style="color:#58a6ff">Open /report →</a></code>
    </div>
    <div class="card">
      <h3>GET /api/report</h3>
      <p>Latest VuleReport as JSON</p>
      <code>curl http://localhost:${port}/api/report</code>
    </div>
  </div>

  <div class="section">
    <h2 style="color:#58a6ff">Submit a VuleReport</h2>
    <div class="upload" id="drop">
      <p><strong>Drop a VuleReport JSON file here</strong></p>
      <p>or click to choose</p>
      <input type="file" id="file" accept=".json" style="display:none">
      <button class="btn" id="btn">Choose file…</button>
      <p class="status" id="status"></p>
    </div>
    <p style="margin-top:16px;font-size:13px;color:#8b949e">
      Or POST directly:
      <code style="display:inline-block;margin-left:8px">curl -X POST -H "content-type: application/json" --data-binary @report.json http://localhost:${port}/api/report</code>
    </p>
  </div>

  <script>
    const drop = document.getElementById('drop');
    const file = document.getElementById('file');
    const btn = document.getElementById('btn');
    const status = document.getElementById('status');

    function postJSON(json) {
      fetch('/api/report', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: json
      })
        .then(r => r.json().then(b => ({ ok: r.ok, body: b })))
        .then(({ ok, body }) => {
          status.className = 'status ' + (ok ? 'ok' : 'err');
          status.textContent = ok
            ? '✅ Report accepted (nodeCount=' + body.nodeCount + '). <a href="/report" style="color:#58a6ff">View →</a>'
            : '❌ ' + (body.error || 'invalid report');
        })
        .catch(e => {
          status.className = 'status err';
          status.textContent = '❌ ' + e.message;
        });
    }

    btn.addEventListener('click', () => file.click());
    file.addEventListener('change', () => {
      if (file.files[0]) postJSON(file.files[0]);
    });
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('dragover'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop.addEventListener('drop', e => {
      e.preventDefault();
      drop.classList.remove('dragover');
      if (e.dataTransfer.files[0]) postJSON(e.dataTransfer.files[0]);
    });
  </script>
</body>
</html>`;

export async function serverCommand(options: ServerOptions): Promise<void> {
  const port = options.port;
  let latestReport: VuleReport | null = null;

  const server = Bun.serve({
    port,
    async fetch(req) {
      const url = new URL(req.url);

      if (url.pathname === '/') {
        return new Response(DASHBOARD_HTML(port), {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }

      if (url.pathname === '/report') {
        if (!latestReport) {
          return new Response(
            `<!DOCTYPE html><html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:32px">
            <h1>No report submitted yet</h1>
            <p>POST a VuleReport JSON to <code>/api/report</code>, then refresh this page.</p>
            <p><a href="/" style="color:#58a6ff">← Back to dashboard</a></p>
            </body></html>`,
            { headers: { 'content-type': 'text/html; charset=utf-8' }, status: 404 }
          );
        }
        return new Response(generateHTMLReport(latestReport), {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }

      if (url.pathname === '/api/report') {
        if (req.method === 'GET') {
          if (!latestReport) {
            return Response.json({ error: 'no report submitted' }, { status: 404 });
          }
          return Response.json(latestReport);
        }
        if (req.method === 'POST') {
          try {
            const body = (await req.json()) as VuleReport;
            if (!body.version || !Array.isArray(body.topRisk)) {
              return Response.json(
                { error: 'invalid VuleReport: missing version or topRisk' },
                { status: 400 }
              );
            }
            latestReport = body;
            return Response.json({
              ok: true,
              nodeCount: body.nodeCount,
              topRisk: body.topRisk.length,
            });
          } catch (e) {
            return Response.json(
              { error: `parse error: ${(e as Error).message}` },
              { status: 400 }
            );
          }
        }
        return new Response('Method Not Allowed', { status: 405 });
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
  console.log(`   Dashboard:     http://localhost:${server.port}/`);
  console.log(
    `   Report viewer: http://localhost:${server.port}/report (POST first to /api/report)`
  );
  console.log(`   Health:        http://localhost:${server.port}/healthz`);
  console.log(`   Metrics:       http://localhost:${server.port}/metrics`);

  onShutdown(() => {
    server.stop();
    void shutdownTracing();
  });
  registerShutdownHandlers();
}
