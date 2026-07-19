/**
 * security-vule Web Server — HTTP API + UI dashboard.
 *
 * Pages:
 *   GET /            → Landing page
 *   GET /scan        → Scan page (upload / paste code)
 *   GET /report/:id  → Report viewer
 *   GET /settings    → Settings page
 *   GET /healthz     → Health probe
 *
 * API:
 *   POST /api/scan         → Run a scan on code or file upload
 *   GET  /api/scan/:id     → Get scan status + results
 */

import { analyzeFile, type VulnerabilityFinding } from './engine/analyzer.js';
import { renderLanding, renderScanPage, renderReport, renderSettings, renderError } from './server/ui.js';

const PORT = parseInt(process.env['PORT'] || '3001', 10);

interface ScanJob {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  target: string;
  language: string;
  startedAt: number;
  finishedAt?: number;
  findings?: VulnerabilityFinding[];
  filesScanned?: number;
  error?: string;
}

const jobs: Map<string, ScanJob> = new Map();

function genId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function detectLang(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'php': return 'php';
    case 'py': return 'python';
    case 'js': case 'jsx': case 'mjs': case 'cjs': return 'javascript';
    case 'ts': case 'tsx': return 'typescript';
    case 'java': return 'java';
    case 'go': return 'go';
    case 'c': case 'h': case 'cpp': case 'hpp': return 'c';
    case 'rs': return 'rust';
    default: return 'javascript';
  }
}

async function runScan(job: ScanJob, code: string): Promise<void> {
  try {
    const result = await analyzeFile(job.target, code, job.language);
    job.findings = result.vulnerabilities;
    job.filesScanned = 1;
    job.status = 'completed';
    job.finishedAt = Date.now();
  } catch (e) {
    job.status = 'failed';
    job.error = (e as Error).message;
    job.finishedAt = Date.now();
  }
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    try {
      // === Pages ===
      if (url.pathname === '/' || url.pathname === '/index.html') {
        return html(renderLanding(PORT));
      }

      if (url.pathname === '/scan') {
        return html(renderScanPage(PORT));
      }

      if (url.pathname.startsWith('/report/')) {
        const id = url.pathname.slice('/report/'.length);
        const job = jobs.get(id);
        if (!job) return html(renderError('Report not found', `No scan for id: ${id}`), 404);
        return html(renderReport(job, PORT));
      }

      if (url.pathname === '/settings') {
        return html(renderSettings(PORT));
      }

      // === Health ===
      if (url.pathname === '/healthz' || url.pathname === '/api/health') {
        return Response.json({
          status: 'ok',
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          totalScans: jobs.size,
        });
      }

      // === API: POST /api/scan ===
      if (url.pathname === '/api/scan' && req.method === 'POST') {
        const ct = req.headers.get('content-type') ?? '';
        let target: string;
        let language: string;
        let code: string;

        if (ct.includes('multipart/form-data')) {
          const form = await req.formData();
          target = (form.get('target') as string) || 'uploaded';
          language = (form.get('language') as string) || 'auto';
          const file = form.get('file') as File | null;
          if (file) {
            code = await file.text();
            target = file.name;
          } else {
            code = (form.get('code') as string) || '';
          }
        } else if (ct.includes('application/json')) {
          const body = await req.json() as { target?: string; language?: string; code?: string };
          target = body.target || 'inline';
          language = body.language || 'auto';
          code = body.code || '';
        } else {
          return Response.json({ error: 'unsupported content-type' }, { status: 415 });
        }

        if (!code.trim()) {
          return Response.json({ error: 'no code provided' }, { status: 400 });
        }

        if (language === 'auto') {
          language = detectLang(target);
        }

        const id = genId();
        const job: ScanJob = {
          id,
          status: 'running',
          target,
          language,
          startedAt: Date.now(),
        };
        jobs.set(id, job);

        // Fire and forget
        runScan(job, code);

        return Response.json({
          ok: true,
          id,
          statusUrl: `/api/scan/${id}`,
          reportUrl: `/report/${id}`,
        });
      }

      // === API: GET /api/scan/:id ===
      if (url.pathname.startsWith('/api/scan/') && req.method === 'GET') {
        const id = url.pathname.slice('/api/scan/'.length);
        const job = jobs.get(id);
        if (!job) return Response.json({ error: 'not found' }, { status: 404 });
        return Response.json(job);
      }

      // === API: GET /api/findings ===
      if (url.pathname === '/api/findings' && req.method === 'GET') {
        const all: ScanJob[] = Array.from(jobs.values())
          .sort((a, b) => b.startedAt - a.startedAt)
          .slice(0, 20);
        return Response.json(all);
      }

      return html(renderError('404 Not Found', `No route for ${url.pathname}`), 404);
    } catch (e) {
      console.error('[server] error:', e);
      return html(renderError('Internal error', (e as Error).message), 500);
    }
  },
});

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

console.log(`\n🌌 security-vule Web UI ready: http://localhost:${server.port}`);
console.log(`   Pages:    / · /scan · /report/:id · /settings`);
console.log(`   API:      /healthz · /api/scan · /api/scan/:id`);
console.log(`   Stop:     Ctrl+C`);
