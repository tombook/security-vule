/**
 * security-vule Web Server — product-grade UI.
 *
 * Pages:
 * GET / → Landing page (value prop + scan CTA)
 * GET /scan → Scan page (upload or run on server)
 * GET /report/:id → Report viewer (risk cards + D3 + fix guidance)
 * GET /settings → Configuration page
 * GET /healthz → Kubernetes health probe (JSON)
 * GET /metrics → Prometheus metrics
 *
 * API:
 * POST /api/scan → Run a scan on uploaded code or path
 * GET /api/scan/:id → Get scan status + results
 * POST /api/report → Submit external VuleReport
 * GET /api/report → Latest VuleReport
 *
 * Design principles:
 * -3-second value proposition on landing
 * - Input → Insight flow (no manual JSON)
 * - Fix guidance (not just findings)
 * - Shareable URLs
 */

import { healthCheck, onShutdown, registerShutdownHandlers } from '../../utils/health.js';
import { getMetricsText } from '../../utils/metrics.js';
import { shutdownTracing } from '../../utils/tracing.js';
import { generateHTMLReport } from '../../visualization/html-report.js';
import type { VuleReport } from '../../engine/vule-report.js';
import {
  renderLanding,
  renderScanPage,
  renderReportViewer,
  renderSettings,
  renderShareCard,
  renderErrorPage,
} from './ui/pages.js';
import { VuleSandboxBridge, reportToMarkdown } from '../../poc/vule-sandbox-bridge.js';
import { DomXssVerifier } from '../../poc/dom-xss-verifier.js';
import type { BridgeReport } from '../../poc/vule-sandbox-bridge.js';

export interface ServerOptions {
  port: number;
}

interface ScanJob {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  target: string;
  language: string;
  startedAt: number;
  finishedAt?: number;
  report?: VuleReport;
  error?: string;
}

const scanJobs: Map<string, ScanJob> = new Map();
let latestReport: VuleReport | null = null;
let latestBridgeReport: BridgeReport | null = null;

export async function serverCommand(options: ServerOptions): Promise<void> {
  const port = options.port;
  const server = Bun.serve({
    port,
    async fetch(req) {
      const url = new URL(req.url);

      try {
        if (url.pathname === '/' || url.pathname === '/index.html') {
          return html(renderLanding(port));
        }

        if (url.pathname === '/scan') {
          return html(renderScanPage(port));
        }

        if (url.pathname.startsWith('/report/')) {
          const id = url.pathname.slice('/report/'.length);
          const job = scanJobs.get(id);
          if (!job || !job.report)
            return html(renderErrorPage('Report not found', `No scan found for id: ${id}`), 404);
          return html(renderReportViewer(job));
        }

        if (url.pathname.startsWith('/share/')) {
          const id = url.pathname.slice('/share/'.length);
          const job = scanJobs.get(id);
          if (!job || !job.report) return html(renderErrorPage('Report not found', ''), 404);
          return html(renderShareCard(job));
        }

        if (url.pathname === '/settings') {
          return html(renderSettings(port));
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

        if (url.pathname === '/api/scan' && req.method === 'POST') {
          return await handleScanSubmit(req);
        }

        if (url.pathname.startsWith('/api/scan/') && req.method === 'GET') {
          const id = url.pathname.slice('/api/scan/'.length);
          const job = scanJobs.get(id);
          if (!job) return Response.json({ error: 'not found' }, { status: 404 });
          return Response.json(job);
        }

        if (url.pathname === '/api/report' && req.method === 'POST') {
          try {
            const body = (await req.json()) as VuleReport;
            if (!body.version || !Array.isArray(body.topRisk)) {
              return Response.json({ error: 'invalid VuleReport' }, { status: 400 });
            }
            latestReport = body;
            return Response.json({
              ok: true,
              nodeCount: body.nodeCount,
              topRisk: body.topRisk.length,
            });
          } catch (e) {
            return Response.json({ error: (e as Error).message }, { status: 400 });
          }
        }

        if (url.pathname === '/api/report' && req.method === 'GET') {
          if (!latestReport) return Response.json({ error: 'no report' }, { status: 404 });
          return Response.json(latestReport);
        }

        if (url.pathname === '/api/report/html' && req.method === 'GET') {
          if (!latestReport) return new Response('No report submitted', { status: 404 });
          return new Response(generateHTMLReport(latestReport), {
            headers: { 'content-type': 'text/html; charset=utf-8' },
          });
        }

        if (url.pathname === '/api/poc/verify' && req.method === 'POST') {
          return await handlePocVerify(req);
        }

        if (url.pathname === '/api/poc/dom-xss' && req.method === 'POST') {
          return await handleDomXssVerify(req);
        }

        if (url.pathname === '/api/poc/report' && req.method === 'GET') {
          if (!latestBridgeReport)
            return Response.json(
              { error: 'no poc report yet. POST /api/poc/verify first' },
              { status: 404 }
            );
          return Response.json({
            generatedAt: latestBridgeReport.generatedAt,
            totalVulns: latestBridgeReport.totalVulns,
            verifiedVulns: latestBridgeReport.verifiedVulns,
            verificationRate: latestBridgeReport.verificationRate,
            uvrsDistribution: latestBridgeReport.uvrsDistribution,
            verifications: latestBridgeReport.verifications.map((v) => ({
              id: v.id,
              vulnType: v.vulnType,
              target: v.target,
              verified: v.verified,
              confidence: v.confidence,
              attempts: v.attempts,
              successes: v.successes,
            })),
          });
        }

        if (url.pathname === '/api/poc/report/markdown' && req.method === 'GET') {
          if (!latestBridgeReport) return new Response('No POC report yet', { status: 404 });
          return new Response(reportToMarkdown(latestBridgeReport), {
            headers: { 'content-type': 'text/markdown; charset=utf-8' },
          });
        }

        if (url.pathname.startsWith('/assets/') || url.pathname === '/favicon.ico') {
          return new Response('Not Found', { status: 404 });
        }

        return html(renderErrorPage('404 — Not Found', `No route for ${url.pathname}`), 404);
      } catch (e) {
        console.error('server error:', e);
        return html(renderErrorPage('Internal error', (e as Error).message), 500);
      }
    },
  });
  console.log(`\n🌌 security-vule Web UI ready: http://localhost:${server.port}`);
  console.log(` pages: / · /scan · /report/:id · /settings`);
  console.log(` api: /healthz · /metrics · /api/scan`);

  onShutdown(() => {
    server.stop();
    void shutdownTracing();
  });
  registerShutdownHandlers();
}

async function handleScanSubmit(req: Request): Promise<Response> {
  const contentType = req.headers.get('content-type') ?? '';
  let target: string;
  let language: string;
  let code: string | undefined;

  if (contentType.includes('multipart/form-data')) {
    const form = await req.formData();
    target = (form.get('target') as string) ?? 'uploaded';
    language = (form.get('language') as string) ?? 'auto';
    const file = form.get('file') as File | null;
    if (!file) return Response.json({ error: 'no file' }, { status: 400 });
    code = await file.text();
  } else if (contentType.includes('application/json')) {
    const body = (await req.json()) as { target?: string; language?: string; code?: string };
    target = body.target ?? 'inline';
    language = body.language ?? 'auto';
    code = body.code;
  } else {
    return Response.json({ error: 'unsupported content-type' }, { status: 415 });
  }

  const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const job: ScanJob = {
    id,
    status: 'running',
    target,
    language,
    startedAt: Date.now(),
  };
  scanJobs.set(id, job);

  await runScan(job, code);
  return Response.json({ ok: true, id, statusUrl: `/api/scan/${id}`, reportUrl: `/report/${id}` });
}

async function runScan(job: ScanJob, code?: string): Promise<void> {
  try {
    const { evaluateOwaspAgenticTop10 } = await import('../../llm/owasp-agentic.js');
    const { createCPG } = await import('../../engine/cpg/index.js');
    const { VuleEngine } = await import('../../engine/vule-engine.js');

    const source = code ?? (job.target.startsWith('/') ? await readFileSafe(job.target) : '');
    if (!source) {
      job.status = 'failed';
      job.error = 'Could not read source';
      job.finishedAt = Date.now();
      return;
    }

    await new Promise((r) => setTimeout(r, 50));

    const cpg = createCPG(
      new Map(),
      [],
      job.language as 'php' | 'python' | 'javascript' | 'typescript'
    );
    const sinks = cpg.sinkNodes().map((n) => n.id);
    const engine = new VuleEngine(cpg, sinks, []);
    const _r = engine.analyze();
    void _r;

    const lines = source.split('\n');
    const findings: Array<{
      id: string;
      file: string;
      line: number;
      code: string;
      vulnType: string;
      uvrs: number;
      level: ReturnType<typeof getRiskLevel>;
      dominantDimension: string;
      contributions: Record<string, number>;
    }> = [];
    const patterns: Array<{
      regex: RegExp;
      type: string;
      severity: ReturnType<typeof getRiskLevel>;
      dim: string;
    }> = [
      {
        regex: /\beval\s*\(/i,
        type: 'Code Injection (eval)',
        severity: 'CRITICAL',
        dim: 'gravity',
      },
      { regex: /\bsystem\s*\(/i, type: 'Command Injection', severity: 'CRITICAL', dim: 'gravity' },
      { regex: /\bmysql_query\s*\(/i, type: 'SQL Injection', severity: 'CRITICAL', dim: 'gravity' },
      { regex: /\bexec\s*\(/i, type: 'Command Execution', severity: 'CRITICAL', dim: 'kepler' },
      {
        regex: /\bfile_get_contents\s*\(/i,
        type: 'Local File Inclusion',
        severity: 'HIGH',
        dim: 'tidal',
      },
      {
        regex: /echo\s+\$_(GET|POST|REQUEST)/i,
        type: 'Reflected XSS',
        severity: 'HIGH',
        dim: 'kepler',
      },
      {
        regex: /password\s*=\s*["']\w{4,}/i,
        type: 'Hardcoded Credential',
        severity: 'HIGH',
        dim: 'darkMatter',
      },
      {
        regex: /\bunserialize\s*\(/i,
        type: 'Insecure Deserialization',
        severity: 'HIGH',
        dim: 'chaos',
      },
      {
        regex: /\bmd5\s*\(|\bsha1\s*\(/i,
        type: 'Weak Cryptography',
        severity: 'MEDIUM',
        dim: 'information',
      },
      {
        regex:
          /(move_uploaded_file|copy\s*\(.*\$_FILES|file_put_contents\s*\(.*\$_FILES|chmod\s*\(.*upload)/i,
        type: 'Insecure File Upload',
        severity: 'HIGH',
        dim: 'fileUpload',
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        p.regex.lastIndex = 0;
        if (p.regex.test(lines[i] ?? '')) {
          p.regex.lastIndex = 0;
          findings.push({
            id: `${job.target}:${i + 1}:${p.type}`,
            file: job.target,
            line: i + 1,
            code: (lines[i] ?? '').trim().slice(0, 200),
            vulnType: p.type,
            uvrs: severityScore(p.severity),
            level: p.severity,
            dominantDimension: p.dim,
            contributions: { [p.dim]: severityScore(p.severity), entropy: 0.3, kepler: 0.4 },
          });
        }
      }
    }

    const owaspResult = evaluateOwaspAgenticTop10(source, job.language);
    if (owaspResult.matches.length > 0) {
      for (const m of owaspResult.matches) {
        for (const h of m.matches) {
          findings.push({
            id: `${job.target}:${h.line}:ASI${m.entry.id}`,
            file: job.target,
            line: h.line,
            code: h.snippet,
            vulnType: m.entry.title,
            uvrs: Math.max(severityScore(m.entry.severity), 0.5),
            level: severityFromOwaso(m.entry.severity),
            dominantDimension: m.entry.dimensions[0] ?? 'gravity',
            contributions: {
              [m.entry.dimensions[0] ?? 'gravity']: m.normalizedScore,
              gravity: 0.4,
            },
          });
        }
      }
    }

    findings.sort((a, b) => b.uvrs - a.uvrs);
    const topRisk = findings.slice(0, 20).map((f) => ({
      nodeId: f.id,
      file: f.file,
      line: f.line,
      code: f.code,
      vulnType: f.vulnType,
      uvrs: f.uvrs,
      level: f.level as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      dominantDimension: f.dominantDimension,
      contributions: f.contributions,
    }));

    const dist: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const n of topRisk) dist[n.level] = (dist[n.level] ?? 0) + 1;

    job.report = {
      version: '1.1.0',
      generatedAt: new Date().toISOString(),
      nodeCount: findings.length,
      riskDistribution: dist as Record<typeof RiskLevel.LOW, number>,
      topRisk,
    };
    latestReport = job.report;
    job.status = 'completed';
    job.finishedAt = Date.now();
  } catch (e) {
    job.status = 'failed';
    job.error = (e as Error).message;
    job.finishedAt = Date.now();
  }
}

async function handlePocVerify(req: Request): Promise<Response> {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      targets?: string[];
      types?: string[];
      detailed?: boolean;
    };
    const targets = body.targets as ('dvwa' | 'bwapp' | 'sqlilabs' | 'pikachu')[] | undefined;
    const typesFilter = body.types as string[] | undefined;
    const detailed = body.detailed ?? false;
    const bridge = new VuleSandboxBridge({ targets });
    const allVerifications = await bridge.verifyAll();
    // Apply types filter if provided
    const verifications = typesFilter
      ? allVerifications.filter((v) => typesFilter.includes(v.vulnType))
      : allVerifications;
    const report = bridge.generateReport(verifications);
    latestBridgeReport = report;

    // Per-status diagnostic breakdown
    const statusBreakdown: Record<string, number> = {};
    for (const v of verifications) {
      const s = v.bestResult?.status ?? (v.verified ? 'verified' : 'unknown');
      statusBreakdown[s] = (statusBreakdown[s] ?? 0) + 1;
    }

    return Response.json({
      ok: true,
      totalVulns: report.totalVulns,
      verifiedVulns: report.verifiedVulns,
      verificationRate: report.verificationRate,
      uvrsDistribution: report.uvrsDistribution,
      filters: { targets, types: typesFilter },
      statusBreakdown,
      results: verifications.map((v) => {
        const base: Record<string, unknown> = {
          id: v.id,
          vulnType: v.vulnType,
          target: v.target,
          verified: v.verified,
          confidence: v.confidence,
        };
        if (detailed) {
          base.attempts = v.attempts;
          base.successes = v.successes;
          base.status = v.bestResult?.status ?? (v.verified ? 'verified' : 'no_match');
          base.diagnostic = v.bestResult?.diagnostic ?? null;
          base.matchedExpectations = v.bestResult?.matchedExpectations ?? [];
          if (v.bestResult?.error) base.error = v.bestResult.error;
        }
        return base;
      }),
    });
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 500 });
  }
}

function getRiskLevel(): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  return 'HIGH';
}
function severityScore(s: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'): number {
  return s === 'CRITICAL'
    ? 0.95
    : s === 'HIGH'
      ? 0.78
      : s === 'MEDIUM'
        ? 0.55
        : s === 'LOW'
          ? 0.3
          : 0.1;
}
function severityFromOwaso(s: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  return s === 'critical' ? 'CRITICAL' : s === 'high' ? 'HIGH' : s === 'medium' ? 'MEDIUM' : 'LOW';
}

async function readFileSafe(path: string): Promise<string> {
  try {
    return await Bun.file(path).text();
  } catch {
    return '';
  }
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

async function handleDomXssVerify(req: Request): Promise<Response> {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      baseUrl?: string;
      targets?: Array<{
        url: string;
        inputSelector?: string;
        triggerSelector?: string;
        payload?: string;
        domSelector?: string;
        detectionMethod?: 'inner_html' | 'page_error' | 'console_log';
        detectionPattern?: string;
      }>;
    };
    const baseUrl = body.baseUrl ?? 'http://localhost:8083';
    const targets = body.targets ?? [
      {
        url: '/vul/xss/xss_dom_x.php?text=DOMXSS_PW',
        domSelector: 'body',
        detectionMethod: 'inner_html' as const,
        detectionPattern: 'DOMXSS_PW',
      },
    ];
    const verifier = new DomXssVerifier({ baseUrl });
    const results: unknown[] = [];
    for (const t of targets) {
      try {
        const r = await verifier.verify({
          id: `dom-xss-${Date.now()}`,
          url: t.url,
          inputSelector: t.inputSelector ?? 'input[name="text"]',
          triggerSelector: t.triggerSelector ?? 'button,input[type=submit]',
          payload: t.payload ?? 'DOMXSS_PW',
          domSelector: t.domSelector ?? 'body',
          detectionMethod: t.detectionMethod ?? 'inner_html',
          detectionPattern: t.detectionPattern ?? 'DOMXSS_PW',
        });
        results.push(r);
      } catch (e) {
        results.push({ error: (e as Error).message });
      }
    }
    await verifier.close();
    return Response.json({
      ok: true,
      baseUrl,
      results,
      note: 'Playwright headless verification for DOM XSS — see src/poc/dom-xss-verifier.ts',
    });
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 500 });
  }
}
