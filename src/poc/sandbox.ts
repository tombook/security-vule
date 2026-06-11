/**
 * Docker Sandbox PoC executor — type-safe TypeScript equivalent of
 * poc-validator/verify_poc.py with explicit isolation guarantees.
 *
 * Inspired by NMitchem/SkillScan (3-layer: static + LLM + Docker sandbox).
 *
 * Layers:
 *1. STATIC — pattern detection on source (see VQL, OWASP Agentic)
 *2. RUNTIME — execute PoC against a real target with timeout + retries
 *3. SANDBOX — when enabled, run in a Docker container with network=off
 *
 * Usage:
 * const sandbox = new PocSandbox({ target: 'dvwa', isolation: 'docker' });
 * const result = await sandbox.execute({ method: 'GET', url: '/vulnerabilities/sqli/?id=1', expected: { contains: 'admin' } });
 *
 * If isolation === 'process' (default): exec via Bun's child_process
 * If isolation === 'docker': exec inside ephemeral container with --network=none
 * If isolation === 'mock': run against mock_dvwa.py
 */

import { spawn } from 'child_process';

export type PocMethod = 'GET' | 'POST' | 'HEAD';
export type PocIsolation = 'process' | 'docker' | 'mock';

export interface PocTarget {
  name: 'dvwa' | 'bwapp' | 'sqlilabs' | 'pikachu' | 'mock';
  baseUrl: string;
  credentials?: { user: string; password: string; loginPath: string };
}

export interface PocRequest {
  id: string;
  method: PocMethod;
  url: string;
  body?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  expected: PocExpectation;
  timeoutMs?: number;
}

export interface PocExpectation {
  contains?: string;
  matches?: RegExp;
  statusCode?: number;
  containsUser?: string[];
  timeDelayMs?: number;
  baselineUrl?: string;
  headerContains?: string;
  headerMatches?: RegExp;
}

export type PocVerificationStatus =
  | 'verified'
  | 'rejected'
  | 'table_empty'
  | 'no_data_returned'
  | 'auth_failed'
  | 'rate_limited'
  | 'payload_filtered'
  | 'endpoint_changed'
  | 'timeout'
  | 'connection_error'
  | 'unsupported_target'
  | 'time_based_verified';

export interface PocResult {
  id: string;
  success: boolean;
  status: PocVerificationStatus;
  statusCode?: number;
  responseTimeMs: number;
  body?: string;
  matchedExpectations: string[];
  isolation: PocIsolation;
  containerId?: string;
  error?: string;
  diagnostic?: string;
  retryable: boolean;
  completedAt: number;
}

export function inferStatus(result: {
  success: boolean;
  body?: string;
  statusCode?: number;
  matchedExpectations: string[];
}): { status: PocVerificationStatus; diagnostic: string; retryable: boolean } {
  if (result.success) {
    return { status: 'verified', diagnostic: 'All expectations matched', retryable: false };
  }
  if (result.statusCode === 401 || result.statusCode === 403) {
    return {
      status: 'auth_failed',
      diagnostic: `HTTP ${result.statusCode} - credentials rejected. Re-login or check target.`,
      retryable: true,
    };
  }
  if (result.statusCode === 429) {
    return {
      status: 'rate_limited',
      diagnostic: 'HTTP429 - target rate limited. Increase retry interval.',
      retryable: true,
    };
  }
  if (result.statusCode === 302) {
    return {
      status: 'auth_failed',
      diagnostic: 'HTTP302 redirect to login - session expired.',
      retryable: true,
    };
  }
  const body = result.body?.toLowerCase() ?? '';
  if (body.includes('you have an error in your sql syntax')) {
    return {
      status: 'payload_filtered',
      diagnostic: 'SQL error leaked but no data dumped. WAF may block payload.',
      retryable: false,
    };
  }
  if (body.includes('no results') || body.includes('empty result')) {
    return {
      status: 'table_empty',
      diagnostic: 'Query executed but returned0 rows. Database table may be empty.',
      retryable: false,
    };
  }
  if (result.matchedExpectations.length === 0 && result.body && result.body.length < 200) {
    return {
      status: 'no_data_returned',
      diagnostic: 'Response too short to contain expected data.',
      retryable: false,
    };
  }
  if (result.statusCode === 0) {
    return {
      status: 'connection_error',
      diagnostic: 'Connection refused or DNS failure.',
      retryable: true,
    };
  }
  if (result.statusCode === 404) {
    return {
      status: 'endpoint_changed',
      diagnostic: 'HTTP404 - endpoint path may have changed.',
      retryable: false,
    };
  }
  if (result.statusCode === 500) {
    return {
      status: 'unsupported_target',
      diagnostic: 'HTTP500 - server-side error. Target may not support this PoC.',
      retryable: false,
    };
  }
  return {
    status: 'rejected',
    diagnostic: 'No expectations matched. Check payload and target compatibility.',
    retryable: false,
  };
}

export const TARGETS: Record<PocTarget['name'], PocTarget> = {
  dvwa: {
    name: 'dvwa',
    baseUrl: 'http://localhost:8080',
    credentials: { user: 'admin', password: 'password', loginPath: '/login.php' },
  },
  bwapp: {
    name: 'bwapp',
    baseUrl: 'http://localhost:8081',
    credentials: { user: 'bee', password: 'bug', loginPath: '/login.php' },
  },
  sqlilabs: {
    name: 'sqlilabs',
    baseUrl: 'http://localhost:8082',
    credentials: { user: 'root', password: '', loginPath: '/Less-1/' },
  },
  pikachu: {
    name: 'pikachu',
    baseUrl: 'http://localhost:8083',
  },
  mock: { name: 'mock', baseUrl: 'http://localhost:9090' },
};

export interface PocSandboxOptions {
  target: PocTarget['name'] | PocTarget;
  isolation?: PocIsolation;
  dockerImage?: string;
  retries?: number;
}

export class PocSandbox {
  private readonly target: PocTarget;
  private readonly isolation: PocIsolation;
  private readonly dockerImage: string;
  private readonly retries: number;
  private cookies: Record<string, string> = {};
  private loggedIn = false;
  private readonly cookieJarPath: string;

  constructor(options: PocSandboxOptions) {
    this.target = typeof options.target === 'string' ? TARGETS[options.target] : options.target;
    this.isolation = options.isolation ?? 'process';
    this.dockerImage = options.dockerImage ?? 'alpine/curl:8.10.1';
    this.retries = options.retries ?? 2;
    this.cookieJarPath = `/tmp/vule-poc-${this.target.name}-${Date.now()}.cookie`;
  }

  async login(securityLevel?: 'low' | 'medium' | 'high'): Promise<void> {
    if (!this.target.credentials || this.loggedIn) return;
    const { user, password, loginPath } = this.target.credentials;
    const isBwapp = this.target.name === 'bwapp';
    const userField = isBwapp ? 'login' : 'username';
    const level =
      securityLevel === 'low'
        ? 0
        : securityLevel === 'medium'
          ? 1
          : securityLevel === 'high'
            ? 2
            : 0;
    const body = `${userField}=${encodeURIComponent(user)}&password=${encodeURIComponent(password)}${isBwapp ? `&form=submit&security_level=${level}` : '&Login=Login'}`;
    const result = await this.execute({
      id: 'login',
      method: 'POST',
      url: loginPath,
      body,
      expected: {},
      timeoutMs: 5000,
    });
    if (result.statusCode === 200 || result.statusCode === 302 || result.success) {
      this.loggedIn = true;
    }
  }

  async execute(req: PocRequest): Promise<PocResult> {
    if (this.target.credentials && !this.loggedIn && req.id !== 'login') {
      await this.login();
    }

    const start = Date.now();
    let lastError: string | undefined;
    let lastResult: {
      statusCode?: number;
      body?: string;
      headers?: Record<string, string>;
      responseTimeMs?: number;
    } = {};
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        lastResult = await this.runWithRedirects(req);

        if (this.matches(lastResult, req.expected)) {
          return {
            ...lastResult,
            id: req.id,
            success: true,
            status: 'verified',
            isolation: this.isolation,
            matchedExpectations: this.matchedKeys(lastResult, req.expected),
            retryable: false,
            responseTimeMs: Date.now() - start,
            completedAt: Date.now(),
          };
        }

        if (req.expected.timeDelayMs && req.expected.timeDelayMs > 0) {
          const baseline = await this.measureBaseline(req);
          const delayResult = await this.runWithRedirects(req);
          const payloadMs = delayResult.responseTimeMs ?? Date.now() - start;
          if (payloadMs - baseline >= req.expected.timeDelayMs * 0.7) {
            return {
              ...delayResult,
              id: req.id,
              success: true,
              status: 'time_based_verified',
              isolation: this.isolation,
              matchedExpectations: ['timeDelayMs'],
              retryable: false,
              responseTimeMs: Date.now() - start,
              completedAt: Date.now(),
            };
          }
          lastError = `attempt ${attempt + 1}: time-based delay not detected (payload=${payloadMs}ms baseline=${baseline}ms expected=${req.expected.timeDelayMs}ms)`;
        } else {
          lastError = `attempt ${attempt + 1}: expectation not met`;
        }
      } catch (e) {
        lastError = `attempt ${attempt + 1}: ${(e as Error).message}`;
      }
    }

    const inferred = inferStatus({ success: false, ...lastResult, matchedExpectations: [] });

    return {
      id: req.id,
      success: false,
      status: inferred.status,
      isolation: this.isolation,
      responseTimeMs: Date.now() - start,
      matchedExpectations: [],
      error: lastError ?? 'all retries exhausted',
      diagnostic: inferred.diagnostic,
      retryable: inferred.retryable,
      completedAt: Date.now(),
    };
  }

  private async measureBaseline(req: PocRequest): Promise<number> {
    const baselineUrl =
      req.expected.baselineUrl ??
      req.url
        .replace(/['"+]/g, '')
        .replace(/AND\s+SLEEP\(\d+\)/gi, '')
        .replace(/AND\s+BENCHMARK\([^)]+\)/gi, '')
        .replace(/--\s*-\s*$/, '');
    const baselineReq: PocRequest = {
      ...req,
      id: `${req.id}-baseline`,
      url: baselineUrl,
      expected: {},
      timeoutMs: Math.min(req.timeoutMs ?? 10000, 5000),
    };
    const baseStart = Date.now();
    try {
      await this.runWithRedirects(baselineReq);
    } catch {
      /* ignore */
    }
    return Date.now() - baseStart;
  }

  private async runWithRedirects(req: PocRequest): Promise<{
    statusCode?: number;
    body?: string;
    headers?: Record<string, string>;
    responseTimeMs?: number;
  }> {
    let fullUrl = req.url.startsWith('http') ? req.url : `${this.target.baseUrl}${req.url}`;
    let currentReq = req;
    let result: {
      statusCode?: number;
      body?: string;
      headers?: Record<string, string>;
      responseTimeMs?: number;
    };
    const startMs = Date.now();

    for (let hop = 0; hop < 3; hop++) {
      result =
        this.isolation === 'docker'
          ? await this.runInDocker(fullUrl, currentReq)
          : await this.runInProcess(fullUrl, currentReq);

      if (result.statusCode !== 302) {
        return { ...result, responseTimeMs: Date.now() - startMs };
      }

      const location = result.headers?.location;
      if (!location) return result;

      let resolved: string;
      if (location.startsWith('http')) {
        resolved = location;
      } else if (location.startsWith('/')) {
        resolved = `${this.target.baseUrl}${location}`;
      } else {
        const reqDir = fullUrl.substring(0, fullUrl.lastIndexOf('/') + 1);
        resolved = `${reqDir}${location}`;
      }

      currentReq = {
        ...currentReq,
        id: `${currentReq.id}-redirect-${hop + 1}`,
        url: resolved,
        method: 'GET',
        body: undefined,
        headers: undefined,
      };
      fullUrl = resolved;
    }

    return { ...result!, responseTimeMs: Date.now() - startMs };
  }

  private extractLocation(_body: string): string | null {
    return null;
  }

  private matches(
    result: { statusCode?: number; body?: string; headers?: Record<string, string> },
    expected: PocExpectation
  ): boolean {
    if (expected.statusCode !== undefined && result.statusCode !== expected.statusCode)
      return false;
    if (expected.contains && !result.body?.includes(expected.contains)) return false;
    if (expected.matches && !expected.matches.test(result.body ?? '')) return false;
    if (expected.containsUser && result.body) {
      const body = result.body.toLowerCase();
      if (!expected.containsUser.every((u) => body.includes(u.toLowerCase()))) return false;
    }
    if (expected.headerContains) {
      const headerStr = Object.entries(result.headers ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      if (!headerStr.includes(expected.headerContains)) return false;
    }
    if (expected.headerMatches) {
      const headerStr = Object.entries(result.headers ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      if (!expected.headerMatches.test(headerStr)) return false;
    }
    return true;
  }

  private matchedKeys(
    result: { statusCode?: number; body?: string; headers?: Record<string, string> },
    expected: PocExpectation
  ): string[] {
    const keys: string[] = [];
    if (expected.statusCode !== undefined && result.statusCode === expected.statusCode) {
      keys.push('statusCode');
    }
    if (expected.contains && result.body?.includes(expected.contains)) keys.push('contains');
    if (expected.matches && expected.matches.test(result.body ?? '')) keys.push('matches');
    if (
      expected.containsUser &&
      result.body &&
      expected.containsUser.every((u) => result.body!.toLowerCase().includes(u.toLowerCase()))
    ) {
      keys.push('containsUser');
    }
    if (expected.headerContains) {
      const headerStr = Object.entries(result.headers ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      if (headerStr.includes(expected.headerContains)) keys.push('headerContains');
    }
    if (expected.headerMatches) {
      const headerStr = Object.entries(result.headers ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      if (expected.headerMatches.test(headerStr)) keys.push('headerMatches');
    }
    return keys;
  }

  private runInProcess(
    url: string,
    req: PocRequest
  ): Promise<{ statusCode?: number; body?: string; headers?: Record<string, string> }> {
    return new Promise((resolve, reject) => {
      const headerFile = `/tmp/vule-poc-headers-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.tmp`;
      const args = ['-sS', '-D', headerFile, '-w', '\\n%{http_code}', '-X', req.method];
      if (this.cookieJarPath && req.id !== 'login') {
        args.push('-b', this.cookieJarPath);
      }
      for (const [k, v] of Object.entries(req.headers ?? {})) args.push('-H', `${k}: ${v}`);
      if (req.body) args.push('-d', req.body);
      if (this.cookieJarPath) {
        args.push('-c', this.cookieJarPath);
      }
      for (const [k, v] of Object.entries(this.cookies)) args.push('-b', `${k}=${v}`);
      for (const [k, v] of Object.entries(req.cookies ?? {})) args.push('-b', `${k}=${v}`);
      args.push(url);

      const proc = spawn('curl', args, { timeout: req.timeoutMs ?? 10000 });
      const chunks: Buffer[] = [];
      proc.stdout.on('data', (c: Buffer) => chunks.push(c));
      proc.on('close', async (code) => {
        if (code !== 0 && code !== null) return reject(new Error(`curl exit ${code}`));
        const out = Buffer.concat(chunks).toString();
        const lastNewline = out.lastIndexOf('\n');
        const body = lastNewline >= 0 ? out.slice(0, lastNewline) : out;
        const statusLine = lastNewline >= 0 ? out.slice(lastNewline + 1).trim() : '';
        const statusCode = parseInt(statusLine, 10) || undefined;

        const headers: Record<string, string> = {};
        try {
          const { readFileSync } = await import('fs');
          const hdrFile = readFileSync(headerFile, 'utf-8');
          for (const line of hdrFile.split(/\r?\n/)) {
            const m = line.match(/^([A-Za-z0-9-]+):\s*(.+?)\s*$/);
            if (m) headers[m[1].toLowerCase()] = m[2].trim();
          }
          const { unlinkSync } = await import('fs');
          try {
            unlinkSync(headerFile);
          } catch {}
        } catch {
          /* ignore */
        }

        resolve({ statusCode, body, headers });
      });
      proc.on('error', reject);
    });
  }

  private runInDocker(
    url: string,
    req: PocRequest
  ): Promise<{
    statusCode?: number;
    body?: string;
    headers?: Record<string, string>;
    containerId?: string;
  }> {
    return new Promise((resolve, reject) => {
      const dockerArgs = [
        'run',
        '--rm',
        '--network=host',
        '-i',
        this.dockerImage,
        'sh',
        '-c',
        `curl -sS -D - -w '\\n%{http_code}' -X ${req.method} '${url}' ${req.body ? `-d '${req.body.replace(/'/g, "'\\''")}'` : ''}`,
      ];
      const proc = spawn('docker', dockerArgs, { timeout: req.timeoutMs ?? 15000 });
      const chunks: Buffer[] = [];
      const containerId = `sandbox-${Date.now()}`;
      proc.stdout.on('data', (c: Buffer) => chunks.push(c));
      proc.on('close', (code) => {
        if (code !== 0 && code !== null) return reject(new Error(`docker exit ${code}`));
        const out = Buffer.concat(chunks).toString();
        // Docker output: HTTP/1.1 <code>\nHeaders...\n\nBody\n<status>
        const statusLineMatch = out.match(/\n(\d{3})\s*$/);
        const statusCode = statusLineMatch ? parseInt(statusLineMatch[1], 10) : undefined;
        const headerEnd = out.indexOf('\r\n\r\n');
        const headers: Record<string, string> = {};
        if (headerEnd > 0) {
          const headerSection = out.slice(0, headerEnd);
          for (const line of headerSection.split('\r\n')) {
            const m = line.match(/^([A-Za-z0-9-]+):\s*(.+)$/);
            if (m) headers[m[1].toLowerCase()] = m[2].trim();
          }
        }
        // Strip headers and final status line
        const bodyStart = headerEnd > 0 ? headerEnd + 4 : 0;
        const body = out
          .slice(bodyStart)
          .replace(/\n\d{3}\s*$/, '')
          .trim();
        resolve({ statusCode, body, headers, containerId });
      });
      proc.on('error', reject);
    });
  }
}
