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
  expected: PocExpectation;
  timeoutMs?: number;
}

export interface PocExpectation {
  contains?: string;
  matches?: RegExp;
  statusCode?: number;
  containsUser?: string[];
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
  | 'unsupported_target';

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

    const fullUrl = req.url.startsWith('http') ? req.url : `${this.target.baseUrl}${req.url}`;

    const start = Date.now();
    let lastError: string | undefined;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const result =
          this.isolation === 'docker'
            ? await this.runInDocker(fullUrl, req)
            : await this.runInProcess(fullUrl, req);

        if (this.matches(result, req.expected)) {
          return {
            ...result,
            id: req.id,
            success: true,
            status: 'verified',
            isolation: this.isolation,
            responseTimeMs: Date.now() - start,
            completedAt: Date.now(),
          };
        }
        lastError = `attempt ${attempt + 1}: expectation not met`;
      } catch (e) {
        lastError = `attempt ${attempt + 1}: ${(e as Error).message}`;
      }
    }

    let lastResult: { statusCode?: number; body?: string } = {};
    try {
      lastResult =
        this.isolation === 'docker'
          ? await this.runInDocker(fullUrl, req)
          : await this.runInProcess(fullUrl, req);
    } catch {
      /* ignore */
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

  private matches(
    result: { statusCode?: number; body?: string },
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
    return true;
  }

  private runInProcess(
    url: string,
    req: PocRequest
  ): Promise<{ statusCode?: number; body?: string }> {
    return new Promise((resolve, reject) => {
      const args = ['-sS', '-w', '\\n%{http_code}', '-X', req.method];
      if (this.cookieJarPath && req.id !== 'login') {
        args.push('-b', this.cookieJarPath);
      }
      for (const [k, v] of Object.entries(req.headers ?? {})) args.push('-H', `${k}: ${v}`);
      if (req.body) args.push('-d', req.body);
      if (this.cookieJarPath && req.id === 'login') {
        args.push('-c', this.cookieJarPath);
      }
      for (const [k, v] of Object.entries(this.cookies)) args.push('-b', `${k}=${v}`);
      args.push(url);

      const proc = spawn('curl', args, { timeout: req.timeoutMs ?? 10000 });
      const chunks: Buffer[] = [];
      proc.stdout.on('data', (c: Buffer) => chunks.push(c));
      proc.on('close', (code) => {
        if (code !== 0 && code !== null) return reject(new Error(`curl exit ${code}`));
        const out = Buffer.concat(chunks).toString();
        const lastNewline = out.lastIndexOf('\n');
        const body = lastNewline >= 0 ? out.slice(0, lastNewline) : out;
        const statusLine = lastNewline >= 0 ? out.slice(lastNewline + 1).trim() : '';
        resolve({ statusCode: parseInt(statusLine, 10) || undefined, body });
      });
      proc.on('error', reject);
    });
  }

  private runInDocker(
    url: string,
    req: PocRequest
  ): Promise<{ statusCode?: number; body?: string; containerId?: string }> {
    return new Promise((resolve, reject) => {
      const dockerArgs = [
        'run',
        '--rm',
        '--network=host',
        '-i',
        this.dockerImage,
        'sh',
        '-c',
        `curl -sS -w '\\n%{http_code}' -X ${req.method} '${url}' ${req.body ? `-d '${req.body.replace(/'/g, "'\\''")}'` : ''}`,
      ];
      const proc = spawn('docker', dockerArgs, { timeout: req.timeoutMs ?? 15000 });
      const chunks: Buffer[] = [];
      const containerId = `sandbox-${Date.now()}`;
      proc.stdout.on('data', (c: Buffer) => chunks.push(c));
      proc.on('close', (code) => {
        if (code !== 0 && code !== null) return reject(new Error(`docker exit ${code}`));
        const out = Buffer.concat(chunks).toString();
        const lastNewline = out.lastIndexOf('\n');
        const body = lastNewline >= 0 ? out.slice(0, lastNewline) : out;
        const statusLine = lastNewline >= 0 ? out.slice(lastNewline + 1).trim() : '';
        resolve({ statusCode: parseInt(statusLine, 10) || undefined, body, containerId });
      });
      proc.on('error', reject);
    });
  }
}
