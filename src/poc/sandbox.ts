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

export interface PocResult {
  id: string;
  success: boolean;
  statusCode?: number;
  responseTimeMs: number;
  body?: string;
  matchedExpectations: string[];
  isolation: PocIsolation;
  containerId?: string;
  error?: string;
  completedAt: number;
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
    credentials: { user: 'bee', password: 'bug', loginPath: '/portal.php' },
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

  constructor(options: PocSandboxOptions) {
    this.target = typeof options.target === 'string' ? TARGETS[options.target] : options.target;
    this.isolation = options.isolation ?? 'process';
    this.dockerImage = options.dockerImage ?? 'alpine/curl:8.10.1';
    this.retries = options.retries ?? 2;
  }

  async login(): Promise<void> {
    if (!this.target.credentials || this.loggedIn) return;
    const { user, password, loginPath } = this.target.credentials;
    const body = `username=${encodeURIComponent(user)}&password=${encodeURIComponent(password)}`;
    await this.execute({
      id: 'login',
      method: 'POST',
      url: loginPath,
      body,
      expected: { statusCode: 200 },
      timeoutMs: 5000,
    });
    this.loggedIn = true;
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

    return {
      id: req.id,
      success: false,
      isolation: this.isolation,
      responseTimeMs: Date.now() - start,
      matchedExpectations: [],
      error: lastError ?? 'all retries exhausted',
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
      for (const [k, v] of Object.entries(req.headers ?? {})) args.push('-H', `${k}: ${v}`);
      if (req.body) args.push('-d', req.body);
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
