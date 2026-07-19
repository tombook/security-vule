// tests/helpers/api.ts
// API 测试基础设施:启动/停止 API,HTTP 请求助手,JWT 工厂

import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { SignJWT } from 'jose';
import { TENANT_A, TENANT_B, CUSTOMER_C, CUSTOMER_D, USERS, type Role } from './seed';

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-only-jwt-secret-please-change-in-prod-must-be-32-chars';
const JWT_SECRET_BYTES = new TextEncoder().encode(JWT_SECRET);

export const API_BASE = process.env.TEST_API_BASE ?? 'http://localhost:3000';

let apiProcess: ChildProcess | null = null;
let apiStartedByTests = false;

export async function ensureApiRunning(): Promise<void> {
  try {
    const res = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(2000) });
    if (res.ok) return;
  } catch {}
  await startApi();
}

export async function startApi(): Promise<void> {
  if (apiProcess) return;
  const apiDir = resolve(import.meta.dir, '..', '..', 'apps', 'api');
  apiProcess = spawn('bun', ['run', 'src/index.ts'], {
    cwd: apiDir,
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule',
      FRONTEND_URL: 'http://localhost:5173',
      PORT: '3000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Forward child stdio to our own stdout/stderr so test runs surface
  // the API's console.log / console.error (Hono request logger, error
  // stacks, …) and not just swallow them into a closed pipe.
  apiProcess.stdout?.on('data', (d) => process.stdout.write(`[api] ${d}`));
  apiProcess.stderr?.on('data', (d) => process.stderr.write(`[api-err] ${d}`));
  apiProcess.on('error', (err) => {
    console.error('[api-spawn-error]', err);
  });
  apiProcess.on('exit', (code, signal) => {
    if (code !== 0 && code !== null) {
      console.error(`[api-exit] code=${code} signal=${signal}`);
    }
  });
  apiStartedByTests = true;
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch {}
    await sleep(500);
  }
}

export async function stopApi(): Promise<void> {
  if (!apiProcess) return;
  apiProcess.kill('SIGTERM');
  await new Promise<void>((resolve) => {
    if (!apiProcess) return resolve();
    apiProcess.on('exit', () => resolve());
    setTimeout(() => resolve(), 2000);
  });
  apiProcess = null;
  apiStartedByTests = false;
}

export interface TestToken {
  sub: string;
  email: string;
  role: Role;
  tenant_id: string;
  portal: 'provider' | 'customer';
  customer_id?: string;
}

export async function signTestJwt(payload: TestToken, expiresIn = 1800, secretOverride?: string): Promise<string> {
  const secret = secretOverride ? new TextEncoder().encode(secretOverride) : JWT_SECRET_BYTES;
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setSubject(payload.sub)
    .sign(secret);
}

export async function authHeader(payload: TestToken): Promise<Record<string, string>> {
  const token = await signTestJwt(payload);
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

export const TOKENS = {
  ownerA: (): TestToken => ({ sub: USERS.ownerA, email: 'owner-a@test.dev', role: 'ProviderOwner', tenant_id: TENANT_A, portal: 'provider' }),
  adminA: (): TestToken => ({ sub: USERS.adminA, email: 'admin-a@test.dev', role: 'ProviderAdmin', tenant_id: TENANT_A, portal: 'provider' }),
  engineerA: (): TestToken => ({ sub: USERS.engineerA, email: 'eng-a@test.dev', role: 'ProviderEngineer', tenant_id: TENANT_A, portal: 'provider' }),
  viewerA: (): TestToken => ({ sub: USERS.viewerA, email: 'view-a@test.dev', role: 'ProviderViewer', tenant_id: TENANT_A, portal: 'provider' }),
  adminC: (): TestToken => ({ sub: USERS.adminC, email: 'admin-c@test.dev', role: 'CustomerAdmin', tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_C }),
  developerC: (): TestToken => ({ sub: USERS.developerC, email: 'dev-c@test.dev', role: 'CustomerDeveloper', tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_C }),
  viewerC: (): TestToken => ({ sub: USERS.viewerC, email: 'view-c@test.dev', role: 'CustomerViewer', tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_C }),
  ownerB: (): TestToken => ({ sub: USERS.ownerB, email: 'owner-b@test.dev', role: 'ProviderOwner', tenant_id: TENANT_B, portal: 'provider' }),
  adminC_D: (): TestToken => ({ sub: USERS.adminC, email: 'admin-c@test.dev', role: 'CustomerAdmin', tenant_id: TENANT_A, portal: 'customer', customer_id: CUSTOMER_D }),
};

export async function httpGet(path: string, token?: TestToken): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (token) Object.assign(headers, await authHeader(token));
  const res = await fetch(`${API_BASE}${path}`, { headers, signal: AbortSignal.timeout(5000) });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

export async function httpPost(path: string, data: any, token?: TestToken): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (token) Object.assign(headers, await authHeader(token));
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(5000),
  });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

export async function httpPatch(path: string, data: any, token?: TestToken): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (token) Object.assign(headers, await authHeader(token));
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(5000),
  });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

export async function httpDelete(path: string, token?: TestToken): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (token) Object.assign(headers, await authHeader(token));
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'DELETE',
    headers,
    signal: AbortSignal.timeout(5000),
  });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

export async function httpPut(path: string, data: any, token?: TestToken): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (token) Object.assign(headers, await authHeader(token));
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(5000),
  });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

export { TENANT_A, TENANT_B, CUSTOMER_C, CUSTOMER_D, USERS, type Role } from './seed';