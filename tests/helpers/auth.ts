// tests/helpers/auth.ts
// JWT 测试 helper — 直接用 jose 签 token,避免起 API 进程

import { SignJWT } from 'jose';

const TEST_JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret-key-for-jwt-hs256-min-256-bits';

export interface TestTokenPayload {
  sub: string;
  email: string;
  role: string;
  tenant_id: string;
  portal: 'provider' | 'customer';
  customer_id?: string;
}

export async function signTestToken(payload: TestTokenPayload, expiresIn = 3600): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setSubject(payload.sub)
    .sign(new TextEncoder().encode(TEST_JWT_SECRET));
}

export async function authHeader(payload: TestTokenPayload): Promise<Record<string, string>> {
  const token = await signTestToken(payload);
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

export const TEST_JWT_SECRET_VALUE = TEST_JWT_SECRET;