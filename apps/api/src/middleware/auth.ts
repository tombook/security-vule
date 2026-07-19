import type { Context, Next } from 'hono';
import { jwtVerify, SignJWT } from 'jose';
import { config } from '../config';
import { unauthorized } from './error';

export interface JwtPayload {
  sub: string;
  email: string;
  role: string;
  tenant_id: string;
  portal: string;
  customer_id?: string;
  exp?: number;
}

const secret = new TextEncoder().encode(config.jwtSecret);

export async function signAccessToken(payload: Omit<JwtPayload, 'exp'>): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${config.jwtAccessTtl}s`)
    .setSubject(payload.sub)
    .sign(secret);
}

export async function verifyAccessToken(token: string): Promise<JwtPayload> {
  try {
    const { payload } = await jwtVerify(token, secret, { algorithms: ['HS256'] });
    if (!payload.sub || typeof payload.sub !== 'string' || payload.sub.length === 0) {
      throw unauthorized('Token missing subject');
    }
    return payload as unknown as JwtPayload;
  } catch (err) {
    throw unauthorized('Invalid or expired token');
  }
}

export const authMiddleware = async (c: Context, next: Next) => {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    throw unauthorized('Missing Bearer token');
  }
  const token = auth.slice(7);
  const payload = await verifyAccessToken(token);
  c.set('user', {
    id: payload.sub,
    email: payload.email,
    role: payload.role,
    tenantId: payload.tenant_id,
    portal: (payload as any).portal,
    customerId: payload.customer_id,
  });
  console.log('[auth]', { sub: payload.sub, tenantId: payload.tenant_id, role: payload.role, portal: (payload as any).portal });
  await next();
};
