import type { Context, Next } from 'hono';
import { pool } from '../db/client';
import type { MiddlewareVariables } from '../types';

export const tenantMiddleware = async (c: Context, next: Next) => {
  const user = c.get('user' as keyof MiddlewareVariables) as MiddlewareVariables['user'];
  if (!user) throw new Error('tenantMiddleware requires authMiddleware first');

  const client = await pool.connect();
  try {
    await client.query(`SET app.current_tenant = '${user.tenantId}'`);
    await client.query(`SET app.current_user_role = '${user.role}'`);
    if (user.customerId) {
      await client.query(`SET app.current_customer = '${user.customerId}'`);
    }
    c.set('pg', client);
    await next();
  } finally {
    // Reset GUCs so the connection goes back to the pool clean (defence
    // against accidentally leaking tenant state into the next request
    // that happens to draw the same physical connection).
    try {
      await client.query('RESET app.current_tenant');
      await client.query('RESET app.current_user_role');
      await client.query('RESET app.current_customer');
    } catch { /* ignore — connection may be broken */ }
    client.release();
  }
};