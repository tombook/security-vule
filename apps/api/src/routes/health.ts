import { Hono } from 'hono';
import { pool } from '../db/client';

export const healthRoute = new Hono()
  .get('/', async (c) => {
    const start = Date.now();
    let dbOk = false;
    try {
      const client = await pool.connect();
      try {
        await client.query('SELECT 1');
        dbOk = true;
      } finally {
        client.release();
      }
    } catch {}
    return c.json({
      status: dbOk ? 'ok' : 'degraded',
      db: dbOk ? 'ok' : 'down',
      latency_ms: Date.now() - start,
      ts: new Date().toISOString(),
    });
  });
