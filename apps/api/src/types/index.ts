import 'hono';
import type { PoolClient } from 'pg';

declare module 'hono' {
  interface ContextVariableMap {
    user: {
      id: string;
      email: string;
      role: string;
      tenantId: string;
      portal: string;
      customerId?: string;
    };
    pg: PoolClient;
  }
}
