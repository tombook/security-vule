/**
 * Example 4: Web UI server.
 *
 * Starts the Bun.serve HTTP server exposing:
 *   - GET /            → HTML dashboard
 *   - GET /healthz     → Kubernetes health probe
 *   - GET /metrics     → Prometheus metrics
 *
 * Run: bun run examples/web-ui/start.sh
 */
import { serverCommand } from '../../src/integration/commands/server.js';

const port = parseInt(process.env['PORT'] || '3000', 10);
console.log(`Starting VuleEngine web UI on port ${port}...`);
console.log(`  → http://localhost:${port}/`);
console.log(`  → http://localhost:${port}/healthz`);
console.log(`  → http://localhost:${port}/metrics`);

await serverCommand({ port });
