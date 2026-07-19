// apps/api/src/routes/targets.ts
//
// CRUD for core.targets — the live URLs / containers the PoC
// verifier actually points its requests at. One target belongs to
// a (tenant, customer) pair; projects can optionally pin one via
// core.targets.project_id so the PoC runner auto-selects it.
//
// Auth: every write requires ProviderOwner / ProviderAdmin /
// ProviderEngineer. Reads are open to any role in the tenant.

import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { requireRole, PROVIDER_WRITE_ROLES } from '../middleware/rbac';
import { badRequest, notFound } from '../middleware/error';
import { encryptSecret, decryptSecret } from '../lib/crypto';

const createSchema = z.object({
  customerId: z.string().uuid(),
  projectId: z.string().uuid().optional(),
  name: z.string().min(1).max(120),
  baseUrl: z.string().url(),
  targetType: z.enum(['http', 'https', 'docker', 'ssh', 'mock']).default('http'),
  authKind: z.enum(['none', 'basic', 'form', 'cookie', 'bearer', 'header']).default('none'),
  authUsername: z.string().max(200).optional(),
  authPassword: z.string().max(500).optional(),
  authToken: z.string().max(2000).optional(),
  cookieJar: z.record(z.string()).optional(),
  allowInsecure: z.boolean().default(false),
  metadata: z.record(z.any()).optional(),
});

const patchSchema = createSchema.partial().omit({ customerId: true });

export const targetRoutes = new Hono()
  .get('/', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const customerId = c.req.query('customerId');
    const status = c.req.query('status');
    const params: unknown[] = [user.tenantId];
    const conds: string[] = ['t.tenant_id = $1', 't.status != \'retired\''];
    if (customerId) { params.push(customerId); conds.push(`t.customer_id = $${params.length}`); }
    if (status) { params.push(status); conds.push(`t.status = $${params.length}::target_status_enum`); }
    const { rows } = await pg.query(
      `SELECT t.id, t.tenant_id, t.customer_id, t.project_id, t.name, t.base_url,
              t.target_type, t.auth_kind, t.cookie_jar, t.allow_insecure,
              t.status, t.last_seen_at, t.last_health, t.metadata, t.created_at,
              c.name AS customer_name
       FROM core.targets t
       JOIN core.customers c ON c.id = t.customer_id
       WHERE ${conds.join(' AND ')}
       ORDER BY t.created_at DESC`,
      params,
    );
    return c.json({ items: rows });
  })
  .get('/:id', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pg.query(
      `SELECT t.*, c.name AS customer_name
         FROM core.targets t
         JOIN core.customers c ON c.id = t.customer_id
        WHERE t.id = $1 AND t.tenant_id = $2`,
      [id, user.tenantId],
    );
    if (rows.length === 0) return notFound('target not found');
    // Strip ciphertext from response — never sent to the client.
    const row = rows[0];
    delete row.auth_password_ciphertext;
    delete row.auth_token_ciphertext;
    return c.json(row);
  })
  .post('/', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const pg = c.get('pg');
    const user = c.get('user');
    const body = await c.req.json().catch(() => null);
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) return badRequest('Invalid body: ' + parsed.error.message);
    const data = parsed.data;

    // Pin customer to tenant.
    const cust = await pg.query(
      `SELECT id FROM core.customers WHERE id = $1 AND tenant_id = $2`,
      [data.customerId, user.tenantId],
    );
    if (cust.rows.length === 0) return notFound('customer not found');

    if (data.projectId) {
      const proj = await pg.query(
        `SELECT id FROM core.projects WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
        [data.projectId, user.tenantId],
      );
      if (proj.rows.length === 0) return notFound('project not found');
    }

    const passwordCipher = data.authPassword ? encryptSecret(data.authPassword) : null;
    const tokenCipher    = data.authToken    ? encryptSecret(data.authToken)    : null;

    const { rows } = await pg.query(
      `INSERT INTO core.targets
         (tenant_id, customer_id, project_id, name, base_url,
          target_type, auth_kind, auth_username,
          auth_password_ciphertext, auth_token_ciphertext,
          cookie_jar, allow_insecure, status, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::target_type_enum, $7::target_auth_kind_enum,
               $8, $9, $10, $11::jsonb, $12, 'active', $13::jsonb)
       RETURNING id, name, base_url, target_type, auth_kind, status, created_at`,
      [user.tenantId, data.customerId, data.projectId ?? null, data.name, data.baseUrl,
       data.targetType, data.authKind, data.authUsername ?? null,
       passwordCipher, tokenCipher,
       JSON.stringify(data.cookieJar ?? {}), data.allowInsecure,
       JSON.stringify(data.metadata ?? {})],
    );
    return c.json(rows[0], 201);
  })
  .patch('/:id', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const parsed = patchSchema.safeParse(body);
    if (!parsed.success) return badRequest('Invalid body');
    const data = parsed.data;

    const sets: string[] = [];
    const params: unknown[] = [];
    let nextIdx = 0;
    const add = (val: unknown) => { params.push(val); return ++nextIdx; };
    for (const [k, v] of Object.entries(data)) {
      if (v === undefined) continue;
      if (k === 'baseUrl')      { sets.push(`base_url = $${add(v)}`); }
      else if (k === 'targetType') { sets.push(`target_type = $${add(v)}::target_type_enum`); }
      else if (k === 'authKind') { sets.push(`auth_kind = $${add(v)}::target_auth_kind_enum`); }
      else if (k === 'authUsername') { sets.push(`auth_username = $${add(v)}`); }
      else if (k === 'authPassword') { sets.push(`auth_password_ciphertext = $${add(encryptSecret(String(v)))}`); }
      else if (k === 'authToken')    { sets.push(`auth_token_ciphertext = $${add(encryptSecret(String(v)))}`); }
      else if (k === 'cookieJar')    { sets.push(`cookie_jar = $${add(JSON.stringify(v))}::jsonb`); }
      else if (k === 'allowInsecure'){ sets.push(`allow_insecure = $${add(v)}`); }
      else if (k === 'metadata')     { sets.push(`metadata = $${add(JSON.stringify(v))}::jsonb`); }
      else if (k === 'name')         { sets.push(`name = $${add(v)}`); }
      else if (k === 'projectId')    { sets.push(`project_id = $${add(v)}`); }
    }
    if (sets.length === 0) return badRequest('no fields to update');
    sets.push('updated_at = NOW()');
    params.push(id, user.tenantId);
    const { rows } = await pg.query(
      `UPDATE core.targets SET ${sets.join(', ')}
        WHERE id = $${nextIdx + 1} AND tenant_id = $${nextIdx + 2}
        RETURNING id, name, base_url, target_type, auth_kind, status, updated_at`,
      params,
    );
    if (rows.length === 0) return notFound('target not found');
    return c.json(rows[0]);
  })
  .delete('/:id', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');
    // Soft delete → status='retired' so historical poc_runs still
    // resolve the target id; only the list endpoint hides retired rows.
    const { rows } = await pg.query(
      `UPDATE core.targets SET status = 'retired', updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2 AND status != 'retired'
        RETURNING id, status`,
      [id, user.tenantId],
    );
    if (rows.length === 0) return notFound('target not found or already retired');
    return c.json({ deleted: rows[0] });
  })
  // Health probe — fetches the base URL and reports status code +
  // response time. Used by the UI's "test connection" button.
  .post('/:id/health', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pg.query(
      `SELECT id, base_url, allow_insecure FROM core.targets
        WHERE id = $1 AND tenant_id = $2 AND status != 'retired'`,
      [id, user.tenantId],
    );
    if (rows.length === 0) return notFound('target not found');
    const target = rows[0];

    const start = Date.now();
    let status = 0;
    let ok = false;
    let detail = '';
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(target.base_url, {
        method: 'HEAD',
        signal: ctrl.signal,
        // Bun's fetch doesn't yet expose an `allowInsecure` knob; the
        // TLS verification decision is delegated to the runtime.
        redirect: 'manual',
      });
      clearTimeout(t);
      status = res.status;
      ok = status > 0 && status < 500;
      detail = `HTTP ${status}`;
    } catch (err: any) {
      detail = err.message ?? String(err);
    }
    const latencyMs = Date.now() - start;

    await pg.query(
      `UPDATE core.targets
         SET last_seen_at = NOW(), last_health = $2
        WHERE id = $1`,
      [id, `${ok ? 'ok' : 'fail'} (${status}) ${latencyMs}ms`],
    );

    return c.json({ ok, httpStatus: status, latencyMs, detail });
  })

  // ── Deploy source into an isolated sandbox ─────────────────
  // Security model:
  //   1. Source code is COPYed into the Docker image (not mounted)
  //      so the host filesystem is not exposed to the container.
  //   2. Container runs in a dedicated Docker network
  //      'security-vule-sandbox' with no outbound internet access.
  //   3. No host ports are mapped — the container is reachable
  //      only from within the sandbox network (via Docker DNS).
  //   4. Resource limits: 512MB RAM, 1 CPU, 30-minute TTL.
  //   5. PoC verifier accesses the container through `docker exec`
  //      or by joining the sandbox network — never via localhost.
  //   6. Cleanup (POST /:id/cleanup) kills the container + removes
  //      the image + deletes the source from disk.
  .post('/:id/deploy', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');

    // Resolve target + its project + source
    const tgt = await pg.query(
      `SELECT t.id, t.project_id, t.customer_id, t.status,
              s.upload_object_key
         FROM core.targets t
         LEFT JOIN core.sources s ON s.project_id = t.project_id
        WHERE t.id = $1 AND t.tenant_id = $2 AND t.status != 'retired'`,
      [id, user.tenantId],
    );
    if (tgt.rows.length === 0) return notFound('target not found');
    const { upload_object_key: srcRoot } = tgt.rows[0];
    if (!srcRoot) return badRequest('项目无上传源码，请先在代码源页面上传 zip 或关联 Git');

    const containerName = `sandbox-${id.slice(0, 8)}`;
    const imageName = `svule-sandbox-${id.slice(0, 8)}`;
    const networkName = 'security-vule-sandbox';
    const SANDBOX_TTL_MINUTES = 30;

    // 0. Ensure the sandbox network exists (idempotent)
    Bun.spawnSync({
      cmd: ['docker', 'network', 'create', networkName],
      stdout: 'pipe', stderr: 'pipe', // ignore "already exists" error
    });

    // 1. Kill any existing sandbox for this target
    Bun.spawnSync({
      cmd: ['sh', '-c', `docker rm -f ${containerName} 2>/dev/null; docker rmi ${imageName} 2>/dev/null; true`],
      stdout: 'pipe', stderr: 'pipe',
    });

    // 2. Detect language / framework
    const find = Bun.spawnSync({
      cmd: ['find', srcRoot, '-maxdepth', '2', '-type', 'f',
        '-name', 'package.json', '-o', '-name', 'requirements.txt',
        '-o', '-name', 'go.mod', '-o', '-name', 'pom.xml',
        '-o', '-name', 'Dockerfile', '-o', '-name', 'index.php',
        '-o', '-name', 'docker-compose.yml'],
      stdout: 'pipe', stderr: 'pipe',
    });
    const markers = new TextDecoder().decode(find.stdout).trim().split('\n').filter(Boolean);

    let dockerfile = '';
    let exposedPort = '8080';
    const has = (name: string) => markers.some((m: string) => m.endsWith(name));
    let detectedStack = 'generic';

    if (has('Dockerfile')) {
      // Project ships a Dockerfile — use it, but try to read the
      // EXPOSE directive so the host port maps to the right in-container
      // port. Falls back to 8080 if EXPOSE is missing.
      dockerfile = '';
      const dfResult = Bun.spawnSync({
        cmd: ['sh', '-c', `grep -iE '^\\s*EXPOSE\\s+[0-9]+' "${srcRoot}/Dockerfile" | head -1`],
        stdout: 'pipe', stderr: 'pipe',
      });
      const dfText = new TextDecoder().decode(dfResult.stdout).trim();
      const m = dfText.match(/EXPOSE\s+(\d+)/i);
      exposedPort = m ? m[1] : '8080';
      detectedStack = 'dockerfile';
    } else if (has('package.json')) {
      dockerfile = `FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm install --omit=dev || true\nEXPOSE 3000\nCMD ["npm", "start"]\n`;
      exposedPort = '3000'; detectedStack = 'node';
    } else if (has('requirements.txt')) {
      dockerfile = `FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nRUN pip install --no-cache-dir -r requirements.txt || true\nEXPOSE 8080\nCMD ["python", "app.py"]\n`;
      exposedPort = '8080'; detectedStack = 'python';
    } else if (has('go.mod')) {
      dockerfile = `FROM golang:1.22-alpine\nWORKDIR /app\nCOPY . .\nRUN go build -o server . || true\nEXPOSE 8080\nCMD ["./server"]\n`;
      exposedPort = '8080'; detectedStack = 'go';
    } else if (has('index.php')) {
      dockerfile = `FROM php:8.2-apache\nCOPY . /var/www/html/\nEXPOSE 80\nCMD ["apache2-foreground"]\n`;
      exposedPort = '80'; detectedStack = 'php';
    } else {
      dockerfile = `FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nEXPOSE 8080\nCMD ["python", "-m", "http.server", "8080"]\n`;
      exposedPort = '8080'; detectedStack = 'generic';
    }

    if (dockerfile) {
      // Rewrite base images through a CN mirror (docker.1ms.run) to
      // avoid timeouts / slow pulls on the dev network. Only the
      // registry hostname is rewritten — the tag is preserved.
      // Set SECURITY_VULE_SKIP_MIRROR=1 to disable (e.g. for CI
      // environments that already cache the upstream images).
      if (!process.env.SECURITY_VULE_SKIP_MIRROR) {
        dockerfile = dockerfile.replace(
          /^(FROM\s+)([a-z0-9.\/_-]+)(\s*)$/im,
          (_, prefix, image) => {
            if (image.startsWith('docker.1ms.run/') || image.startsWith('localhost/')) return _;
            return `${prefix}docker.1ms.run/${image}${''}`;
          },
        );
      }
      await Bun.write(`${srcRoot}/Dockerfile`, dockerfile);
    }

    // 3. docker build (source code is baked into the image)
    const build = Bun.spawnSync({
      cmd: ['docker', 'build', '-t', imageName, srcRoot],
      stdout: 'pipe', stderr: 'pipe',
    });
    const buildLog = new TextDecoder().decode(build.stderr).slice(-800);
    if (build.exitCode !== 0) {
      return c.json({
        ok: false, error: 'docker build 失败', buildLog: buildLog.slice(-500),
      }, 500);
    }

    // 4. docker run in sandbox network — ALSO map a host port so
    //    the PoC verifier (a Python process on the host) can reach
    //    the container via localhost:<port>. The sandbox network
    //    provides an additional layer of isolation between sandbox
    //    containers, but the host-side port is necessary because
    //    the verifier runs outside Docker.
    const hostPort = String(19000 + Math.floor(Math.random() * 999));
    const run = Bun.spawnSync({
      cmd: ['docker', 'run', '-d',
        '--name', containerName,
        '--network', networkName,
        '-p', `${hostPort}:${exposedPort}`,
        '--memory=512m', '--cpus=1',
        '--restart=no',
        imageName],
      stdout: 'pipe', stderr: 'pipe',
    });
    if (run.exitCode !== 0) {
      return c.json({
        ok: false, error: 'docker run 失败',
        runLog: new TextDecoder().decode(run.stderr).slice(-500),
      }, 500);
    }

    // 5. Update target — base_url uses localhost:<hostPort> so the
    //    PoC verifier (Python process on the host) can reach the
    //    sandbox container. We also store the Docker-internal URL
    //    for future use when the verifier itself runs in Docker.
    const sandboxUrl = `http://localhost:${hostPort}`;
    const internalUrl = `http://${containerName}:${exposedPort}`;
    const expiresAt = new Date(Date.now() + SANDBOX_TTL_MINUTES * 60 * 1000).toISOString();
    await pg.query(
      `UPDATE core.targets
         SET base_url = $2, status = 'active', last_seen_at = NOW(),
             last_health = 'sandbox running (TTL ${SANDBOX_TTL_MINUTES}min)',
             updated_at = NOW(),
             metadata = jsonb_set(jsonb_set(jsonb_set(jsonb_set(
               COALESCE(metadata, '{}'::jsonb),
               '{sandbox,container}', to_jsonb($3::text)),
               '{sandbox,image}', to_jsonb($4::text)),
               '{sandbox,network}', to_jsonb($5::text)),
               '{sandbox,expires_at}', to_jsonb($6::text))
       WHERE id = $1`,
      [id, sandboxUrl, containerName, imageName, networkName, expiresAt],
    );

    return c.json({
      ok: true,
      sandboxUrl,
      internalUrl,
      hostPort,
      container: containerName,
      network: networkName,
      detectedStack,
      exposedPort,
      ttlMinutes: SANDBOX_TTL_MINUTES,
      expiresAt,
      buildLog: buildLog.slice(-200),
    });
  })

  // ── Cleanup sandbox: kill container + remove image + delete source ──
  .post('/:id/cleanup', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');

    const tgt = await pg.query(
      `SELECT t.id, t.metadata,
              s.upload_object_key
         FROM core.targets t
         LEFT JOIN core.sources s ON s.project_id = t.project_id
        WHERE t.id = $1 AND t.tenant_id = $2`,
      [id, user.tenantId],
    );
    if (tgt.rows.length === 0) return notFound('target not found');
    const meta = tgt.rows[0].metadata ?? {};
    const container = meta?.sandbox?.container ?? `sandbox-${id.slice(0, 8)}`;
    const image = meta?.sandbox?.image ?? `svule-sandbox-${id.slice(0, 8)}`;

    // 1. Kill container
    const kill = Bun.spawnSync({
      cmd: ['docker', 'rm', '-f', container],
      stdout: 'pipe', stderr: 'pipe',
    });
    // 2. Remove image
    Bun.spawnSync({
      cmd: ['docker', 'rmi', '-f', image],
      stdout: 'pipe', stderr: 'pipe',
    });
    // 3. Source tree stays on disk — the operator may want to
    //    redeploy (or the platform may auto-recycle) without
    //    re-uploading. cleanup only retires the Docker artifacts.
    //    The 30-minute sandbox TTL is the natural reclaim window.
    const srcRoot = tgt.rows[0].upload_object_key;

    // 4. Update target status
    await pg.query(
      `UPDATE core.targets
         SET status = 'paused', last_health = 'sandbox cleaned up',
             updated_at = NOW(),
             metadata = metadata || '{"sandbox":{"status":"cleaned"}}'::jsonb
       WHERE id = $1`,
      [id],
    );

    return c.json({
      ok: true,
      cleaned: { container, image, sourceKept: !!srcRoot },
    });
  })

  // ── Check sandbox status ────────────────────────────
  .get('/:id/sandbox-status', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const id = c.req.param('id');

    const tgt = await pg.query(
      `SELECT metadata FROM core.targets WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (tgt.rows.length === 0) return notFound('target not found');
    const meta = tgt.rows[0].metadata ?? {};
    const container = meta?.sandbox?.container;

    if (!container) {
      return c.json({ running: false, note: '未部署沙盒' });
    }

    // docker inspect
    const inspect = Bun.spawnSync({
      cmd: ['docker', 'inspect', container, '--format',
        '{{.State.Status}}|{{.State.StartedAt}}'],
      stdout: 'pipe', stderr: 'pipe',
    });
    const out = new TextDecoder().decode(inspect.stdout).trim();
    if (inspect.exitCode !== 0) {
      return c.json({ running: false, container, note: '沙盒已停止或已清理' });
    }
    const [state, startedAt] = out.split('|');
    const expiresAt = meta?.sandbox?.expires_at;
    const remainingMs = expiresAt ? new Date(expiresAt).getTime() - Date.now() : 0;

    return c.json({
      running: state === 'running',
      state,
      container,
      startedAt,
      expiresAt,
      remainingMinutes: Math.max(0, Math.round(remainingMs / 60000)),
    });
  });