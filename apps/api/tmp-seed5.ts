import { Pool } from "pg";
import crypto from "crypto";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
const tenantId = "11111111-1111-1111-1111-111111111111";
const customerId = "22222222-2222-2222-2222-222222222222";

async function main() {
  const { rows: ep } = await pg.query("SELECT id FROM core.projects WHERE tenant_id = $1 AND customer_id = $2 LIMIT 1", [tenantId, customerId]);
  let projectId = ep[0]?.id;
  if (!projectId) {
    const { rows } = await pg.query("INSERT INTO core.projects (tenant_id, customer_id, name, slug, status) VALUES ($1,$2,'Demo','demo','active') RETURNING id", [tenantId, customerId]);
    projectId = rows[0].id;
  }
  const ruleId = "0aaa0001-0000-0000-0000-000000000001";
  const engineId = "0eee0001-0000-0000-0000-000000000001";
  await pg.query("INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ($1,'semgrep','semgrep','1.0.0',true) ON CONFLICT (id) DO NOTHING", [engineId]);
  await pg.query("INSERT INTO detection.rules (id, engine_id, rule_external_id, title, severity) VALUES ($1,$2,'sqli-test','SQL Injection','critical') ON CONFLICT (id) DO NOTHING", [ruleId, engineId]);

  const scanRunId = crypto.randomUUID();
  await pg.query(
    `INSERT INTO detection.scan_runs (id, tenant_id, customer_id, project_id, status, started_at) VALUES ($1,$2,$3,$4,'done', NOW())`,
    [scanRunId, tenantId, customerId, projectId]
  );

  const fid = crypto.randomUUID();
  await pg.query(
    `INSERT INTO detection.findings (id, tenant_id, customer_id, project_id, scan_run_id, rule_id, title, description, severity, cwe_ids, file_path, start_line, end_line, code_snippet, status, engines, confidence)
     VALUES ($1,$2,$3,$4,$5,$6,'SQL Injection in query parameter','User input concatenated into SQL without parameterization, allowing injection attacks.','critical',ARRAY['89'],'app/api/users.py',42,45,'cursor.execute("SELECT * FROM users WHERE id = " + user_input)','open',ARRAY['semgrep'],'high') RETURNING id`,
    [fid, tenantId, customerId, projectId, scanRunId, ruleId]
  );
  console.log("Finding:", fid);
  console.log("Project:", projectId);
  await pg.end();
}
main().catch(e => { console.error(e); process.exit(1); });