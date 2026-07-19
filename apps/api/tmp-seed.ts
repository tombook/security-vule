import { Pool } from "pg";
import crypto from "crypto";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
const tenantId = "11111111-1111-1111-1111-111111111111";
const customerId = "22222222-2222-2222-2222-222222222222";

async function main() {
  const { rows: existingProj } = await pg.query(
    "SELECT id FROM core.projects WHERE tenant_id = $1 AND customer_id = $2 LIMIT 1",
    [tenantId, customerId]
  );
  let projectId;
  if (existingProj.length > 0) {
    projectId = existingProj[0].id;
  } else {
    const { rows } = await pg.query(
      `INSERT INTO core.projects (tenant_id, customer_id, name, slug, status) VALUES ($1, $2, 'Demo Project', 'demo-project', 'active') RETURNING id`,
      [tenantId, customerId]
    );
    projectId = rows[0].id;
  }
  console.log("Project:", projectId);

  const engineId = "aeee0001-0000-0000-0000-000000000001";
  const ruleId   = "arrr0001-0000-0000-0000-000000000001";
  await pg.query(`INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ($1, 'semgrep', 'semgrep', '1.0.0', true) ON CONFLICT (id) DO NOTHING`, [engineId]);
  await pg.query(`INSERT INTO detection.rules (id, engine_id, rule_external_id, title, severity) VALUES ($1, $2, 'python-sqli-test', 'SQL Injection in query parameter', 'critical') ON CONFLICT (id) DO NOTHING`, [ruleId, engineId]);

  const findingId = crypto.randomUUID();
  await pg.query(
    `INSERT INTO detection.findings (id, tenant_id, customer_id, project_id, rule_id, engine_id, title, description, severity, cwe_ids, file_path, start_line, end_line, code_snippet, status)
     VALUES ($1, $2, $3, $4, $5, $6,
       'SQL Injection in query parameter',
       'User input is concatenated directly into SQL query without parameterization, allowing SQL injection attacks.',
       'critical', ARRAY['89'], 'app/api/users.py', 42, 45,
       'cursor.execute("SELECT * FROM users WHERE id = " + user_input)',
       'open')
     RETURNING id`,
    [findingId, tenantId, customerId, projectId, ruleId, engineId]
  );
  console.log("Finding:", findingId);
  await pg.end();
}
main().catch(e => { console.error(e); process.exit(1); });