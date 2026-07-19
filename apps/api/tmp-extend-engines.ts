import { Pool } from "pg";
import crypto from "crypto";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
async function main() {
  // Extend enum
  await pg.query(`ALTER TYPE engine_type_enum ADD VALUE IF NOT EXISTS 'llm';`);
  await pg.query(`ALTER TYPE engine_type_enum ADD VALUE IF NOT EXISTS 'runtime';`);
  await pg.query(`ALTER TYPE engine_type_enum ADD VALUE IF NOT EXISTS 'sandbox';`);
  await pg.query(`ALTER TYPE engine_type_enum ADD VALUE IF NOT EXISTS 'network_probe';`);
  console.log("Enum extended");

  const engineId = "0eee0001-0000-0000-0000-000000000001";
  await pg.query("INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ($1,'semgrep','semgrep','1.0.0',true) ON CONFLICT (id) DO NOTHING", [engineId]);

  // Seed LLM engines
  const llmEngines = [
    { id: "0eee0001-0000-0000-0000-100000000001", name: "GLM PoC Generator", version: "glm-5.2", provider: "glm" },
    { id: "0eee0001-0000-0000-0000-100000000002", name: "OpenAI PoC Generator", version: "MiniMax-M3", provider: "openai" },
    { id: "0eee0001-0000-0000-0000-100000000003", name: "Ollama Triage", version: "security-vule-poc-v1", provider: "ollama" },
  ];
  for (const e of llmEngines) {
    await pg.query("INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ($1,$2,'llm',$3,true) ON CONFLICT (id) DO NOTHING", [e.id, e.name, e.version]);
    console.log(`LLM engine: ${e.name} (${e.version})`);
  }

  // Seed Runtime engines
  const rtEngines = [
    { id: "0eee0001-0000-0000-0000-200000000001", name: "Sandbox PoC Runner", version: "1.0.0" },
    { id: "0eee0001-0000-0000-0000-200000000002", name: "Network Probe", version: "1.0.0" },
  ];
  for (const e of rtEngines) {
    await pg.query("INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ($1,$2,'runtime',$3,true) ON CONFLICT (id) DO NOTHING", [e.id, e.name, e.version]);
    console.log(`Runtime engine: ${e.name}`);
  }

  // Verify
  const { rows } = await pg.query("SELECT engine_type, count(*) as n FROM detection.engines GROUP BY engine_type ORDER BY 1");
  console.log("\n=== Engine distribution ===");
  for (const r of rows) console.log(`  ${r.engine_type}: ${r.n}`);

  await pg.end();
}
main().catch(e => { console.error(e); process.exit(1); });