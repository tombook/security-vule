import { Pool } from "pg";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
async function main() {
  // scan_runs columns
  const { rows: sr } = await pg.query(`
    SELECT column_name, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema = 'detection' AND table_name = 'scan_runs'
    ORDER BY ordinal_position
  `);
  console.log("=== scan_runs NOT NULL columns ===");
  for (const r of sr) {
    if (r.is_nullable === 'NO' && !r.column_default) {
      console.log(`  ${r.column_name}`);
    }
  }
  // Also check findings NOT NULL
  const { rows: f } = await pg.query(`
    SELECT column_name, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema = 'detection' AND table_name = 'findings'
    ORDER BY ordinal_position
  `);
  console.log("\n=== findings NOT NULL (no default) ===");
  for (const r of f) {
    if (r.is_nullable === 'NO' && !r.column_default) {
      console.log(`  ${r.column_name}`);
    }
  }
  await pg.end();
}
main();