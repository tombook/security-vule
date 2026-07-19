import { Pool } from "pg";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
async function main() {
  const { rows } = await pg.query(`
    SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'detection' AND table_name = 'findings'
    ORDER BY ordinal_position
  `);
  for (const r of rows) {
    console.log(`  ${r.column_name}: ${r.data_type}`);
  }
  await pg.end();
}
main();