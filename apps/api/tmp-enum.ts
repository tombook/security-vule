import { Pool } from "pg";
const pg = new Pool({ connectionString: process.env.DATABASE_URL });
async function main() {
  // Check scan_status_enum values
  const { rows } = await pg.query(`SELECT enumlabel FROM pg_enum WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'scan_status_enum')`);
  console.log("scan_status_enum:", rows.map(r => r.enumlabel).join(', '));
  await pg.end();
}
main();