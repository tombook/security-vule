#!/usr/bin/env bun
/**
 * scripts/apply-migration.ts
 *
 * Apply a single SQL migration file to the dev DB via the pg
 * driver. Used because the project doesn't ship psql in the
 * dev container; bun-runtime psql client avoids a separate dep.
 *
 * Usage:
 *   bun run scripts/apply-migration.ts db/migrations/0030_targets.sql
 */
import { Pool } from 'pg';
import { readFileSync } from 'fs';

const path = process.argv[2];
if (!path) {
  console.error('usage: bun run scripts/apply-migration.ts <file.sql>');
  process.exit(2);
}

const sql = readFileSync(path, 'utf8');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule',
});

try {
  await pool.query(sql);
  console.log(`applied ${path}`);
} catch (err: any) {
  console.error(`FAILED: ${err.message}`);
  process.exit(1);
} finally {
  await pool.end();
}