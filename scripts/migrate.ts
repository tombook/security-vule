#!/usr/bin/env bun
// scripts/migrate.ts
// 幂等 migration runner + SHA-256 checksum drift 检测
// 用法:
//   bun run scripts/migrate.ts                 # 应用所有未应用的 migrations
//   bun run scripts/migrate.ts --status        # 只显示当前 schema_migrations 表内容
//   bun run scripts/migrate.ts --file 0019.sql # 强制应用指定文件 (不推荐,跳过 checksum 校验)

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Pool } from 'pg';

const MIGRATIONS_DIR = join(import.meta.dir, '..', 'db', 'migrations');

interface AppliedMigration {
  version: string;
  checksum: string;
  applied_at: Date;
}

async function ensureMetaTable(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS meta.schema_migrations (
      version     TEXT PRIMARY KEY,
      filename    TEXT NOT NULL,
      checksum    TEXT NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function loadApplied(pool: Pool): Promise<Map<string, AppliedMigration>> {
  const { rows } = await pool.query<AppliedMigration>(
    `SELECT version, checksum, applied_at FROM meta.schema_migrations`,
  );
  return new Map(rows.map((r) => [r.version, r]));
}

function listMigrations(): { version: string; filename: string; path: string; checksum: string }[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  return files.map((filename) => {
    const path = join(MIGRATIONS_DIR, filename);
    const content = readFileSync(path);
    const version = filename.replace(/\.sql$/, '');
    const checksum = createHash('sha256').update(content).digest('hex');
    return { version, filename, path, checksum };
  });
}

async function applyMigration(
  pool: Pool,
  mig: { version: string; filename: string; path: string; checksum: string },
): Promise<void> {
  const sql = readFileSync(mig.path, 'utf-8');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query(
      `INSERT INTO meta.schema_migrations (version, filename, checksum)
       VALUES ($1, $2, $3)`,
      [mig.version, mig.filename, mig.checksum],
    );
    await client.query('COMMIT');
    console.log(`  ✓ ${mig.filename}  sha256=${mig.checksum.slice(0, 12)}…`);
  } catch (err) {
    await client.query('ROLLBACK');
    throw new Error(`Migration ${mig.filename} failed: ${(err as Error).message}`);
  } finally {
    client.release();
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const isStatus = args.includes('--status');

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('ERROR: DATABASE_URL env var required');
    console.error('  export DATABASE_URL=postgresql://user:pass@host:5432/dbname');
    process.exit(1);
  }

  const pool = new Pool({ connectionString: databaseUrl });
  await ensureMetaTable(pool);

  const applied = await loadApplied(pool);
  const migrations = listMigrations();

  console.log(`\n[schema_migrations] ${applied.size} applied, ${migrations.length} on disk\n`);

  let drift = 0;
  let appliedCount = 0;
  for (const mig of migrations) {
    const prev = applied.get(mig.version);
    if (prev) {
      if (prev.checksum !== mig.checksum) {
        drift++;
        console.error(`  ⚠ DRIFT  ${mig.filename}`);
        console.error(`      on-disk:    ${mig.checksum.slice(0, 16)}…`);
        console.error(`      in DB:      ${prev.checksum.slice(0, 16)}…`);
        console.error(`      applied at: ${prev.applied_at.toISOString()}`);
        console.error(`      ⚠ 已应用的 migration 与磁盘文件不一致;不要修改已部署的 migration`);
      } else {
        console.log(`  ✓ ${mig.filename}  (already applied)`);
      }
    } else {
      if (!isStatus) {
        console.log(`  → applying ${mig.filename}…`);
        await applyMigration(pool, mig);
        appliedCount++;
      } else {
        console.log(`  ○ ${mig.filename}  (pending)`);
      }
    }
  }

  console.log('');
  if (drift > 0) {
    console.error(`✗ ${drift} migration(s) drifted — schema 与磁盘不一致`);
    process.exit(2);
  }
  if (appliedCount > 0) {
    console.log(`✓ applied ${appliedCount} new migration(s)`);
  } else {
    console.log(`✓ schema is up to date`);
  }
  await pool.end();
}

main().catch((err) => {
  console.error('FATAL:', err.message);
  process.exit(1);
});