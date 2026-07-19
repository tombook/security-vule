-- PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- uuid_generate_v7 (PG 18+ 内置,15/16/17 需自定义)
-- 基于时间序 + 随机,索引友好
CREATE OR REPLACE FUNCTION uuid_generate_v7() RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  ts_ms bigint;
  rand bytea;
  bytes bytea;
  ts_hex text;
BEGIN
  ts_ms := (extract(epoch from clock_timestamp()) * 1000)::bigint - 1234567890000;
  rand := gen_random_bytes(10);
  ts_hex := lpad(to_hex(ts_ms), 12, '0');
  bytes := decode(substr(ts_hex, 1, 8) || '7' || substr(ts_hex, 10, 3), 'hex') || rand;
  return encode(bytes, 'hex')::uuid;
EXCEPTION WHEN OTHERS THEN
  RETURN gen_random_uuid();
END $$;
