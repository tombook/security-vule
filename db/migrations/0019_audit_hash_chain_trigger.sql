-- 0019_audit_hash_chain_trigger.sql
-- Phase 3D: 哈希链自动签名触发器
-- 在 governance.audit_logs 上 BEFORE INSERT 触发,
-- 自动计算 prev_hash (同 tenant 最新 entry_hash) 与 entry_hash (sha256(prev || canonical))
-- Genesis 行 (同 tenant 第一条) 的 prev_hash 用 32 字节全 0 作为创世标记。

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION governance.tg_audit_log_sign()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_prev_entry_hash BYTEA;
  v_content BYTEA;
  v_canonical BYTEA;
BEGIN
  SELECT entry_hash INTO v_prev_entry_hash
  FROM governance.audit_logs
  WHERE tenant_id = NEW.tenant_id
  ORDER BY occurred_at DESC, id DESC
  LIMIT 1;

  IF v_prev_entry_hash IS NULL THEN
    v_prev_entry_hash := decode(repeat('0', 64), 'hex');
  END IF;

  v_content := convert_to(
    coalesce(NEW.tenant_id::text, '') || E'\x1f' ||
    NEW.occurred_at::text || E'\x1f' ||
    NEW.event_type::text || E'\x1f' ||
    coalesce(NEW.actor_email, '') || E'\x1f' ||
    NEW.action || E'\x1f' ||
    coalesce(NEW.resource_type, '') || E'\x1f' ||
    coalesce(NEW.resource_id::text, '') || E'\x1f' ||
    NEW.metadata::text,
    'UTF8'
  );

  v_canonical := v_prev_entry_hash || v_content;

  NEW.prev_hash := v_prev_entry_hash;
  NEW.entry_hash := digest(v_canonical, 'sha256');

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_log_sign ON governance.audit_logs;

CREATE TRIGGER trg_audit_log_sign
BEFORE INSERT ON governance.audit_logs
FOR EACH ROW
EXECUTE FUNCTION governance.tg_audit_log_sign();

COMMENT ON FUNCTION governance.tg_audit_log_sign() IS
  'BEFORE INSERT trigger: 自动计算 prev_hash (同 tenant 最新 entry_hash) + entry_hash (sha256).';
COMMENT ON TRIGGER trg_audit_log_sign ON governance.audit_logs IS
  '哈希链自动签名触发器;Phase 3D 交付';

COMMIT;