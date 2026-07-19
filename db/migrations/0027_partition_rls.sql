-- 0027_partition_rls.sql
-- 分区表 RLS 单独启用 + 复制 policy(partition 不会从 parent 继承 RLS 属性/policy)

BEGIN;

DO $$
DECLARE
  r RECORD;
  policy_exists BOOLEAN;
BEGIN
  FOR r IN
    SELECT c.relname, c.oid
    FROM pg_class c
    JOIN pg_inherits i ON i.inhrelid = c.oid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname IN ('audit_logs', 'notifications')
      AND c.relkind = 'r'
  LOOP
    EXECUTE format('ALTER TABLE governance.%I ENABLE ROW LEVEL SECURITY', r.relname);
    SELECT count(*) > 0 INTO policy_exists
    FROM pg_policies WHERE schemaname = 'governance' AND tablename = r.relname;
    IF NOT policy_exists THEN
      EXECUTE format(
        'CREATE POLICY %I ON governance.%I FOR ALL TO PUBLIC USING ('
        'current_setting(''app.current_user_role'', true) LIKE ''Provider%%'' AND '
        'octet_length(current_setting(''app.current_tenant'', true)) = 36 AND '
        'tenant_id::text = current_setting(''app.current_tenant'', true))',
        r.relname || '_tenant', r.relname);
    END IF;
  END LOOP;
END $$;

COMMIT;