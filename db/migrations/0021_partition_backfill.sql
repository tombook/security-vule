-- 0021_partition_backfill.sql
-- 补 2026_06 月份分区(0014_governance.sql 与 0012_usage.sql 只声明了 2026_07/08/09)
-- 现实 dev DB 在初始 seed 时手工建了 2026_06 分区,现把这条声明写入迁移,保证新部署一致

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'audit_logs_2026_06' AND n.nspname = 'governance'
  ) THEN
    CREATE TABLE governance.audit_logs_2026_06 PARTITION OF governance.audit_logs
      FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'notifications_2026_06' AND n.nspname = 'governance'
  ) THEN
    CREATE TABLE governance.notifications_2026_06 PARTITION OF governance.notifications
      FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'usage_events_2026_06' AND n.nspname = 'usage'
  ) THEN
    CREATE TABLE usage.usage_events_2026_06 PARTITION OF usage.usage_events
      FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
  END IF;
END $$;

-- 2027_01 提前声明(运维友好)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs_2027_01')
    THEN CREATE TABLE governance.audit_logs_2027_01 PARTITION OF governance.audit_logs
      FOR VALUES FROM ('2027-01-01') TO ('2027-02-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs_2027_02')
    THEN CREATE TABLE governance.audit_logs_2027_02 PARTITION OF governance.audit_logs
      FOR VALUES FROM ('2027-02-01') TO ('2027-03-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs_2027_03')
    THEN CREATE TABLE governance.audit_logs_2027_03 PARTITION OF governance.audit_logs
      FOR VALUES FROM ('2027-03-01') TO ('2027-04-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'notifications_2027_01')
    THEN CREATE TABLE governance.notifications_2027_01 PARTITION OF governance.notifications
      FOR VALUES FROM ('2027-01-01') TO ('2027-02-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'notifications_2027_02')
    THEN CREATE TABLE governance.notifications_2027_02 PARTITION OF governance.notifications
      FOR VALUES FROM ('2027-02-01') TO ('2027-03-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'notifications_2027_03')
    THEN CREATE TABLE governance.notifications_2027_03 PARTITION OF governance.notifications
      FOR VALUES FROM ('2027-03-01') TO ('2027-04-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'usage_events_2027_01')
    THEN CREATE TABLE usage.usage_events_2027_01 PARTITION OF usage.usage_events
      FOR VALUES FROM ('2027-01-01') TO ('2027-02-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'usage_events_2027_02')
    THEN CREATE TABLE usage.usage_events_2027_02 PARTITION OF usage.usage_events
      FOR VALUES FROM ('2027-02-01') TO ('2027-03-01'); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'usage_events_2027_03')
    THEN CREATE TABLE usage.usage_events_2027_03 PARTITION OF usage.usage_events
      FOR VALUES FROM ('2027-03-01') TO ('2027-04-01'); END IF;
END $$;

-- 0017_alter_users_notification.sql 是 no-op(IF NOT EXISTS 守护,0008 已建 notification_prefs)
-- 不需要新 ALTER;此条作为审计说明

COMMENT ON SCHEMA meta IS
  'Phase 0 audit: 0017 是 no-op,无需额外修改;2026_06 + 2027_01/02/03 分区由 0021 补齐';

COMMIT;