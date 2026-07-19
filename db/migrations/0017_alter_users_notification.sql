ALTER TABLE core.users
  ADD COLUMN IF NOT EXISTS notification_prefs JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_users__notification_prefs_gin
  ON core.users USING GIN (notification_prefs jsonb_path_ops);

COMMENT ON COLUMN core.users.notification_prefs IS '按事件×渠道的通知偏好矩阵;JSONB 灵活扩展';
