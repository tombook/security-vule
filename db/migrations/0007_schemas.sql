CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS detection;
CREATE SCHEMA IF NOT EXISTS poc;
CREATE SCHEMA IF NOT EXISTS usage;
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS governance;
CREATE SCHEMA IF NOT EXISTS meta;
CREATE SCHEMA IF NOT EXISTS integration;

COMMENT ON SCHEMA core IS '身份/客户/项目域';
COMMENT ON SCHEMA detection IS '扫描/规则/findings 域';
COMMENT ON SCHEMA poc IS 'PoC 验证/沙箱/库 域';
COMMENT ON SCHEMA usage IS 'AI token 用量/配额 域';
COMMENT ON SCHEMA billing IS '计费/账单/分摊 域';
COMMENT ON SCHEMA governance IS '审计/通知/webhook 域';
COMMENT ON SCHEMA meta IS '平台元数据/任务队列 域';
COMMENT ON SCHEMA integration IS '第三方集成(工单系统) 域';
