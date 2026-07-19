DO $$ BEGIN CREATE TYPE user_role_enum AS ENUM ('ProviderOwner','ProviderAdmin','ProviderEngineer','ProviderViewer','ProviderBilling','CustomerAdmin','CustomerDeveloper','CustomerViewer','SystemBot'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE tenant_status_enum AS ENUM ('pending','active','suspended','rejected','deleted'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE customer_status_enum AS ENUM ('active','suspended','deleted'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE project_status_enum AS ENUM ('configuring','active','paused','error','deleted'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE user_status_enum AS ENUM ('pending','active','disabled','locked'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE invite_status_enum AS ENUM ('pending','accepted','revoked','expired'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE portal_enum AS ENUM ('provider','customer'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE sla_tier_enum AS ENUM ('standard','priority','premium'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE source_type_enum AS ENUM ('github','gitlab','upload'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE source_status_enum AS ENUM ('active','expired','revoked','error'); EXCEPTION WHEN duplicate_object THEN null; END $$;

COMMENT ON TYPE tenant_status_enum IS '服务商入驻流程状态机: pending→active/rejected/suspended→deleted';
COMMENT ON TYPE customer_status_enum IS '客户状态: active/suspended/deleted(软删 90 天可恢复)';
COMMENT ON TYPE project_status_enum IS '项目状态: configuring→active/paused/error→deleted';
COMMENT ON TYPE portal_enum IS '门户隔离: 同一邮箱不可跨 portal 登录';
