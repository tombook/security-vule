DO $$ BEGIN CREATE TYPE ai_capability_enum AS ENUM ('poc_gen','poc_chat','triage','explain','report','monitor','code_understand'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE ai_provider_enum AS ENUM ('anthropic','openai','ollama','glm','deepseek','custom'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE tenant_plan_enum AS ENUM ('starter','pro','enterprise','private'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE billing_plan_enum AS ENUM ('starter','pro','enterprise'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE billing_status_enum AS ENUM ('active','past_due','canceled'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE allocation_strategy_enum AS ENUM ('usage_proportional','flat_rate','custom'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE invoice_status_enum AS ENUM ('draft','issued','paid','overdue','void'); EXCEPTION WHEN duplicate_object THEN null; END $$;
