DO $$ BEGIN CREATE TYPE poc_source_enum AS ENUM ('ai','manual','library_reuse'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE poc_status_enum AS ENUM ('pending','approved','running','success','failed','timeout','canceled'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE sandbox_runtime_enum AS ENUM ('docker','firecracker','gvisor'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE sandbox_status_enum AS ENUM ('pending','running','done','failed','timeout','destroyed'); EXCEPTION WHEN duplicate_object THEN null; END $$;
