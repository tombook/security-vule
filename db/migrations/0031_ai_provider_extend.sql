-- Add python-verifier to ai_provider_enum so usage_events can record
-- executions that ran the in-tree Python PoC verifier rather than an
-- LLM call. Same approach as the existing enum values; safe additive.
ALTER TYPE ai_provider_enum ADD VALUE IF NOT EXISTS 'python-verifier';
