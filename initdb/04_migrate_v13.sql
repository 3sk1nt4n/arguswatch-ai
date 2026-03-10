-- ArgusWatch V13 migration - customer onboarding + asset confidence
-- Safe to run multiple times (all IF NOT EXISTS)

-- Customer onboarding state machine
ALTER TABLE customers ADD COLUMN IF NOT EXISTS onboarding_state VARCHAR(30) DEFAULT 'created';
ALTER TABLE customers ADD COLUMN IF NOT EXISTS onboarding_updated_at TIMESTAMP;

-- Asset confidence scoring
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 1.0;
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS confidence_sources JSONB DEFAULT '[]';
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS discovery_source VARCHAR(100);
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS last_seen_in_ioc TIMESTAMP;
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS ioc_hit_count INTEGER DEFAULT 0;

-- AI rescore columns (if not already added by migrate_v13_ai)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_decision VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_reasoning TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_confidence FLOAT;
