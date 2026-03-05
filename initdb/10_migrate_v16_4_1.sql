-- V16.4.1 hotfix: Add missing 'email_domain' to assettype enum
DO $$
BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'email_domain' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
ALTER TYPE assettype ADD VALUE 'email_domain';
END IF;
END$$;

-- V16.4.1: Safety net - ensure all AI pipeline columns exist on findings
-- These are also added by migrate_v13_ai.py but we add here as belt-and-suspenders
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_decision VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_reasoning TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_confidence FLOAT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_narrative TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_attribution_reasoning TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_flag BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_enriched_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_provider VARCHAR(50);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confirmed_exposure BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exposure_type VARCHAR(50);

-- V16.4.1: Safety net - ensure campaigns has ai_narrative
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS ai_narrative TEXT;
