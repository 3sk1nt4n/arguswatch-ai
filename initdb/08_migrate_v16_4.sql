-- V16.4 Migration: Enum expansion + missing columns + Agentic AI tables
-- Fixes: AssetType enum gap (Bug #5), Detection.match_proof (Bug #6), CustomerAsset.manual_entry (Bug #7)
-- Adds: FP Memory, Dark Web Triage, Sector Advisories, Exposure Narrative

-- Add missing asset types to enum (idempotent - checks before adding)
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'aws_account' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'aws_account';
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'azure_tenant' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'azure_tenant';
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'gcp_project' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'gcp_project';
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'internal_domain' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'internal_domain';
    END IF;
END $$;

-- Bug fix columns
ALTER TABLE detections ADD COLUMN IF NOT EXISTS match_proof JSONB DEFAULT '{}';
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN DEFAULT FALSE;

-- Agentic AI: Dark Web Triage fields on darkweb_mentions
ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_classification VARCHAR(50);
ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_action VARCHAR(50);
ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_narrative TEXT;
ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMP;

-- Agentic AI: Exposure narrative
ALTER TABLE customer_exposure ADD COLUMN IF NOT EXISTS score_narrative TEXT;

-- Agentic AI: FP Memory table
CREATE TABLE IF NOT EXISTS fp_patterns (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value_pattern TEXT NOT NULL,
    match_type VARCHAR(20) DEFAULT 'exact',
    source VARCHAR(100),
    reason TEXT,
    confidence FLOAT DEFAULT 0.9,
    hit_count INTEGER DEFAULT 1,
    last_hit_at TIMESTAMP,
    created_by VARCHAR(100) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_fp_customer_type ON fp_patterns(customer_id, ioc_type);

-- Agentic AI: Sector Advisory table (cross-customer)
CREATE TABLE IF NOT EXISTS sector_advisories (
    id SERIAL PRIMARY KEY,
    ioc_value TEXT NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,
    affected_customer_count INTEGER DEFAULT 0,
    affected_industries JSONB DEFAULT '[]',
    affected_customer_ids JSONB DEFAULT '[]',
    severity severitylevel DEFAULT 'HIGH',
    classification VARCHAR(50),
    ai_narrative TEXT,
    ai_recommended_actions JSONB DEFAULT '[]',
    status VARCHAR(30) DEFAULT 'active',
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_sector_adv_created ON sector_advisories(created_at);
