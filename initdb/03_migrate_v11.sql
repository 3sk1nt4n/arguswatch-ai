-- ArgusWatch V11 migration - run on existing V10 databases
-- Safe to run multiple times (all statements IF NOT EXISTS / idempotent)

-- 1. Create campaigns table (findings.campaign_id references it, must exist first)
CREATE TABLE IF NOT EXISTS campaigns (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id) NOT NULL,
    actor_id INTEGER REFERENCES threat_actors(id),
    actor_name VARCHAR(255),
    name VARCHAR(255),
    kill_chain_stage VARCHAR(50),
    finding_count INTEGER DEFAULT 0,
    severity severitylevel DEFAULT 'HIGH',
    status VARCHAR(30) DEFAULT 'active',
    first_seen TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_campaign_customer ON campaigns(customer_id);
CREATE INDEX IF NOT EXISTS ix_campaign_actor ON campaigns(actor_id);
CREATE INDEX IF NOT EXISTS ix_campaign_status ON campaigns(status);

-- 2. Create findings table
CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    ioc_value TEXT NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,
    customer_id INTEGER REFERENCES customers(id),
    matched_asset VARCHAR(500),
    correlation_type VARCHAR(50),
    severity severitylevel DEFAULT 'MEDIUM',
    status detectionstatus DEFAULT 'NEW',
    sla_hours INTEGER DEFAULT 72,
    sla_deadline TIMESTAMP,
    source_count INTEGER DEFAULT 1,
    all_sources JSONB DEFAULT '[]',
    confidence FLOAT DEFAULT 0.5,
    actor_id INTEGER REFERENCES threat_actors(id),
    actor_name VARCHAR(255),
    campaign_id INTEGER REFERENCES campaigns(id),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_finding_ioc      ON findings(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS ix_finding_customer ON findings(customer_id);
CREATE INDEX IF NOT EXISTS ix_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_finding_status   ON findings(status);
CREATE INDEX IF NOT EXISTS ix_finding_actor    ON findings(actor_id);
CREATE INDEX IF NOT EXISTS ix_finding_created  ON findings(created_at);

-- 3. Create finding_sources table
CREATE TABLE IF NOT EXISTS finding_sources (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT REFERENCES findings(id) ON DELETE CASCADE NOT NULL,
    detection_id BIGINT REFERENCES detections(id) NOT NULL,
    source VARCHAR(100) NOT NULL,
    contributed_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_fsource_finding ON finding_sources(finding_id);

-- 4. Add finding_id FK to detections
ALTER TABLE detections ADD COLUMN IF NOT EXISTS finding_id BIGINT REFERENCES findings(id);
CREATE INDEX IF NOT EXISTS ix_detection_finding ON detections(finding_id);

-- 5. Create actor_iocs table
CREATE TABLE IF NOT EXISTS actor_iocs (
    id BIGSERIAL PRIMARY KEY,
    actor_id INTEGER REFERENCES threat_actors(id) ON DELETE CASCADE NOT NULL,
    actor_name VARCHAR(255) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    ioc_role VARCHAR(50),
    confidence FLOAT DEFAULT 0.8,
    source VARCHAR(100),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_actor_ioc_value ON actor_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS ix_actor_ioc_actor ON actor_iocs(actor_id);

-- 6. Create cve_product_map table
CREATE TABLE IF NOT EXISTS cve_product_map (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    vendor VARCHAR(100),
    version_range VARCHAR(255),
    cvss_score FLOAT,
    severity VARCHAR(20),
    actively_exploited BOOLEAN DEFAULT FALSE,
    source VARCHAR(50) DEFAULT 'nvd',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_cve_product_cve  ON cve_product_map(cve_id);
CREATE INDEX IF NOT EXISTS ix_cve_product_name ON cve_product_map(product_name);

-- 7. Create finding_remediations table
CREATE TABLE IF NOT EXISTS finding_remediations (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT REFERENCES findings(id) NOT NULL,
    playbook_key VARCHAR(100),
    action_type VARCHAR(50) NOT NULL,
    title VARCHAR(500),
    steps_technical JSONB DEFAULT '[]',
    steps_governance JSONB DEFAULT '[]',
    evidence_required JSONB DEFAULT '[]',
    assigned_to VARCHAR(255),
    assigned_role VARCHAR(100),
    deadline TIMESTAMP,
    sla_hours INTEGER,
    status VARCHAR(30) DEFAULT 'pending',
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_freq_finding  ON finding_remediations(finding_id);
CREATE INDEX IF NOT EXISTS ix_freq_status   ON finding_remediations(status);
CREATE INDEX IF NOT EXISTS ix_freq_deadline ON finding_remediations(deadline);

SELECT 'V11 migration complete' AS status;

-- V11 Phase 12: add code_repo to asset_type enum
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum
        WHERE enumlabel = 'code_repo'
        AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')
    ) THEN
        ALTER TYPE assettype ADD VALUE 'code_repo';
    END IF;
END$$;

SELECT 'V11 Phase 12 migration complete' AS status;
