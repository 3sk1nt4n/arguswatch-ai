-- ArgusWatch V10 - init schema (runs once on fresh postgres)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE severitylevel AS ENUM ('CRITICAL','HIGH','MEDIUM','LOW','INFO');
CREATE TYPE detectionstatus AS ENUM ('NEW','ENRICHED','ALERTED','REMEDIATED','VERIFIED_CLOSED','ESCALATION','FALSE_POSITIVE','CLOSED');
-- V10: 5 new asset types added for full correlation coverage
CREATE TYPE assettype AS ENUM (
    'domain','ip','email','keyword','cidr','org_name','github_org',
    'subdomain','tech_stack','brand_name','exec_name','cloud_asset'
);

CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    industry VARCHAR(100),
    tier VARCHAR(20) DEFAULT 'standard',
    primary_contact VARCHAR(255),
    email VARCHAR(255),
    slack_channel VARCHAR(100),
    active BOOLEAN DEFAULT TRUE,
    onboarding_state VARCHAR(30) DEFAULT 'created',
    onboarding_updated_at TIMESTAMP,
    recon_status VARCHAR(20) DEFAULT NULL,
    recon_error TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS customer_assets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE NOT NULL,
    asset_type assettype NOT NULL,
    asset_value VARCHAR(500) NOT NULL,
    criticality VARCHAR(20) DEFAULT 'medium',
    confidence FLOAT DEFAULT 1.0,
    confidence_sources JSONB DEFAULT '[]',
    discovery_source VARCHAR(100),
    last_seen_in_ioc TIMESTAMP,
    ioc_hit_count INTEGER DEFAULT 0,
    tech_risk_baseline FLOAT DEFAULT 0.0,
    manual_entry BOOLEAN DEFAULT false,
    normalized_domain VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_asset_type_value ON customer_assets(asset_type, asset_value);

CREATE TABLE IF NOT EXISTS threat_actors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    aliases JSONB DEFAULT '[]',
    origin_country VARCHAR(100),
    motivation VARCHAR(100),
    sophistication VARCHAR(50),
    active_since VARCHAR(20),
    last_seen VARCHAR(20),
    target_sectors JSONB DEFAULT '[]',
    target_countries JSONB DEFAULT '[]',
    description TEXT,
    mitre_id VARCHAR(20),
    source VARCHAR(50) DEFAULT 'mitre',
    iocs JSONB DEFAULT '[]',
    techniques JSONB DEFAULT '[]',
    "references" JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS customer_exposure (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE NOT NULL,
    actor_id INTEGER REFERENCES threat_actors(id) ON DELETE CASCADE NOT NULL,
    exposure_score FLOAT DEFAULT 0.0,
    sector_match BOOLEAN DEFAULT FALSE,
    detection_count INTEGER DEFAULT 0,
    darkweb_mentions INTEGER DEFAULT 0,
    last_calculated TIMESTAMP DEFAULT NOW(),
    -- V10 additions
    factor_breakdown JSONB DEFAULT '{}',
    recency_multiplier FLOAT DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS exposure_history (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE NOT NULL,
    snapshot_date TIMESTAMP NOT NULL,
    overall_score FLOAT DEFAULT 0.0,
    d1_score FLOAT DEFAULT 0.0,
    d2_score FLOAT DEFAULT 0.0,
    d3_score FLOAT DEFAULT 0.0,
    d4_score FLOAT DEFAULT 0.0,
    d5_score FLOAT DEFAULT 0.0,
    total_detections INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_eh_customer_date ON exposure_history(customer_id, snapshot_date);

CREATE TABLE IF NOT EXISTS detections (
    id BIGSERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    source VARCHAR(100) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value TEXT NOT NULL,
    raw_text TEXT,
    severity severitylevel DEFAULT 'MEDIUM',
    sla_hours INTEGER DEFAULT 72,
    status detectionstatus DEFAULT 'NEW',
    matched_asset VARCHAR(500),
    -- V10 additions
    correlation_type VARCHAR(50),    -- HOW it matched: exact_domain, subdomain, ip_range, email_pattern, tech_stack, typosquat, keyword, exec_name, brand_name, cloud_asset, cidr
    source_count INTEGER DEFAULT 1,  -- how many distinct sources corroborate this IOC
    confidence FLOAT DEFAULT 0.5,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    metadata JSONB DEFAULT '{}',
    -- V11: finding link
    finding_id BIGINT,
    -- V15: feed quality + matching
    normalized_domain VARCHAR(255),
    feed_confidence FLOAT DEFAULT 0.7,
    feed_freshness_ts TIMESTAMP,
    normalized_score FLOAT,
    match_proof JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_detection_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS ix_detection_status ON detections(status);
CREATE INDEX IF NOT EXISTS ix_detection_source ON detections(source);
CREATE INDEX IF NOT EXISTS ix_detection_ioc ON detections(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS ix_detection_created ON detections(created_at);
CREATE INDEX IF NOT EXISTS ix_detection_corr_type ON detections(correlation_type);   -- V10
CREATE INDEX IF NOT EXISTS ix_detection_source_count ON detections(source_count);    -- V10

CREATE TABLE IF NOT EXISTS darkweb_mentions (
    id BIGSERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    source VARCHAR(100) NOT NULL,
    mention_type VARCHAR(50),
    title VARCHAR(500),
    content_snippet TEXT,
    url TEXT,
    threat_actor VARCHAR(255),
    severity severitylevel DEFAULT 'HIGH',
    published_at TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_darkweb_source ON darkweb_mentions(source);
CREATE INDEX IF NOT EXISTS ix_darkweb_discovered ON darkweb_mentions(discovered_at);

CREATE TABLE IF NOT EXISTS enrichments (
    id BIGSERIAL PRIMARY KEY,
    detection_id BIGINT REFERENCES detections(id) ON DELETE CASCADE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    enrichment_type VARCHAR(50),
    data JSONB DEFAULT '{}',
    risk_score FLOAT,
    queried_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id BIGSERIAL PRIMARY KEY,
    detection_id BIGINT REFERENCES detections(id) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    description TEXT,
    assigned_to VARCHAR(255),
    status VARCHAR(30) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_log (
    id BIGSERIAL PRIMARY KEY,
    detection_id BIGINT REFERENCES detections(id),
    channel VARCHAR(30) NOT NULL,
    recipient VARCHAR(255),
    message TEXT,
    sent_at TIMESTAMP DEFAULT NOW(),
    success BOOLEAN DEFAULT TRUE,
    error_detail TEXT
);

CREATE TABLE IF NOT EXISTS stix_bundles (
    id BIGSERIAL PRIMARY KEY,
    detection_id BIGINT REFERENCES detections(id),
    bundle_json JSONB NOT NULL,
    stix_version VARCHAR(10) DEFAULT '2.1',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS collector_runs (
    id BIGSERIAL PRIMARY KEY,
    collector_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'running',
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    stats JSONB DEFAULT '{}',
    error_msg TEXT,
    -- V15: run metrics
    iocs_inserted INTEGER DEFAULT 0,
    duration_seconds FLOAT,
    error_detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_crun_name ON collector_runs(collector_name);
CREATE INDEX IF NOT EXISTS ix_crun_started ON collector_runs(started_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    "user" VARCHAR(100) DEFAULT 'system',
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id VARCHAR(50),
    details JSONB DEFAULT '{}',
    timestamp TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_log(action);

-- ═══════════════════════════════════════════════════════
-- V11 NEW TABLES
-- ═══════════════════════════════════════════════════════

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
    -- V13: AI rescore
    ai_rescore_decision VARCHAR(20),
    ai_rescore_reasoning TEXT,
    ai_rescore_confidence FLOAT,
    -- V15: matching proof + narrative
    match_proof JSONB,
    enrichment_narrative TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_finding_ioc ON findings(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS ix_finding_customer ON findings(customer_id);
CREATE INDEX IF NOT EXISTS ix_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_finding_status ON findings(status);
CREATE INDEX IF NOT EXISTS ix_finding_actor ON findings(actor_id);
CREATE INDEX IF NOT EXISTS ix_finding_created ON findings(created_at);

CREATE TABLE IF NOT EXISTS finding_sources (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT REFERENCES findings(id) ON DELETE CASCADE NOT NULL,
    detection_id BIGINT REFERENCES detections(id) NOT NULL,
    source VARCHAR(100) NOT NULL,
    contributed_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_fsource_finding ON finding_sources(finding_id);

-- Add finding_id FK to detections
ALTER TABLE detections ADD COLUMN IF NOT EXISTS finding_id BIGINT REFERENCES findings(id);
CREATE INDEX IF NOT EXISTS ix_detection_finding ON detections(finding_id);

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
CREATE INDEX IF NOT EXISTS ix_cve_product_cve ON cve_product_map(cve_id);
CREATE INDEX IF NOT EXISTS ix_cve_product_name ON cve_product_map(product_name);

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
CREATE INDEX IF NOT EXISTS ix_freq_finding ON finding_remediations(finding_id);
CREATE INDEX IF NOT EXISTS ix_freq_status ON finding_remediations(status);
CREATE INDEX IF NOT EXISTS ix_freq_deadline ON finding_remediations(deadline);
