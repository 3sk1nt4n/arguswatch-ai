-- ArgusWatch v14 migration - 3-class IOC model + environmental threat pressure
-- Safe to run multiple times (all IF NOT EXISTS / CREATE IF NOT EXISTS)

-- ═══════════════════════════════════════════════════════════════════════
-- Global Threat Activity - environmental pressure from unmatched IOCs
-- Feodo C2 IPs don't match customers directly, but they increase
-- "banking malware activity" pressure on banking sector customers.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS global_threat_activity (
    id              SERIAL PRIMARY KEY,
    malware_family  VARCHAR(255),           -- "Emotet", "LockBit", "Cobalt Strike"
    category        VARCHAR(100) NOT NULL,  -- "c2_botnet", "ransomware", "phishing", "exploit_campaign", "credential_theft"
    targeted_sectors JSONB DEFAULT '[]',    -- ["financial", "healthcare"]
    affected_products JSONB DEFAULT '[]',   -- ["Exchange", "FortiOS"] - from CVE CPE data
    activity_level  FLOAT DEFAULT 0.0,      -- 0.0-10.0 calculated from IOC volume + recency
    ioc_count       INTEGER DEFAULT 0,      -- how many IOCs contributed to this signal
    sources         JSONB DEFAULT '[]',     -- ["feodo", "threatfox", "ransomfeed"]
    first_seen      TIMESTAMP DEFAULT NOW(),
    last_seen       TIMESTAMP DEFAULT NOW(),
    window_start    TIMESTAMP,              -- activity measurement window
    window_end      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_gta_category ON global_threat_activity(category);
CREATE INDEX IF NOT EXISTS ix_gta_malware ON global_threat_activity(malware_family);
CREATE INDEX IF NOT EXISTS ix_gta_level ON global_threat_activity(activity_level DESC);

-- ═══════════════════════════════════════════════════════════════════════
-- Probable Exposures - tech stack risk baseline + indirect matches
-- "Customer runs Exchange, Exchange has had 15 critical CVEs in 2 years"
-- Even without a matching CVE today, there's baseline risk.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS probable_exposures (
    id              SERIAL PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    exposure_type   VARCHAR(50) NOT NULL,   -- "tech_risk_baseline", "sector_pressure", "probable_cve", "unknown_version"
    source_detail   VARCHAR(500),           -- "Exchange historically targeted (15 CVEs in 24mo)"
    product_name    VARCHAR(255),           -- matched product if applicable
    cve_id          VARCHAR(30),            -- specific CVE if applicable
    confidence      FLOAT DEFAULT 0.5,      -- 0.0-1.0 - lower for probable, higher for verified
    risk_points     FLOAT DEFAULT 0.0,      -- contribution to risk score
    last_calculated TIMESTAMP DEFAULT NOW(),
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_pe_customer ON probable_exposures(customer_id);
CREATE INDEX IF NOT EXISTS ix_pe_type ON probable_exposures(exposure_type);

-- Add tech_risk_baseline to customer_assets for tracking historically-risky tech
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS tech_risk_baseline FLOAT DEFAULT 0.0;
-- Add manual_entry flag to distinguish analyst-entered assets from auto-discovered
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN DEFAULT false;
