-- ArgusWatch v16.4.7 -  IOC Type Registry
-- Replaces 6 hardcoded Python dicts with a single DB table.
-- All pipeline stages read from this table via cached loader.
--
-- AUTO-CRITICALITY SCORING:
--   base_severity = what the registry says (static default)
--   runtime_severity = calculated from 8 weighted factors:
--     F1: base_severity_weight    (0.20) -  registry default
--     F2: kill_chain_weight       (0.15) -  later stage = higher
--     F3: enrichment_weight       (0.20) -  VT score, key liveness, breach recency
--     F4: source_reliability      (0.10) -  proven collector vs regex-only
--     F5: temporal_decay          (0.05) -  older = less critical
--     F6: customer_industry       (0.10) -  healthcare + PII = escalate
--     F7: mitre_tactic_weight     (0.10) -  Impact/Exfil > Recon
--     F8: exposure_context        (0.10) -  confirmed exposure = escalate

CREATE TABLE IF NOT EXISTS ioc_type_registry (
    id SERIAL PRIMARY KEY,
    type_name VARCHAR(80) UNIQUE NOT NULL,

    -- Pattern matching
    regex TEXT,                              -- NULL = comes from collectors, not regex
    regex_confidence FLOAT DEFAULT 0.85,
    category VARCHAR(50),                   -- 'API Keys', 'Credentials', 'Network IOCs', etc.

    -- Severity & SLA (base -  can be overridden by auto-scoring)
    base_severity VARCHAR(10) DEFAULT 'MEDIUM',  -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    sla_hours INTEGER DEFAULT 48,
    assignee_role VARCHAR(50) DEFAULT 'secops',

    -- MITRE ATT&CK
    mitre_technique VARCHAR(20),            -- T1552.004
    mitre_tactic VARCHAR(30),               -- Credential Access
    mitre_description TEXT,                 -- One-line analyst description

    -- Kill chain
    kill_chain_stage VARCHAR(20),           -- recon/delivery/exploitation/c2/exfiltration/persistence

    -- Remediation
    playbook_key VARCHAR(200) DEFAULT 'generic',

    -- Enrichment
    enrichment_source VARCHAR(30),          -- vt, key_liveness, credential_breach, etc.

    -- Auto-criticality factors (adjustable per type)
    auto_score_enabled BOOLEAN DEFAULT true,
    kill_chain_weight FLOAT DEFAULT 1.0,    -- multiplier for stage position
    tactic_weight FLOAT DEFAULT 1.0,        -- multiplier for MITRE tactic severity

    -- Status
    active BOOLEAN DEFAULT true,
    status VARCHAR(20) DEFAULT 'WORKING',   -- PROVEN/WORKING/THEORETICAL/REMOVED
    source_note TEXT,                        -- 'Comes from grep.app collector'
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(50) DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS ix_ioc_registry_type ON ioc_type_registry(type_name);
CREATE INDEX IF NOT EXISTS ix_ioc_registry_active ON ioc_type_registry(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS ix_ioc_registry_category ON ioc_type_registry(category);

-- Auto-criticality scoring weights table (adjustable by admin)
CREATE TABLE IF NOT EXISTS criticality_weights (
    id SERIAL PRIMARY KEY,
    factor_name VARCHAR(50) UNIQUE NOT NULL,
    weight FLOAT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO criticality_weights (factor_name, weight, description) VALUES
    ('base_severity',    0.20, 'Registry default severity (CRITICAL=1.0, HIGH=0.75, MEDIUM=0.5, LOW=0.25, INFO=0.1)'),
    ('kill_chain_stage', 0.15, 'Kill chain position (persistence=1.0, exfiltration=0.85, c2=0.7, exploitation=0.55, delivery=0.4, recon=0.25)'),
    ('enrichment_data',  0.20, 'External validation (active key=1.0, VT>10=0.9, breach confirmed=0.8, no data=0.3)'),
    ('source_reliability',0.10, 'Detection source (PROVEN=1.0, WORKING=0.7, THEORETICAL=0.4)'),
    ('temporal_freshness',0.05, 'Time decay (today=1.0, 7d=0.8, 30d=0.5, 90d=0.3, older=0.1)'),
    ('industry_context',  0.10, 'Customer industry alignment (PII+healthcare=1.0, financial+creds=0.9, generic=0.5)'),
    ('mitre_tactic',      0.10, 'MITRE tactic severity (Impact=1.0, Exfil=0.9, LatMov=0.85, CredAccess=0.8, C2=0.7, Persistence=0.65, etc.)'),
    ('exposure_confirmed',0.10, 'Confirmed customer exposure (yes=1.0, probable=0.6, no=0.2)')
ON CONFLICT (factor_name) DO NOTHING;
