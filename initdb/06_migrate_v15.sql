-- ArgusWatch v15 migration - eTLD+1 normalization, feed confidence, product aliases
-- Safe to run multiple times (IF NOT EXISTS / IF NOT EXISTS)

-- ═══════════════════════════════════════════════════════════════════
-- A) Normalized domain column on customer_assets for eTLD+1 matching
-- ═══════════════════════════════════════════════════════════════════
ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255);
CREATE INDEX IF NOT EXISTS ix_ca_normdomain ON customer_assets(normalized_domain);

-- Also add to detections for fast join
ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255);
CREATE INDEX IF NOT EXISTS ix_det_normdomain ON detections(normalized_domain);

-- ═══════════════════════════════════════════════════════════════════
-- B) Feed confidence + freshness on detections
-- ═══════════════════════════════════════════════════════════════════
ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_confidence FLOAT DEFAULT 0.7;
ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_freshness_ts TIMESTAMP;
ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_score FLOAT;

-- ═══════════════════════════════════════════════════════════════════
-- C) Product alias table - canonical product names
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS product_aliases (
    id          SERIAL PRIMARY KEY,
    alias       VARCHAR(255) NOT NULL,          -- "nginx", "nginx-plus", "openresty"
    canonical   VARCHAR(255) NOT NULL,          -- "nginx"
    vendor      VARCHAR(255),                   -- "F5"
    UNIQUE(alias)
);
INSERT INTO product_aliases (alias, canonical, vendor) VALUES
    ('nginx', 'nginx', 'F5'),
    ('nginx-plus', 'nginx', 'F5'),
    ('openresty', 'nginx', 'OpenResty'),
    ('apache', 'apache_http_server', 'Apache'),
    ('httpd', 'apache_http_server', 'Apache'),
    ('apache2', 'apache_http_server', 'Apache'),
    ('apache http server', 'apache_http_server', 'Apache'),
    ('exchange', 'microsoft_exchange', 'Microsoft'),
    ('exchange server', 'microsoft_exchange', 'Microsoft'),
    ('microsoft exchange', 'microsoft_exchange', 'Microsoft'),
    ('outlook web access', 'microsoft_exchange', 'Microsoft'),
    ('owa', 'microsoft_exchange', 'Microsoft'),
    ('fortios', 'fortios', 'Fortinet'),
    ('fortigate', 'fortios', 'Fortinet'),
    ('forti os', 'fortios', 'Fortinet'),
    ('fortinet', 'fortios', 'Fortinet'),
    ('confluence', 'confluence', 'Atlassian'),
    ('atlassian confluence', 'confluence', 'Atlassian'),
    ('ivanti', 'ivanti_connect_secure', 'Ivanti'),
    ('ivanti connect secure', 'ivanti_connect_secure', 'Ivanti'),
    ('pulse secure', 'ivanti_connect_secure', 'Ivanti'),
    ('pulse connect secure', 'ivanti_connect_secure', 'Ivanti'),
    ('citrix', 'citrix_netscaler', 'Citrix'),
    ('netscaler', 'citrix_netscaler', 'Citrix'),
    ('citrix adc', 'citrix_netscaler', 'Citrix'),
    ('esxi', 'vmware_esxi', 'VMware'),
    ('vmware esxi', 'vmware_esxi', 'VMware'),
    ('vcenter', 'vmware_vcenter', 'VMware'),
    ('vmware vcenter', 'vmware_vcenter', 'VMware'),
    ('sharepoint', 'sharepoint', 'Microsoft'),
    ('microsoft sharepoint', 'sharepoint', 'Microsoft'),
    ('openssh', 'openssh', 'OpenBSD'),
    ('ssh', 'openssh', 'OpenBSD'),
    ('wordpress', 'wordpress', 'WordPress'),
    ('wp', 'wordpress', 'WordPress'),
    ('php', 'php', 'PHP Group'),
    ('moveit', 'moveit_transfer', 'Progress'),
    ('moveit transfer', 'moveit_transfer', 'Progress'),
    ('panos', 'paloalto_panos', 'Palo Alto'),
    ('pan-os', 'paloalto_panos', 'Palo Alto'),
    ('palo alto', 'paloalto_panos', 'Palo Alto'),
    ('solarwinds', 'solarwinds_orion', 'SolarWinds'),
    ('orion', 'solarwinds_orion', 'SolarWinds'),
    ('jira', 'jira', 'Atlassian'),
    ('atlassian jira', 'jira', 'Atlassian'),
    ('gitlab', 'gitlab', 'GitLab'),
    ('jenkins', 'jenkins', 'Jenkins'),
    ('tomcat', 'apache_tomcat', 'Apache'),
    ('apache tomcat', 'apache_tomcat', 'Apache'),
    ('iis', 'microsoft_iis', 'Microsoft'),
    ('microsoft-iis', 'microsoft_iis', 'Microsoft')
ON CONFLICT (alias) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════
-- D) Collector health tracking columns on collector_runs
-- ═══════════════════════════════════════════════════════════════════
ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS iocs_inserted INTEGER DEFAULT 0;
ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS duration_seconds FLOAT;
ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS error_detail TEXT;

-- ═══════════════════════════════════════════════════════════════════
-- E) Match proof + enrichment narrative on detections/findings
-- ═══════════════════════════════════════════════════════════════════
ALTER TABLE detections ADD COLUMN IF NOT EXISTS match_proof JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS match_proof JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_narrative TEXT;

-- ═══════════════════════════════════════════════════════════════════
-- F) EDR telemetry table for hash matching
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS edr_telemetry (
    id              SERIAL PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    hostname        VARCHAR(255),
    file_path       VARCHAR(1000),
    hash_sha256     VARCHAR(64),
    hash_md5        VARCHAR(32),
    process_name    VARCHAR(255),
    seen_at         TIMESTAMP DEFAULT NOW(),
    source          VARCHAR(100) DEFAULT 'edr_agent',    -- edr_agent, siem, manual
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_edr_hash256 ON edr_telemetry(hash_sha256);
CREATE INDEX IF NOT EXISTS ix_edr_hash_md5 ON edr_telemetry(hash_md5);
CREATE INDEX IF NOT EXISTS ix_edr_customer ON edr_telemetry(customer_id);
