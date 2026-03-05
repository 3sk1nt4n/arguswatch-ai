-- ═══════════════════════════════════════════════════════════════
-- ArgusWatch v16.4.1 - Row-Level Security (RLS)
-- Multi-tenant data isolation at the database level.
--
-- HOW IT WORKS:
--   1. Each API request sets a session variable: SET app.current_customer_id = X
--   2. PostgreSQL policies filter rows so queries only see that customer's data
--   3. Admin/system role bypasses RLS (has BYPASSRLS privilege)
--   4. This is defense-in-depth - app-level filters still exist
--
-- SETUP:
--   1. Run this migration: psql -f 09_row_level_security.sql
--   2. Backend sets session var on each request (see middleware)
--   3. System operations use the admin role
--
-- ═══════════════════════════════════════════════════════════════

-- Step 1: Create restricted role for API requests
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arguswatch_api') THEN
        CREATE ROLE arguswatch_api LOGIN PASSWORD 'arguswatch_api_2026';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arguswatch_admin') THEN
        CREATE ROLE arguswatch_admin LOGIN BYPASSRLS PASSWORD 'arguswatch_admin_2026';
    END IF;
END
$$;

-- Grant basic access to api role
GRANT USAGE ON SCHEMA public TO arguswatch_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO arguswatch_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO arguswatch_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO arguswatch_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO arguswatch_api;

-- Grant full access to admin role
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO arguswatch_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO arguswatch_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO arguswatch_admin;

-- Step 2: Enable RLS on customer-scoped tables
-- These tables have customer_id and should be filtered per-tenant

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_exposure ENABLE ROW LEVEL SECURITY;
ALTER TABLE darkweb_mentions ENABLE ROW LEVEL SECURITY;
ALTER TABLE edr_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_actions ENABLE ROW LEVEL SECURITY;

-- Step 3: Create policies
-- Policy pattern: user sees rows where customer_id matches session variable
-- System/admin sees all rows (BYPASSRLS)

-- Helper function to get current customer context
CREATE OR REPLACE FUNCTION current_customer_id() RETURNS INTEGER AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_customer_id', true), '')::INTEGER;
EXCEPTION
    WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- Findings: scoped to customer
DROP POLICY IF EXISTS findings_customer_isolation ON findings;
CREATE POLICY findings_customer_isolation ON findings
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL  -- no filter set = see all (for dashboard overview)
        OR customer_id = current_customer_id()
    )
    WITH CHECK (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    );

-- Customer Assets: scoped to customer
DROP POLICY IF EXISTS assets_customer_isolation ON customer_assets;
CREATE POLICY assets_customer_isolation ON customer_assets
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    )
    WITH CHECK (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    );

-- Customer Exposure: scoped to customer
DROP POLICY IF EXISTS exposure_customer_isolation ON customer_exposure;
CREATE POLICY exposure_customer_isolation ON customer_exposure
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    )
    WITH CHECK (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    );

-- Dark Web Mentions: scoped to customer (nullable customer_id = global intel)
DROP POLICY IF EXISTS darkweb_customer_isolation ON darkweb_mentions;
CREATE POLICY darkweb_customer_isolation ON darkweb_mentions
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR customer_id IS NULL  -- global intel visible to all
        OR customer_id = current_customer_id()
    );

-- EDR Telemetry: strictly scoped
DROP POLICY IF EXISTS edr_customer_isolation ON edr_telemetry;
CREATE POLICY edr_customer_isolation ON edr_telemetry
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR customer_id = current_customer_id()
    )
    WITH CHECK (
        customer_id = current_customer_id()  -- cannot insert for other customers
    );

-- Remediation Actions: scoped via finding → customer
DROP POLICY IF EXISTS remed_customer_isolation ON remediation_actions;
CREATE POLICY remed_customer_isolation ON remediation_actions
    FOR ALL
    TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR detection_id IN (SELECT id FROM detections WHERE customer_id = current_customer_id())
    );

-- Step 4: Tables that should NOT have RLS (shared/global data)
-- detections       - global intel, not customer-scoped
-- customers        - managed by admins, customer portal would need RLS
-- threat_actors    - global threat intel
-- campaigns        - cross-customer correlation
-- collector_runs   - system operational data
-- enrichments      - global enrichment cache
-- sector_advisories - cross-customer
-- fp_patterns      - per-customer but managed by analysts
-- product_aliases  - global lookup

-- Note: If building a customer-facing portal, add RLS to customers table:
-- CREATE POLICY customer_self_only ON customers FOR SELECT TO arguswatch_customer
--     USING (id = current_customer_id());

-- Step 5: Verify
DO $$
DECLARE
    tbl TEXT;
    rls_on BOOLEAN;
BEGIN
    FOR tbl, rls_on IN
        SELECT tablename, rowsecurity
        FROM pg_tables
        WHERE schemaname = 'public'
        AND tablename IN ('findings', 'customer_assets', 'customer_exposure',
                          'darkweb_mentions', 'edr_telemetry', 'remediation_actions')
    LOOP
        IF NOT rls_on THEN
            RAISE WARNING 'RLS not enabled on %', tbl;
        ELSE
            RAISE NOTICE 'RLS ✓ %', tbl;
        END IF;
    END LOOP;
END $$;
