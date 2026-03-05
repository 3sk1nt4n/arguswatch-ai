-- ArgusWatch V10 migration - run on existing V9 databases
-- Safe to run multiple times (IF NOT EXISTS / ALTER ... IF NOT EXISTS)

-- 1. Extend the assettype enum with new values
DO $$
BEGIN
    -- Add new asset types if they don't exist
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'subdomain'
                   AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'subdomain';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'tech_stack'
                   AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'tech_stack';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'brand_name'
                   AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'brand_name';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'exec_name'
                   AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'exec_name';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'cloud_asset'
                   AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')) THEN
        ALTER TYPE assettype ADD VALUE 'cloud_asset';
    END IF;
END$$;

-- 2. Add new columns to detections
ALTER TABLE detections
    ADD COLUMN IF NOT EXISTS correlation_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS source_count INTEGER DEFAULT 1;

CREATE INDEX IF NOT EXISTS ix_detection_corr_type   ON detections(correlation_type);
CREATE INDEX IF NOT EXISTS ix_detection_source_count ON detections(source_count);

-- 3. Add new columns to customer_exposure
ALTER TABLE customer_exposure
    ADD COLUMN IF NOT EXISTS factor_breakdown JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS recency_multiplier FLOAT DEFAULT 1.0;

-- 4. Backfill source_count = 1 for existing rows that are NULL
UPDATE detections SET source_count = 1 WHERE source_count IS NULL;

SELECT 'V10 migration complete' AS status;
