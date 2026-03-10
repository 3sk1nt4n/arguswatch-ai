-- V16-fix: Recon status tracking on customers
ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_status VARCHAR(20) DEFAULT NULL;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_error TEXT DEFAULT NULL;

-- V16-fix: Exposure history table for trend charts (may already exist from model auto-create)
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
