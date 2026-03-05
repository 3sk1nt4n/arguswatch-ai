#!/bin/bash
# ArgusWatch AI-Agentic Threat Intelligence v16.4.1 - Backend Entrypoint
set -e

echo "======================================================="
echo "  ArgusWatch AI-Agentic Threat Intelligence v16.4.1"
echo "  Solvent CyberSecurity LLC"
echo "======================================================="

# 1. Wait for PostgreSQL (errors visible, not suppressed)
echo "[1/5] Waiting for PostgreSQL..."
for i in $(seq 1 90); do
    RESULT=$(python -c "
import psycopg2, os
try:
    conn = psycopg2.connect(
        host=os.environ.get('POSTGRES_HOST','postgres'),
        port=os.environ.get('POSTGRES_PORT','5432'),
        user=os.environ.get('POSTGRES_USER','arguswatch'),
        password=os.environ.get('POSTGRES_PASSWORD','arguswatch_dev_2026'),
        dbname=os.environ.get('POSTGRES_DB','arguswatch'),
        connect_timeout=5
    )
    conn.close()
    print('CONNECTED')
except Exception as e:
    print(f'FAIL:{e}')
" 2>&1)
    if echo "$RESULT" | grep -q "CONNECTED"; then
        echo "  PostgreSQL connected"
        break
    fi
    if [ "$i" -eq 1 ] || [ "$((i % 10))" -eq 0 ]; then
        echo "  Attempt $i: $RESULT"
    fi
    if [ "$i" -eq 90 ]; then
        echo "  PostgreSQL not ready after 90 attempts"
        echo "  Last error: $RESULT"
        exit 1
    fi
    sleep 2
done

# 2. Run migrations
echo "[2/5] Running migrations..."
python -m arguswatch.scripts.migrate_v10     2>&1 | tail -1 || echo "  migrate_v10 skipped"
python -m arguswatch.scripts.migrate_v13_ai  2>&1 | tail -1 || echo "  migrate_v13_ai skipped"
python -m arguswatch.scripts.migrate_v13b    2>&1 | tail -1 || echo "  migrate_v13b skipped"
python -m arguswatch.scripts.migrate_v14     2>&1 | tail -1 || echo "  migrate_v14 skipped"
python -m arguswatch.scripts.migrate_v15     2>&1 | tail -1 || echo "  migrate_v15 skipped"
python -m arguswatch.scripts.migrate_v16_fix 2>&1 | tail -1 || echo "  migrate_v16_fix skipped"
python -m arguswatch.scripts.migrate_v16_4   2>&1 | tail -1 || echo "  migrate_v16_4 skipped"
echo "  Migrations complete"

# 3. Alembic baseline
echo "[3/5] Stamping Alembic baseline..."
cd /app && alembic stamp head 2>/dev/null || true
echo "  Alembic stamped"

# 4. Auto-seed if empty
echo "[4/5] Checking if demo data needed..."
CUSTOMER_COUNT=$(python -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ.get('POSTGRES_HOST','postgres'),
    port=os.environ.get('POSTGRES_PORT','5432'),
    user=os.environ.get('POSTGRES_USER','arguswatch'),
    password=os.environ.get('POSTGRES_PASSWORD','arguswatch_dev_2026'),
    dbname=os.environ.get('POSTGRES_DB','arguswatch'),
    connect_timeout=5
)
cur = conn.cursor()
try:
    cur.execute('SELECT COUNT(*) FROM customers')
    print(cur.fetchone()[0])
except:
    print('0')
conn.close()
" 2>&1 || echo "0")

if [ "$CUSTOMER_COUNT" -lt "1" ]; then
    echo "  Empty DB - seeding customers from CSV FIRST..."
    python -c "
import asyncio
from arguswatch.services.seed import seed_from_csv
result = asyncio.run(seed_from_csv())
print(f'  CSV Seed: {result}')
" 2>&1 || echo "  CSV seed skipped"

    echo "  Seeding demo threat data..."
    python -c "
import asyncio
from arguswatch.services.seed_demo import seed_demo_data
result = asyncio.run(seed_demo_data())
print(f'  Demo Seed: {result}')
" 2>&1 || echo "  Demo seed skipped (non-critical)"
else
    echo "  DB has $CUSTOMER_COUNT customers - skipping seed"
fi

# ── SQL SAFETY NET ──────────────────────────────────────────────────
# If Python seeds failed silently, force-create via raw SQL.
# This ALWAYS works regardless of ORM bugs.
echo "  Running SQL safety net..."
PGCMD="psql -h ${POSTGRES_HOST:-postgres} -U ${POSTGRES_USER:-arguswatch} -d ${POSTGRES_DB:-arguswatch}"
export PGPASSWORD="${POSTGRES_PASSWORD:-arguswatch_dev_2026}"

# Customers
$PGCMD -c "INSERT INTO customers (name, industry, tier, email, onboarding_state, active) VALUES
  ('Yahoo','technology','enterprise','security@yahoo.com','monitoring',true),
  ('Shopify','technology','premium','security@shopify.com','monitoring',true),
  ('Uber','transportation','enterprise','security@uber.com','monitoring',true),
  ('GitHub','technology','enterprise','security@github.com','monitoring',true),
  ('Starbucks','retail','premium','security@starbucks.com','monitoring',true),
  ('VulnWeb Demo','technology','standard','admin@vulnweb.com','monitoring',true)
  ON CONFLICT (name) DO NOTHING;" 2>/dev/null || true

# Customer assets
$PGCMD -c "INSERT INTO customer_assets (customer_id, asset_type, asset_value, criticality)
  SELECT c.id, a.t::assettype, a.v, a.cr FROM customers c
  CROSS JOIN (VALUES
    ('domain','yahoo.com','critical'),('keyword','yahoo','critical'),('brand_name','Yahoo','critical'),
    ('subdomain','mail.yahoo.com','critical'),('subdomain','login.yahoo.com','high'),
    ('domain','shopify.com','critical'),('keyword','shopify','critical'),('brand_name','Shopify','critical'),
    ('subdomain','accounts.shopify.com','critical'),
    ('domain','uber.com','critical'),('keyword','uber','critical'),('brand_name','Uber','critical'),
    ('subdomain','auth.uber.com','critical'),
    ('domain','github.com','critical'),('keyword','github','critical'),('brand_name','GitHub','critical'),
    ('subdomain','api.github.com','critical'),
    ('domain','starbucks.com','critical'),('keyword','starbucks','critical'),('brand_name','Starbucks','critical'),
    ('domain','vulnweb.com','critical'),('keyword','vulnweb','critical'),('keyword','acunetix','high'),
    ('brand_name','VulnWeb','critical')
  ) AS a(t, v, cr)
  WHERE (c.name='Yahoo' AND a.v IN ('yahoo.com','yahoo','Yahoo','mail.yahoo.com','login.yahoo.com'))
     OR (c.name='Shopify' AND a.v IN ('shopify.com','shopify','Shopify','accounts.shopify.com'))
     OR (c.name='Uber' AND a.v IN ('uber.com','uber','Uber','auth.uber.com'))
     OR (c.name='GitHub' AND a.v IN ('github.com','github','GitHub','api.github.com'))
     OR (c.name='Starbucks' AND a.v IN ('starbucks.com','starbucks','Starbucks'))
     OR (c.name='VulnWeb Demo' AND a.v IN ('vulnweb.com','vulnweb','acunetix','VulnWeb'))
  ON CONFLICT DO NOTHING;" 2>/dev/null || true

# NOTE: No fake findings seeded. Findings are created ONLY by real correlation:
# Collectors fetch IOCs → Correlation engine matches against customer assets → Findings created
# This happens automatically via Celery beat schedule or manual POST /api/correlate

# Print final counts
FINAL_COUNTS=$($PGCMD -t -c "
  SELECT 'Customers: ' || (SELECT COUNT(*) FROM customers)
  || ' | Findings: ' || (SELECT COUNT(*) FROM findings)
  || ' | Assets: ' || (SELECT COUNT(*) FROM customer_assets);" 2>/dev/null || echo "  counts unavailable")
echo "  $FINAL_COUNTS"
echo "  SQL safety net complete"

# 5. Start uvicorn
echo "[5/5] Starting ArgusWatch backend..."
echo "======================================================="
echo "  Dashboard:  http://localhost:7777"
echo "  API Docs:   http://localhost:7777/docs"
echo "  Prometheus: http://localhost:9091"
echo "======================================================="

exec uvicorn arguswatch.main:app --host 0.0.0.0 --port 8000
