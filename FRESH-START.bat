@echo off
echo ===================================================
echo   ArgusWatch AI v16.4.6 - Fresh Start (Windows)
echo   Solvent CyberSecurity LLC
echo   WARNING: This destroys ALL data and rebuilds
echo ===================================================
echo.

REM Check Docker
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Start Docker Desktop first.
    pause
    exit /b 1
)
echo [OK] Docker running

REM Nuke everything
echo.
echo [1/6] Stopping and removing all containers + volumes...
docker compose down -v --remove-orphans 2>nul

REM Build
echo.
echo [2/6] Building all images (2-5 min first time)...
docker compose build --no-cache
if errorlevel 1 (
    echo [ERROR] Build failed. Check Dockerfiles.
    pause
    exit /b 1
)
echo [OK] Images built

REM Start
echo.
echo [3/6] Starting 10 services...
docker compose up -d
echo [OK] Services started

REM Wait for backend
echo.
echo [4/6] Waiting for backend to bootstrap (migrations + seeding)...
echo       This takes 60-120 seconds...
timeout /t 10 /nobreak >nul
echo       10s...
timeout /t 10 /nobreak >nul
echo       20s...
timeout /t 10 /nobreak >nul
echo       30s...
timeout /t 10 /nobreak >nul
echo       40s...
timeout /t 10 /nobreak >nul
echo       50s...
timeout /t 10 /nobreak >nul
echo       60s...
timeout /t 10 /nobreak >nul
echo       70s...
timeout /t 10 /nobreak >nul
echo       80s... checking now

REM Check if customers exist
echo.
echo [5/6] Checking if customers were seeded...
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT COUNT(*) FROM customers;" 2>nul
echo.

REM Force-seed customers as safety net
echo       Force-seeding 6 demo customers (safety net)...
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c "INSERT INTO customers (name, industry, tier, email, onboarding_state, active) VALUES ('Yahoo','technology','enterprise','security@yahoo.com','monitoring',true), ('Shopify','technology','premium','security@shopify.com','monitoring',true), ('Uber','transportation','enterprise','security@uber.com','monitoring',true), ('GitHub','technology','enterprise','security@github.com','monitoring',true), ('Starbucks','retail','premium','security@starbucks.com','monitoring',true), ('VulnWeb Demo','technology','standard','admin@vulnweb.com','monitoring',true) ON CONFLICT (name) DO NOTHING;"

echo       Seeding customer assets...
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c "INSERT INTO customer_assets (customer_id, asset_type, asset_value, criticality) SELECT c.id, a.asset_type::assettype, a.asset_value, a.criticality FROM customers c CROSS JOIN (VALUES ('domain','yahoo.com','critical'),('keyword','yahoo','critical'),('brand_name','Yahoo','critical'),('subdomain','mail.yahoo.com','critical'),('subdomain','login.yahoo.com','high'),('domain','shopify.com','critical'),('keyword','shopify','critical'),('brand_name','Shopify','critical'),('subdomain','accounts.shopify.com','critical'),('domain','uber.com','critical'),('keyword','uber','critical'),('brand_name','Uber','critical'),('subdomain','auth.uber.com','critical'),('domain','github.com','critical'),('keyword','github','critical'),('brand_name','GitHub','critical'),('subdomain','api.github.com','critical'),('domain','starbucks.com','critical'),('keyword','starbucks','critical'),('brand_name','Starbucks','critical'),('domain','vulnweb.com','critical'),('keyword','vulnweb','critical'),('keyword','acunetix','high'),('brand_name','VulnWeb','critical')) AS a(asset_type, asset_value, criticality) WHERE (c.name='Yahoo' AND a.asset_value IN ('yahoo.com','yahoo','Yahoo','mail.yahoo.com','login.yahoo.com')) OR (c.name='Shopify' AND a.asset_value IN ('shopify.com','shopify','Shopify','accounts.shopify.com')) OR (c.name='Uber' AND a.asset_value IN ('uber.com','uber','Uber','auth.uber.com')) OR (c.name='GitHub' AND a.asset_value IN ('github.com','github','GitHub','api.github.com')) OR (c.name='Starbucks' AND a.asset_value IN ('starbucks.com','starbucks','Starbucks')) OR (c.name='VulnWeb Demo' AND a.asset_value IN ('vulnweb.com','vulnweb','acunetix','VulnWeb')) ON CONFLICT DO NOTHING;"

echo.
echo       Customers now:
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT name FROM customers ORDER BY id;"

REM Wait for intel collection
echo.
echo [6/6] Waiting for intel collection (30s)...
timeout /t 30 /nobreak >nul

REM Trigger correlation
echo.
echo       Triggering correlation + finding promotion + attribution...

REM Seed demo findings for all customers so dashboard shows data immediately
echo       Seeding demo findings...
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c "INSERT INTO findings (ioc_value,ioc_type,customer_id,severity,status,sla_hours,source_count,all_sources,confidence,first_seen,last_seen,created_at,matched_asset,correlation_type,sla_deadline) SELECT v.ioc,v.typ,c.id,v.sev::severitylevel,'NEW'::detectionstatus,v.sla,v.sc,('[' || chr(34) || v.src || chr(34) || ']')::jsonb,v.conf,NOW()-v.age*INTERVAL'1h',NOW(),NOW()-v.age*INTERVAL'1h',v.ma,v.ct,NOW()+v.sla*INTERVAL'1h' FROM customers c CROSS JOIN (VALUES ('phish-login.yahoo-verify.com','domain','CRITICAL',4,2,'phishtank',0.92,6,'yahoo.com','typosquat'),('185.220.101.34','ipv4','HIGH',12,1,'feodo',0.85,24,'yahoo.com','ip_range'),('CVE-2024-3400','cve_id','CRITICAL',4,1,'cisa_kev',0.95,3,'yahoo.com','tech_stack'),('yahoo-support-ticket.com','domain','HIGH',12,1,'urlhaus',0.78,48,'yahoo.com','typosquat'),('admin-yahoo-verify.com','domain','MEDIUM',72,1,'rss',0.65,72,'yahoo.com','typosquat'),('shopify-payment-update.com','domain','CRITICAL',4,2,'phishtank',0.91,8,'shopify.com','typosquat'),('accounts-shopify.net','domain','HIGH',12,1,'urlhaus',0.82,18,'shopify.com','typosquat'),('CVE-2024-21887','cve_id','CRITICAL',4,1,'cisa_kev',0.97,2,'shopify.com','tech_stack'),('45.155.205.233','ipv4','HIGH',12,1,'feodo',0.88,36,'shopify.com','ip_range'),('uber-driver-login.com','domain','CRITICAL',4,2,'phishtank',0.90,5,'uber.com','typosquat'),('uber-eats-refund.net','domain','HIGH',12,1,'urlhaus',0.79,30,'uber.com','typosquat'),('94.232.249.211','ipv4','HIGH',12,1,'threatfox',0.86,20,'uber.com','ip_range'),('CVE-2024-47575','cve_id','CRITICAL',4,1,'nvd',0.94,4,'uber.com','tech_stack'),('starbucks-rewards-claim.com','domain','CRITICAL',4,2,'phishtank',0.89,10,'starbucks.com','typosquat'),('starbucks-gift-card.net','domain','HIGH',12,1,'urlhaus',0.77,42,'starbucks.com','typosquat'),('reward-starbucks.com','domain','MEDIUM',72,1,'rss',0.62,60,'starbucks.com','typosquat'),('testphp.vulnweb.com/exploit','url','CRITICAL',4,1,'urlhaus',0.93,7,'vulnweb.com','exact_domain'),('vulnweb-scanner.com','domain','HIGH',12,1,'phishtank',0.81,15,'vulnweb.com','typosquat'),('CVE-2023-46805','cve_id','CRITICAL',4,1,'cisa_kev',0.96,1,'vulnweb.com','tech_stack')) AS v(ioc,typ,sev,sla,sc,src,conf,age,ma,ct) WHERE (c.name='Yahoo' AND v.ma='yahoo.com') OR (c.name='Shopify' AND v.ma='shopify.com') OR (c.name='Uber' AND v.ma='uber.com') OR (c.name='Starbucks' AND v.ma='starbucks.com') OR (c.name='VulnWeb Demo' AND v.ma='vulnweb.com') ON CONFLICT DO NOTHING;"

REM Also promote any real correlation matches to findings
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c "INSERT INTO findings (ioc_value, ioc_type, customer_id, severity, status, sla_hours, sla_deadline, source_count, all_sources, confidence, first_seen, last_seen, created_at) SELECT d.ioc_value, d.ioc_type, d.customer_id, d.severity, 'NEW', COALESCE(d.sla_hours,72), NOW() + INTERVAL '72 hours', 1, to_jsonb(ARRAY[d.source]), COALESCE(d.confidence,0.7), COALESCE(d.first_seen, d.created_at), COALESCE(d.last_seen, d.created_at), NOW() FROM detections d WHERE d.customer_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.ioc_value=d.ioc_value AND f.ioc_type=d.ioc_type AND f.customer_id=d.customer_id);"

REM Final stats
echo.
echo ===================================================
echo   ArgusWatch AI v16.4.6 - READY
echo ===================================================
echo.
echo   Stats:
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Detections: ' || COUNT(*) FROM detections;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Customers:  ' || COUNT(*) FROM customers;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Actors:     ' || COUNT(*) FROM threat_actors;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Findings:   ' || COUNT(*) FROM findings;"
echo.
echo   Access:
echo     Dashboard:  http://localhost:7777
echo     API Docs:   http://localhost:7777/docs
echo     HTTPS:      https://localhost:9443
echo.
echo   Commands:
echo     Logs:       docker compose logs -f backend
echo     Status:     docker ps
echo     Stop:       docker compose down
echo.
echo ===================================================
echo   Solvent CyberSecurity LLC
echo   Defending what matters. One command at a time.
echo ===================================================
echo.
pause
