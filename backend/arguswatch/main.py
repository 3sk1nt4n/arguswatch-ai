"""ArgusWatch AI-Agentic Threat Intelligence V16.4.7 - FastAPI backend."""
import os
import re
import logging
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text, and_, exists, case
from pydantic import BaseModel
from typing import Optional
from arguswatch.config import settings
from arguswatch.database import get_db
from arguswatch.models import (Detection, SeverityLevel, DetectionStatus, Customer,
    CustomerAsset, ThreatActor, CustomerExposure, DarkWebMention, CollectorRun, Enrichment, Finding)
from arguswatch.api.customers import router as customers_router
from arguswatch.api.detections import router as detections_router
from arguswatch.api.enrichments import enrich_router, remed_router
from arguswatch.api.ai_routes import router as ai_router
from arguswatch.api.stats_routes import router as stats_router
from arguswatch.api.findings_routes import router as findings_router
from arguswatch.api.ops_routes import router as ops_router
from arguswatch.api.settings_routes import router as settings_router
from arguswatch.auth import (
    get_current_user, require_role, authenticate_user, create_user,
    delete_user, list_users, create_access_token, UserInfo, LoginRequest, LoginResponse,
    AUTH_DISABLED,
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from arguswatch.metrics import setup_metrics

logger = logging.getLogger("arguswatch.main")

STATIC = Path(__file__).parent / "static"

def _sev(val):
    """Safe severity value extraction - handles both enum and string."""
    if val is None: return None
    return val.value if hasattr(val, 'value') else str(val)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"{'='*55}\n  ArgusWatch AI-Agentic Threat Intelligence V16.4.7 -- Starting\n{'='*55}")

    # Disable AI during boot to prevent 2+ hour hang (149 findings × 60s per AI call)
    try:
        import arguswatch.services.ai_pipeline_hooks as _ai_hooks
        _ai_hooks._boot_mode = True
    except Exception:
        pass
    
    # ── AUTO-MIGRATE: runs every startup, safe (IF NOT EXISTS) ──
    try:
        from arguswatch.database import async_session
        from sqlalchemy import text
        async with async_session() as db:
            migrations = [
                # V13: onboarding
                "ALTER TABLE customers ADD COLUMN IF NOT EXISTS onboarding_state VARCHAR(30) DEFAULT 'created'",
                "ALTER TABLE customers ADD COLUMN IF NOT EXISTS onboarding_updated_at TIMESTAMP",
                # V13: asset confidence
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 1.0",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS confidence_sources JSONB DEFAULT '[]'",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS discovery_source VARCHAR(100)",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS last_seen_in_ioc TIMESTAMP",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS ioc_hit_count INTEGER DEFAULT 0",
                # V14: tech risk + manual
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS tech_risk_baseline FLOAT DEFAULT 0.0",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN DEFAULT false",
                # V15: normalized + feed quality
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255)",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS finding_id BIGINT",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255)",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_confidence FLOAT DEFAULT 0.7",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_freshness_ts TIMESTAMP",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_score FLOAT",
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS match_proof JSONB",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_decision VARCHAR(20)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_reasoning TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_rescore_confidence FLOAT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS match_proof JSONB",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_narrative TEXT",
                "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS iocs_inserted INTEGER DEFAULT 0",
                "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS duration_seconds FLOAT",
                "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS error_detail TEXT",
                # V16: recon tracking
                "ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_status VARCHAR(20) DEFAULT NULL",
                "ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_error TEXT DEFAULT NULL",
                # V16: exposure history
                """CREATE TABLE IF NOT EXISTS exposure_history (
                    id SERIAL PRIMARY KEY,
                    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE NOT NULL,
                    snapshot_date TIMESTAMP NOT NULL,
                    overall_score FLOAT DEFAULT 0.0,
                    d1_score FLOAT DEFAULT 0.0, d2_score FLOAT DEFAULT 0.0,
                    d3_score FLOAT DEFAULT 0.0, d4_score FLOAT DEFAULT 0.0,
                    d5_score FLOAT DEFAULT 0.0,
                    total_detections INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW()
                )""",
                "CREATE INDEX IF NOT EXISTS ix_eh_customer_date ON exposure_history(customer_id, snapshot_date)",
                # V16.4.1: breach status
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS confirmed_exposure BOOLEAN DEFAULT FALSE",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS exposure_type VARCHAR(50) DEFAULT NULL",
                # V16.4.1: AI pipeline columns (also in migrate_v13_ai.py + 10_migrate_v16_4_1.sql)
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_decision VARCHAR(20)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_reasoning TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity_confidence FLOAT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_narrative TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_attribution_reasoning TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_flag BOOLEAN DEFAULT FALSE",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_reason TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_enriched_at TIMESTAMP",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_provider VARCHAR(50)",
                "ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS ai_narrative TEXT",
                # Fix NULL/empty/unknown discovery_source on existing assets
                "UPDATE customer_assets SET discovery_source = 'onboarding' WHERE (discovery_source IS NULL OR discovery_source = '' OR discovery_source = 'unknown') AND asset_type IN ('domain','email_domain')",
                "UPDATE customer_assets SET discovery_source = 'industry_default' WHERE (discovery_source IS NULL OR discovery_source = '' OR discovery_source = 'unknown') AND asset_type = 'tech_stack'",
                "UPDATE customer_assets SET discovery_source = 'auto_from_name' WHERE (discovery_source IS NULL OR discovery_source = '' OR discovery_source = 'unknown') AND asset_type IN ('brand_name','keyword')",
                "UPDATE customer_assets SET discovery_source = 'onboarding' WHERE (discovery_source IS NULL OR discovery_source = '' OR discovery_source = 'unknown')",
                # V16.4.7: IOC Type Registry table (for existing deployments)
                """CREATE TABLE IF NOT EXISTS ioc_type_registry (
                    id SERIAL PRIMARY KEY, type_name VARCHAR(80) UNIQUE NOT NULL,
                    regex TEXT, regex_confidence FLOAT DEFAULT 0.85, category VARCHAR(50),
                    base_severity VARCHAR(10) DEFAULT 'MEDIUM', sla_hours INTEGER DEFAULT 48,
                    assignee_role VARCHAR(50) DEFAULT 'secops',
                    mitre_technique VARCHAR(20), mitre_tactic VARCHAR(30), mitre_description TEXT,
                    kill_chain_stage VARCHAR(20), playbook_key VARCHAR(200) DEFAULT 'generic',
                    enrichment_source VARCHAR(30), auto_score_enabled BOOLEAN DEFAULT true,
                    kill_chain_weight FLOAT DEFAULT 1.0, tactic_weight FLOAT DEFAULT 1.0,
                    active BOOLEAN DEFAULT true, status VARCHAR(20) DEFAULT 'WORKING',
                    source_note TEXT, created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(), created_by VARCHAR(50) DEFAULT 'system'
                )""",
                """CREATE TABLE IF NOT EXISTS criticality_weights (
                    id SERIAL PRIMARY KEY, factor_name VARCHAR(50) UNIQUE NOT NULL,
                    weight FLOAT NOT NULL, description TEXT, updated_at TIMESTAMP DEFAULT NOW()
                )""",
                # V16.4.7: AI Prompt Management -  editable system prompts per hook
                """CREATE TABLE IF NOT EXISTS ai_prompts (
                    id SERIAL PRIMARY KEY,
                    hook_name VARCHAR(50) UNIQUE NOT NULL,
                    system_prompt TEXT NOT NULL,
                    temperature FLOAT DEFAULT 0.2,
                    max_tokens INTEGER DEFAULT 2048,
                    active BOOLEAN DEFAULT true,
                    industry_override JSONB DEFAULT '{}',
                    version INTEGER DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT NOW(),
                    updated_by VARCHAR(50) DEFAULT 'system'
                )""",
                # V16.4.7: MITRE sync tracking
                """CREATE TABLE IF NOT EXISTS mitre_sync_log (
                    id SERIAL PRIMARY KEY,
                    sync_date TIMESTAMP DEFAULT NOW(),
                    attack_version VARCHAR(20),
                    techniques_total INTEGER,
                    techniques_new INTEGER DEFAULT 0,
                    techniques_deprecated INTEGER DEFAULT 0,
                    ioc_types_flagged INTEGER DEFAULT 0,
                    details JSONB DEFAULT '{}'
                )""",
                # V16.4.7: Analyst override tracking (feeds prompt evolution)
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS analyst_override_severity VARCHAR(10)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS analyst_override_at TIMESTAMP",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS analyst_override_reason TEXT",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS analyst_override_by VARCHAR(100)",
                # V16.4.7: Cross-customer FP learning
                "ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS is_global BOOLEAN DEFAULT false",
                "ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS global_promoted_at TIMESTAMP",
                "ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS global_promoted_by VARCHAR(100)",
                "ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS cross_customer_count INTEGER DEFAULT 0",
                "ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS auto_close BOOLEAN DEFAULT false",
                # V16.4.7: Fix playbook_key width (was VARCHAR(50), need 200 for pipe-delimited keys)
                "ALTER TABLE ioc_type_registry ALTER COLUMN playbook_key TYPE VARCHAR(200)",
            ]
            for stmt in migrations:
                await db.execute(text(stmt))
            await db.commit()
            print(f"  + Auto-migrate: {len(migrations)} statements OK",flush=True)
    except Exception as e:
        print(f"  ! Auto-migrate: {e}",flush=True)

    # ── IOC Registry: Seed from legacy hardcoded dicts (first run only) ──
    try:
        from arguswatch.engine.ioc_registry import seed_from_legacy
        from arguswatch.database import async_session as _reg_session
        async with _reg_session() as _rdb:
            await seed_from_legacy(_rdb)
        print(f"  + IOC Registry: seeded",flush=True)
    except Exception as e:
        print(f"  ! IOC Registry seed: {e}",flush=True)

    # ── AI Prompts: Seed defaults (first run only) ──
    try:
        from arguswatch.engine.ai_prompt_manager import seed_default_prompts
        from arguswatch.database import async_session as _prompt_session
        async with _prompt_session() as _pdb:
            await seed_default_prompts(_pdb)
        print(f"  + AI Prompts: seeded",flush=True)
    except Exception as e:
        print(f"  ! AI Prompts seed: {e}",flush=True)

    import asyncio, httpx
    print(f"  Dashboard: http://localhost:7777")
    async def auto_bootstrap():
        await asyncio.sleep(2)
        # Demo customers are seeded AFTER intel-proxy collection (see below).

        # -- Wait for Intel Proxy Gateway --
        proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
        print(f"  >> Intel Proxy Gateway: {proxy_url}")
        proxy_ok = False
        for attempt in range(15):
            try:
                async with httpx.AsyncClient(timeout=5.0) as c:
                    resp = await c.get(f"{proxy_url}/health")
                    data = resp.json()
                    if data.get("internet_access"):
                        print(f"  + Intel Proxy: ONLINE (internet access confirmed)",flush=True)
                        proxy_ok = True
                        break
                    else:
                        print(f"  ! Intel Proxy: running but no internet (attempt {attempt+1})",flush=True)
            except Exception as e:
                if attempt < 5:
                    await asyncio.sleep(3)
                else:
                    print(f"  ! Intel Proxy not ready (attempt {attempt+1}): {str(e)[:60]}",flush=True)
                    await asyncio.sleep(2)

        if proxy_ok:
            # -- Intel Proxy is collecting real data in background --
            # It writes directly to PostgreSQL, so we just wait a bit
            print(f"  >> Intel Proxy is collecting real threat intel from:")
            print(f"     CISA KEV, MITRE ATT&CK, ThreatFox, Feodo Tracker,")
            print(f"     MalwareBazaar, OpenPhish, NVD, RansomFeed, RSS, Paste")
            print(f"  >> Data flows directly to PostgreSQL (shared DB)")

            # Wait for proxy to finish its auto-collection
            print(f"  >> Waiting for initial collection to complete...")
            from arguswatch.models import Detection
            from sqlalchemy import select, func as _bfunc
            for wait_round in range(6):
                await asyncio.sleep(10)
                from arguswatch.database import async_session as _as
                async with _as() as _db:
                    det_count = (await _db.execute(select(_bfunc.count(Detection.id)))).scalar() or 0
                if det_count > 50:
                    print(f"  + {det_count} detections collected - proceeding",flush=True)
                    break
                print(f"  >> {det_count} detections so far, waiting... ({(wait_round+1)*10}s)")

            # Check what was collected
            from arguswatch.database import async_session
            from arguswatch.models import Detection, ThreatActor, DarkWebMention, CollectorRun
            from sqlalchemy import select, func
            async with async_session() as db:
                det_count = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
                actor_count = (await db.execute(select(func.count(ThreatActor.id)))).scalar() or 0
                dw_count = (await db.execute(select(func.count(DarkWebMention.id)))).scalar() or 0
                run_count = (await db.execute(select(func.count(CollectorRun.id)))).scalar() or 0
            print(f"  + Real data collected: {det_count} detections, {actor_count} actors, {dw_count} dark web, {run_count} collector runs",flush=True)
        else:
            print(f"  !! Intel Proxy Gateway not available!")
            print(f"     Check: docker compose logs intel-proxy")

        # -- Auto-correlate detections -> findings --
        try:
            from arguswatch.engine.correlation_engine import correlate_new_detections
            from arguswatch.database import async_session
            async with async_session() as db:
                cr = await correlate_new_detections(db, limit=2000)
                await db.commit()
            routed = cr.get('routed', 0)
            unrouted = cr.get('unrouted', 0)
            print(f"  + Correlation: {routed} routed to customers, {unrouted} unmatched (global intel)",flush=True)
        except Exception as e:
            print(f"  ! Correlation: {e}",flush=True)

        # -- PROMOTE routed detections -> Finding rows --
        # Correlation sets customer_id on detections but does NOT create findings.
        # This step calls get_or_create_finding() for every routed detection.
        try:
            from arguswatch.engine.finding_manager import get_or_create_finding
            from arguswatch.models import Detection
            from arguswatch.database import async_session
            async with async_session() as db:
                from sqlalchemy import select as _sel
                r = await db.execute(
                    _sel(Detection).where(
                        Detection.customer_id != None,
                        Detection.finding_id == None,
                    )
                )
                dets = r.scalars().all()
                created = 0
                _boot_fids = []
                for d in dets:
                    try:
                        f, is_new = await get_or_create_finding(d, db)
                        if is_new:
                            created += 1
                            _boot_fids.append(f.id)
                    except Exception as fe:
                        pass  # skip individual failures
                await db.commit()
            print(f"  + Finding Promotion: {created} new findings from {len(dets)} routed detections", flush=True)
        except Exception as e:
            print(f"  ! Finding Promotion: {e}",flush=True)

        # -- Match ALL customers (8-strategy comprehensive matching) --
        # This is the MAIN matching engine. Correlation only does basic routing.
        # match_all_customers runs domain, keyword, brand, tech_stack, IP, email,
        # CIDR, and context matching for EVERY customer against ALL detections.
        try:
            from arguswatch.engine.customer_intel_matcher import match_all_customers
            from arguswatch.database import async_session
            async with async_session() as db:
                mr = await match_all_customers(db)
                await db.commit()
            total_m = mr.get('total_matches', 0)
            print(f"  + Match All Customers: {total_m} matches across {mr.get('customers_processed', 0)} customers",flush=True)
        except Exception as e:
            print(f"  ! Match All Customers: {e}",flush=True)

        # -- Recalculate exposure for all customers --
        try:
            from arguswatch.services.exposure_scorer import calculate_all_exposures
            er = await calculate_all_exposures()
            print(f"  + Exposure Recalc: {er}",flush=True)
        except Exception as e:
            print(f"  ! Exposure Recalc: {e}",flush=True)

        # -- Attribution: link findings to threat actors --
        print(f"  >> Running attribution...", flush=True)
        try:
            from arguswatch.engine.attribution_engine import run_attribution_pass
            from arguswatch.database import async_session
            async with async_session() as db:
                ar = await asyncio.wait_for(run_attribution_pass(db, limit=50), timeout=120)
                await db.commit()
            print(f"  + Attribution: {ar.get('attributed', 0)} findings linked to actors",flush=True)
        except asyncio.TimeoutError:
            print(f"  ! Attribution: timed out (120s) - Celery will continue",flush=True)
        except Exception as e:
            print(f"  ! Attribution: {e}",flush=True)

        # -- Campaign detection: group findings by actor+customer+timewindow --
        print(f"  >> Running campaign detection...", flush=True)
        try:
            from arguswatch.engine.campaign_detector import check_and_create_campaign
            from arguswatch.models import Finding
            from arguswatch.database import async_session
            async with async_session() as db:
                fr = await db.execute(select(Finding).where(Finding.actor_id != None, Finding.campaign_id == None).limit(200))
                campaigns_created = 0
                for f in fr.scalars().all():
                    try:
                        camp = await check_and_create_campaign(f, db)
                        if camp: campaigns_created += 1
                    except Exception:
                        pass
                await db.commit()
            print(f"  + Campaigns: {campaigns_created} new campaigns detected",flush=True)
        except Exception as e:
            print(f"  ! Campaigns: {e}",flush=True)

        # Re-enable AI for normal operation (Celery will handle AI triage)
        try:
            import arguswatch.services.ai_pipeline_hooks as _ai_hooks
            _ai_hooks._boot_mode = False
            print(f"  + Boot pipeline complete - AI re-enabled for Celery tasks", flush=True)
        except Exception:
            pass

        # -- Auto-seed demo customers (fresh deploy only) --
        # 4 HackerOne bug-bounty-scope companies with real intel data.
        # Each gets full onboard: assets -> recon -> targeted collection -> match
        # -> enrich -> score -> remediate -> campaigns -> exposure.
        # Only runs on fresh deploy (0 customers). Idempotent.
        DEMO_CUSTOMERS = [
            {"name": "Yahoo", "domain": "yahoo.com", "industry": "technology"},
            {"name": "Uber", "domain": "uber.com", "industry": "transportation"},
            {"name": "Shopify", "domain": "shopify.com", "industry": "technology"},
            {"name": "Starbucks", "domain": "starbucks.com", "industry": "retail"},
            {"name": "GitHub", "domain": "github.com", "industry": "technology"},
            {"name": "VulnWeb Demo", "domain": "vulnweb.com", "industry": "technology"},
        ]
        try:
            from arguswatch.models import Customer as _SeedCustomer
            from arguswatch.database import async_session as _seed_session
            from sqlalchemy import func as _sfunc
            async with _seed_session() as _sdb:
                cust_count = (await _sdb.execute(select(_sfunc.count(_SeedCustomer.id)))).scalar() or 0
            if cust_count == 0:
                print(f"  >> Fresh deploy: auto-seeding {len(DEMO_CUSTOMERS)} demo customers...")
                for demo in DEMO_CUSTOMERS:
                    try:
                        async with httpx.AsyncClient(timeout=180.0) as _sc:
                            resp = await _sc.post(
                                "http://127.0.0.1:7777/api/customers/onboard",
                                json=demo,
                                headers={"Content-Type": "application/json"},
                            )
                            if resp.status_code == 200:
                                r = resp.json()
                                matches = r.get("intel_match", {}).get("total_matches", 0)
                                findings = r.get("findings_promoted", 0)
                                remeds = r.get("remediations_created", 0)
                                exp = r.get("exposure", {})
                                score = exp.get("overall_score", exp.get("score", "?"))
                                print(f"  + {demo['name']:12s} {matches:3d} matches | {findings:3d} findings | {remeds:3d} remediations | exposure={score}",flush=True)
                            else:
                                print(f"  ! {demo['name']}: HTTP {resp.status_code}",flush=True)
                    except Exception as e:
                        print(f"  ! {demo['name']}: {str(e)[:80]}",flush=True)
                print(f"  >> Auto-seed complete. Dashboard ready.")
            else:
                print(f"  >> {cust_count} customers exist -  skipping auto-seed")
        except Exception as e:
            print(f"  ! Auto-seed error (non-fatal): {str(e)[:100]}",flush=True)

        # -- Customer Intel Matching (THE CRITICAL BRIDGE) --
        # Searches ALL global detections for matches against each customer's
        # discovered assets (IPs, domains, CIDRs, tech_stack, brands)
        try:
            from arguswatch.engine.customer_intel_matcher import match_all_customers
            from arguswatch.database import async_session
            async with async_session() as db:
                mr = await match_all_customers(db)
            total = mr.get('total_matches', 0)
            per = mr.get('per_customer', {})
            print(f"  + Customer Intel Match: {total} detections linked to customers",flush=True)
            for cname, cnt in per.items():
                if cnt > 0:
                    print(f"    -> {cname}: {cnt} matched")
        except Exception as e:
            print(f"  ! Customer Intel Match: {e}",flush=True)

        # -- Auto-run attribution --
        try:
            from arguswatch.engine.attribution_engine import run_attribution_pass
            from arguswatch.database import async_session
            async with async_session() as db:
                ar = await run_attribution_pass(db)
            print(f"  + Attribution: {ar.get('attributed', 0)} findings attributed",flush=True)
        except Exception as e:
            print(f"  ! Attribution: {e}",flush=True)

        # -- Campaign detection for all findings --
        try:
            from arguswatch.engine.campaign_detector import check_and_create_campaign
            from arguswatch.models import Finding
            from arguswatch.database import async_session
            async with async_session() as db:
                fr = await db.execute(select(Finding).where(Finding.actor_id != None, Finding.campaign_id == None).limit(500))
                campaigns_created = 0
                for f in fr.scalars().all():
                    camp = await check_and_create_campaign(f, db)
                    if camp: campaigns_created += 1
                await db.commit()
            if campaigns_created:
                print(f"  + Campaigns: {campaigns_created} campaigns detected",flush=True)
        except Exception as e:
            print(f"  ! Campaign detection: {e}",flush=True)

        # -- Auto-run exposure --
        try:
            from arguswatch.services.exposure_scorer import calculate_all_exposures
            await calculate_all_exposures()
            print(f"  + Exposure: recalculated",flush=True)
        except Exception as e:
            print(f"  ! Exposure: {e}",flush=True)

        print(f"{'='*55}\n  ArgusWatch AI-Agentic Threat Intelligence V16.4.7 -- READY (Real Intel)")
        print(f"  Intel Proxy: {proxy_url}")
        print(f"  Dashboard:   http://localhost:7777")
        print(f"  API Docs:    http://localhost:7777/docs")
        print(f"  Proxy Docs:  http://localhost:9000/docs")

        # V16.4: Check AI provider status
        try:
            from arguswatch.services.ai_pipeline_hooks import _provider, _pipeline_ai_available
            prov = _provider()
            available = _pipeline_ai_available()
            print(f"  AI Engine:   {prov.upper()} {'✅ ACTIVE' if available else '❌ NOT AVAILABLE'}")
            if prov == "ollama":
                from arguswatch.config import settings as _s
                print(f"  AI Model:    {_s.OLLAMA_MODEL}")
                print(f"  Ollama URL:  {_s.OLLAMA_URL}")
            print(f"  Autonomous:  {getattr(_s, 'AI_AUTONOMOUS', False)}")
            print(f"  Agents:      7 agentic AI workflows active")
        except Exception as _ai_e:
            print(f"  AI Engine:   Check failed ({_ai_e})")

        print(f"{'='*55}")
    asyncio.create_task(auto_bootstrap())
    yield

app = FastAPI(title="ArgusWatch AI-Agentic Threat Intelligence", version="16.4.7", lifespan=lifespan)
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:7777,http://localhost:3000").split(",")
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in _allowed_origins], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(customers_router)
app.include_router(detections_router)
app.include_router(enrich_router)
app.include_router(remed_router)
app.include_router(ai_router)
app.include_router(stats_router)
app.include_router(findings_router)
app.include_router(ops_router)
app.include_router(settings_router)

# V12 routers (playbook management + STIX/syslog export)
from arguswatch.api.enrichments import playbook_router, export_router
app.include_router(playbook_router)
app.include_router(export_router)

# V16.4.7: IOC Registry Admin API
from arguswatch.api.admin_routes import router as admin_router
app.include_router(admin_router)

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

# ── Rate Limiting (app-level defense-in-depth, nginx handles per-route) ──
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"], storage_uri="memory://")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Global Exception Handler -  never silently swallow errors ──
from starlette.responses import JSONResponse
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions, log them, return proper error response."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {type(exc).__name__}: {exc}", exc_info=True)
    # Don't leak internal error details to clients
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )

# ── Prometheus Metrics ──
setup_metrics(app)

# ── Global Auth Middleware ──
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Enforce auth on /api/ routes. Skips public paths and static files."""
    path = request.url.path
    public = {"/", "/health", "/health/network", "/docs", "/openapi.json",
              "/redoc", "/metrics", "/api/auth/login", "/api/seed/demo"}
    if path in public or not path.startswith("/api/") or path.endswith((".html",".css",".js",".ico")):
        return await call_next(request)
    if AUTH_DISABLED:
        request.state.user = UserInfo(username="dev-admin", role="admin")
        return await call_next(request)
    auth_header = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    token_param = request.query_params.get("token", "")
    if auth_header.startswith("Bearer "):
        from arguswatch.auth import verify_token
        try:
            request.state.user = verify_token(auth_header[7:])
        except Exception as e:  # was bare except
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    elif api_key:
        from arguswatch.auth import BOOTSTRAP_API_KEY
        if api_key == BOOTSTRAP_API_KEY and BOOTSTRAP_API_KEY:
            request.state.user = UserInfo(username="api-key-user", role="analyst", is_api_key=True)
        else:
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
    elif token_param:
        from arguswatch.auth import verify_token
        try:
            request.state.user = verify_token(token_param)
        except Exception as e:  # was bare except
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    else:
        return JSONResponse(status_code=401, content={"detail": "Auth required. POST /api/auth/login or set AUTH_DISABLED=true"})
    return await call_next(request)


# ═══════════════════════════════════════════════════════════
# AUTH ENDPOINTS - Login, User Management, Token Verification
# ═══════════════════════════════════════════════════════════

@app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
async def login(req: LoginRequest):
    """Authenticate and get JWT token."""
    user = await authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token, expires_in = create_access_token(user.username, user.role)
    return LoginResponse(
        access_token=token, expires_in=expires_in,
        role=user.role, username=user.username,
    )


@app.get("/api/auth/me", tags=["auth"])
async def auth_me(user: UserInfo = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {"username": user.username, "role": user.role, "auth_disabled": AUTH_DISABLED}


@app.get("/api/auth/users", tags=["auth"], dependencies=[Depends(require_role("admin"))])
async def get_users():
    """List all users (admin only)."""
    return {"users": await list_users()}


@app.post("/api/auth/users", tags=["auth"], dependencies=[Depends(require_role("admin"))])
async def post_user(username: str, password: str, role: str = "analyst"):
    """Create a new user (admin only)."""
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "Role must be admin, analyst, or viewer")
    ok = await create_user(username, password, role)
    if not ok:
        raise HTTPException(409, f"User '{username}' already exists")
    return {"status": "created", "username": username, "role": role}


@app.delete("/api/auth/users/{username}", tags=["auth"], dependencies=[Depends(require_role("admin"))])
async def del_user(username: str):
    """Delete a user (admin only). Cannot delete last admin."""
    ok = await delete_user(username)
    if not ok:
        raise HTTPException(400, f"Cannot delete '{username}' (last admin or not found)")
    return {"status": "deleted", "username": username}


# ── Protected endpoint groups ──────────────────────────────
# Write operations require analyst+, settings require admin
# Read endpoints are open when AUTH_DISABLED=true, otherwise require viewer+

_write_deps = [Depends(require_role("admin", "analyst"))]
_admin_deps = [Depends(require_role("admin"))]


# ── Static dashboard ──
@app.get("/")
async def dashboard():
    return FileResponse(STATIC / "dashboard.html")

@app.get("/threat-universe")
async def threat_universe_page():
    return FileResponse(STATIC / "threat-universe.html")

@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ok", "version": "16.4.7", "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "database": f"error: {e}"}

@app.get("/health/network")
async def network_health():
    """Test if container can reach external threat intel sources."""
    import httpx
    results = {}
    tests = [
        ("cisa", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        ("abuse_ch", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"),
        ("mitre", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"),
        ("nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"),
    ]
    any_ok = False
    for name, url in tests:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.head(url)
                results[name] = {"status": resp.status_code, "ok": True}
                any_ok = True
        except Exception as e:
            results[name] = {"status": str(e)[:80], "ok": False}
    return {
        "network_ok": any_ok,
        "tests": results,
        "fix": None if any_ok else "Docker cannot reach internet. Check: Docker Desktop network settings, Windows Firewall, VPN, corporate proxy. Set HTTP_PROXY/HTTPS_PROXY in docker-compose.yml if behind proxy."
    }

# ── Stats overview ──
# ── Source breakdown ──
# ── IOC type breakdown ──
# ── Timeline (last 7 days by day) ──
# ── Threat Actors ──
@app.get("/api/actors")
async def list_actors(
    limit: int = Query(50, le=500),
    offset: int = 0,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = select(ThreatActor)
    if search:
        q = q.where(ThreatActor.name.ilike(f"%{search}%"))
    q = q.order_by(ThreatActor.name).limit(limit).offset(offset)
    r = await db.execute(q)
    actors = r.scalars().all()
    _flag_map = {"China":"🇨🇳","Russia":"🇷🇺","Iran":"🇮🇷","North Korea":"🇰🇵",
                 "South Korea":"🇰🇷","Vietnam":"🇻🇳","Pakistan":"🇵🇰","India":"🇮🇳",
                 "Turkey":"🇹🇷","Israel":"🇮🇱","Lebanon":"🇱🇧","Nigeria":"🇳🇬",
                 "Ukraine":"🇺🇦","Palestine":"🇵🇸"}
    return [{"id": a.id, "name": a.name, "mitre_id": a.mitre_id, "aliases": a.aliases or [],
             "origin_country": a.origin_country, "motivation": a.motivation,
             "country_flag": _flag_map.get(a.origin_country, "🎭"),
             "target_sectors": a.target_sectors or [], "description": (a.description or "")[:300],
             "technique_count": len(a.techniques or [])} for a in actors]

@app.get("/api/actors/{actor_id}")
async def get_actor(actor_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    a = r.scalar_one_or_none()
    if not a: raise HTTPException(404, "Actor not found")
    return {
        "id": a.id, "name": a.name, "mitre_id": a.mitre_id,
        "aliases": a.aliases or [], "origin_country": a.origin_country,
        "country_flag": {"China":"🇨🇳","Russia":"🇷🇺","Iran":"🇮🇷","North Korea":"🇰🇵",
                         "Vietnam":"🇻🇳","Pakistan":"🇵🇰","India":"🇮🇳","Turkey":"🇹🇷",
                         "Israel":"🇮🇱","Lebanon":"🇱🇧"}.get(a.origin_country, "🎭"),
        "motivation": a.motivation, "sophistication": a.sophistication,
        "active_since": a.active_since, "last_seen": a.last_seen,
        "target_sectors": a.target_sectors or [], "target_countries": a.target_countries or [],
        "description": a.description or "",
        "techniques": (a.techniques or [])[:30],
        "references": (a.references or [])[:10],
        "iocs": a.iocs or [],
        "source": a.source,
    }

# ── Dark Web ──
@app.get("/api/darkweb")
async def list_darkweb(
    limit: int = Query(50, le=500),
    offset: int = 0,
    mention_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = select(DarkWebMention).order_by(desc(DarkWebMention.discovered_at))
    if mention_type:
        q = q.where(DarkWebMention.mention_type == mention_type)
    q = q.limit(limit).offset(offset)
    r = await db.execute(q)
    items = r.scalars().all()
    # Batch-load customer names
    dw_cust_ids = list({m.customer_id for m in items if m.customer_id})
    dw_cust_names = {}
    if dw_cust_ids:
        cnr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(dw_cust_ids)))
        dw_cust_names = {row.id: row.name for row in cnr.all()}
    return [{
        "id": m.id, "source": m.source, "mention_type": m.mention_type,
        "title": m.title, "content": m.content_snippet, "threat_actor": m.threat_actor,
        "severity": _sev(m.severity) or "HIGH",
        "discovered_at": m.discovered_at.isoformat() if m.discovered_at else None,
        "published_at": m.published_at.isoformat() if m.published_at else None,
        "url": m.url, "metadata": m.metadata_ or {},
        "customer_id": m.customer_id,
        "customer_name": dw_cust_names.get(m.customer_id, ""),
        "ai_summary": m.triage_narrative,
        "triage_classification": m.triage_classification,
    } for m in items]

@app.get("/api/darkweb/stats")
async def darkweb_stats(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(DarkWebMention.source, func.count(DarkWebMention.id).label("count"))
        .group_by(DarkWebMention.source).order_by(desc("count"))
    )
    by_source = [{"source": row.source, "count": row.count} for row in r]
    r2 = await db.execute(
        select(DarkWebMention.threat_actor, func.count(DarkWebMention.id).label("count"))
        .where(DarkWebMention.threat_actor != None, DarkWebMention.threat_actor != "")
        .group_by(DarkWebMention.threat_actor).order_by(desc("count")).limit(10)
    )
    top_actors = [{"actor": row.threat_actor, "count": row.count} for row in r2]
    total = await db.execute(select(func.count(DarkWebMention.id)))
    since_24h = datetime.utcnow() - timedelta(hours=24)
    recent = await db.execute(select(func.count()).where(DarkWebMention.discovered_at >= since_24h))
    # Count by type for dashboard stats
    ransomware_r = await db.execute(select(func.count()).where(
        DarkWebMention.mention_type.in_(["ransomware_claim", "extortion", "pre_encryption"])))
    paste_r = await db.execute(select(func.count()).where(
        DarkWebMention.mention_type.in_(["paste", "paste_dump", "credential_dump"])))
    attributed_r = await db.execute(select(func.count()).where(DarkWebMention.customer_id != None))
    triaged_r = await db.execute(select(func.count()).where(DarkWebMention.triaged_at != None))
    _total = total.scalar() or 0
    return {"total": _total, "total_mentions": _total, "dark_web_mentions": _total,
            "last_24h": recent.scalar() or 0,
            "ransomware_claims": ransomware_r.scalar() or 0,
            "paste_dumps": paste_r.scalar() or 0,
            "customer_attributed": attributed_r.scalar() or 0,
            "triaged": triaged_r.scalar() or 0,
            "by_source": by_source, "top_actors": top_actors}

# ── Collector control ──
class CollectorTrigger(BaseModel):
    collector: str

@app.get("/api/enrich/domain/{domain}")
async def enrich_domain_proxy(domain: str):
    """Real domain enrichment via Intel Proxy - DNS, WHOIS, reputation."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            resp = await c.get(f"{proxy_url}/enrich/domain/{domain}")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/enrich/ip/{ip}")
async def enrich_ip_proxy(ip: str):
    """Real IP enrichment via Intel Proxy - rDNS, AbuseIPDB, Shodan."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            resp = await c.get(f"{proxy_url}/enrich/ip/{ip}")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/discover/{domain}")
async def discover_assets_proxy(domain: str):
    """Real asset discovery via Intel Proxy - crt.sh, DNS, email patterns."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            resp = await c.get(f"{proxy_url}/discover/{domain}")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/search/compromise/{query:path}")
async def search_compromise_proxy(query: str):
    """Universal compromise search -  checks local DB, HudsonRock, HIBP, Sourcegraph, VirusTotal.
    Auto-detects input type (email, IP, hash, domain, CVE, API key, keyword).
    Powers the AI bar smart search."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=45.0) as c:
            resp = await c.get(f"{proxy_url}/search/compromise/{query}")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Compromise search failed: {str(e)[:200]}")

# ═══════════════════════════════════════════════════════════════
# CUSTOMER ONBOARDING - single endpoint, zero to monitored
# Fixes ALL 6 backend ❌ items:
#   1. Auto-extract domain from email
#   2. Immediate matching (no 30min wait)
#   3. Auto-trigger recon
#   4. Industry REQUIRED
#   5. Onboarding state machine
#   6. Minimum viable asset validation
# ═══════════════════════════════════════════════════════════════

VALID_INDUSTRIES = {
    "financial", "banking", "healthcare", "technology", "government",
    "defense", "energy", "retail", "manufacturing", "education",
    "legal", "insurance", "construction", "telecommunications",
    "media", "transportation", "hospitality", "real estate",
    "agriculture", "pharmaceutical", "cryptocurrency", "fintech",
    "critical infrastructure", "aerospace", "consulting", "nonprofit",
    "other",
}

@app.post("/api/customers/onboard", dependencies=_write_deps)
async def onboard_customer(request: Request, db: AsyncSession = Depends(get_db)):
    """One-call customer onboarding: create -> register assets -> recon -> match -> score.
    
    REQUIRED: name, industry, domain OR email (domain extracted from email)
    
    Body: {
      "name": "Apex Corp",
      "email": "admin@apex.com",
      "industry": "financial",
      "domain": "apex.com",           // optional if email provided
      "tier": "standard",             // optional
      "primary_contact": "John CISO", // optional
      "slack_channel": "#apex-alerts" // optional
    }
    
    Returns: {
      "customer_id": 1,
      "onboarding_state": "monitoring",
      "assets_auto_registered": ["domain:apex.com", "email_domain:apex.com", "brand_name:Apex Corp"],
      "recon_triggered": true,
      "intel_match_result": {"total_matches": 12, ...},
      "initial_exposure": {"score": 34.5, "d1": 45, "d2": 20, ...},
      "coverage_gaps": ["No github_org - Cat 2 API key scanning disabled", ...]
    }
    """
    body = await request.json()
    
    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip()
    industry = (body.get("industry") or "").strip().lower()
    domain = (body.get("domain") or "").strip().lower()
    tier = body.get("tier", "standard")
    primary_contact = body.get("primary_contact", "")
    slack_channel = body.get("slack_channel", "")
    
    # ── VALIDATION ──
    errors = []
    if not name:
        errors.append("name is required")
    if not industry:
        errors.append("industry is required - needed for threat actor targeting (D3)")
    elif industry not in VALID_INDUSTRIES:
        errors.append(f"industry must be one of: {', '.join(sorted(VALID_INDUSTRIES))}")
    
    # Auto-extract domain from email if not provided
    if not domain and email and "@" in email:
        domain = email.split("@")[1].lower()
    if not domain:
        errors.append("domain is required (or provide email to auto-extract)")
    
    if errors:
        return {"error": "Validation failed", "details": errors}
    
    # ── V16.4.7: Domain-name sanity check ──
    # Prevents onboarding "PAYPAL" with domain "apple.com"
    confirm = body.get("confirm", False)
    if name and domain and not confirm:
        d_root = domain.lower().replace("www.", "").split(".")[0]
        name_words = re.findall(r'[a-z0-9]{3,}', name.lower())
        name_concat = "".join(name_words)
        acronym = "".join(w[0] for w in name_words) if len(name_words) >= 2 else ""
        domain_ok = any(w in d_root or d_root in w for w in name_words) or \
                    d_root in name_concat or name_concat in d_root or \
                    (acronym and (acronym == d_root or d_root.startswith(acronym)))
        if not domain_ok:
            return {
                "error": "Domain mismatch",
                "detail": f"Company '{name}' and domain '{domain}' have no apparent connection. "
                          f"If this is intentional, resend with \"confirm\": true.",
                "name_words": name_words,
                "domain_root": d_root,
            }
    
    # ── V16.4.7: DNS validation -  domain must actually resolve ──
    if domain and not confirm:
        try:
            socket.getaddrinfo(domain, None)
        except socket.gaierror:
            return {
                "error": "Domain does not resolve",
                "detail": f"'{domain}' has no DNS A record. Check for typos. "
                          f"If this is intentional (e.g. internal domain), resend with \"confirm\": true.",
            }
    
    # ── STEP 1: Create customer ──
    try:
      existing = await db.execute(select(Customer).where(Customer.name == name))
      if existing.scalar_one_or_none():
        return {"error": f"Customer '{name}' already exists"}
    except Exception as e:
      return JSONResponse(status_code=500, content={"error": "DB check failed", "detail": str(e)[:200]})
    
    customer = Customer(
        name=name, industry=industry, tier=tier,
        primary_contact=primary_contact, email=email,
        slack_channel=slack_channel, onboarding_state="assets_added",
    )
    db.add(customer)
    await db.flush()
    await db.refresh(customer)
    cid = customer.id
    
    # ── STEP 2: Auto-register minimum viable assets ──
    auto_assets = []
    
    async def _add_asset(atype, aval):
        existing_a = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == atype,
                CustomerAsset.asset_value == aval,
            )
        )
        if not existing_a.scalar_one_or_none():
            db.add(CustomerAsset(
                customer_id=cid, asset_type=atype,
                asset_value=aval, criticality="high",
                discovery_source="onboarding_auto",
            ))
            auto_assets.append(f"{atype}:{aval}")
    
    # Domain
    await _add_asset("domain", domain)
    # Email domain (for credential matching) - wrapped in savepoint
    # because email_domain enum may not exist if migration 10 hasn't run
    try:
        async with db.begin_nested():
            await _add_asset("email_domain", domain)
    except Exception as e:
        # Fallback: register as keyword so S5 brand matching still catches it
        await _add_asset("keyword", domain)
    # Brand name (for S5 dark web matching)
    await _add_asset("brand_name", name)
    # Short brand (first word of name, if distinct enough)
    brand_short = name.split()[0] if name else ""
    if len(brand_short) >= 4 and brand_short.lower() != "the":
        await _add_asset("keyword", brand_short.lower())
    
    customer.onboarding_state = "assets_added"
    
    # ── STEP 2b: Industry Default Tech Stack ──
    # These are PROBABLE products based on industry. NOT confirmed.
    # Creates tech_stack assets with discovery_source="industry_default"
    # so CVE->product matching works even before operator confirms.
    # Lower confidence than manual entry -  tagged as probable.
    INDUSTRY_TECH_DEFAULTS = {
        # Product names use CPE-compatible format (verified 45/45 match NVD).
        # normalize("Exchange Server") matches cpe:...:exchange_server
        # These are PROBABLE products. Tagged discovery_source="industry_default".
        "financial": [
            "Exchange Server", "Sharepoint Server", "Netscaler",
            "Big Ip", "Database", "Vcenter Server", "Esxi",
            "Adaptive Security Appliance", "Ios Xe",
            "Fortios", "Pan Os", "Connect Secure",
            "Windows Server 2019", "Windows Server 2022",
        ],
        "healthcare": [
            "Exchange Server", "Sharepoint Server", "Netscaler",
            "Vcenter Server", "Esxi", "Database",
            "Adaptive Security Appliance", "Fortios",
            "Connect Secure", "Ios Xe",
            "Windows Server 2019",
        ],
        "technology": [
            "Confluence Server", "Jira Server", "Gitlab", "Jenkins",
            "Kubernetes", "Elasticsearch", "Redis", "Postgresql", "Mongodb",
            "Esxi", "Vcenter Server", "Horizon",
            "Ios Xe", "Junos", "Eos",
            "Exchange Server",
        ],
        "manufacturing": [
            "Exchange Server", "Netweaver",
            "Adaptive Security Appliance", "Firepower Threat Defense",
            "Vcenter Server", "Esxi", "Fortios",
            "Ios Xe", "Nx Os",
            "Windows Server 2019", "Idrac",
        ],
        "retail": [
            "Magento", "Exchange Server", "Netweaver",
            "Adaptive Security Appliance", "Fortios",
            "Vcenter Server", "Ios Xe",
            "Big Ip", "Windows Server 2019",
        ],
        "energy": [
            "Fortios", "Fortimanager", "Fortianalyzer",
            "Exchange Server", "Adaptive Security Appliance",
            "Vcenter Server", "Esxi", "Pan Os",
            "Ios Xe", "Ios Xr", "Nx Os",
            "Idrac", "Windows Server 2019",
        ],
        "government": [
            "Exchange Server", "Sharepoint Server",
            "Fortios", "Fortimanager", "Fortiproxy",
            "Pan Os", "Globalprotect", "Expedition",
            "Connect Secure", "Policy Secure",
            "Vcenter Server", "Esxi", "Nsx",
            "Big Ip", "Netscaler",
            "Adaptive Security Appliance", "Firepower Threat Defense",
            "Identity Services Engine",
            "Ios Xe", "Ios Xr",
            "Windows Server 2019", "Windows Server 2022",
        ],
        "education": [
            "Exchange Server", "Sharepoint Server",
            "Adaptive Security Appliance", "Fortios",
            "Vcenter Server", "Esxi",
            "Ios Xe", "Connect Secure",
            "Windows Server 2019",
        ],
        "defense": [
            "Exchange Server", "Sharepoint Server",
            "Fortios", "Fortimanager", "Fortiproxy", "Fortianalyzer",
            "Pan Os", "Globalprotect",
            "Connect Secure", "Policy Secure",
            "Adaptive Security Appliance", "Firepower Threat Defense",
            "Identity Services Engine",
            "Vcenter Server", "Esxi", "Nsx", "Horizon",
            "Big Ip", "Netscaler",
            "Ios Xe", "Ios Xr", "Nx Os",
            "Junos", "Junos Os Evolved",
            "Windows Server 2019", "Windows Server 2022",
            "Idrac", "Ilo",
        ],
        "insurance": [
            "Exchange Server", "Netscaler", "Big Ip",
            "Database", "Netweaver",
            "Adaptive Security Appliance", "Fortios",
            "Vcenter Server", "Ios Xe",
            "Windows Server 2019",
        ],
        "telecommunications": [
            "Junos", "Junos Os Evolved", "Eos",
            "Ios Xe", "Ios Xr", "Nx Os",
            "Adaptive Security Appliance", "Firepower Threat Defense",
            "Exchange Server", "Vcenter Server", "Esxi",
            "Database", "Fortios", "Pan Os",
            "Aruba Clearpass",
        ],
        "pharmaceutical": [
            "Netweaver", "Exchange Server", "Sharepoint Server",
            "Netscaler", "Database",
            "Vcenter Server", "Esxi",
            "Adaptive Security Appliance", "Fortios",
            "Ios Xe", "Windows Server 2019",
        ],
        "cryptocurrency": [
            "Kubernetes", "Elasticsearch", "Redis",
            "Postgresql", "Mongodb", "Gitlab",
            "Vcenter Server", "Esxi",
            "Ios Xe", "Fortios",
        ],
        "aerospace": [
            "Exchange Server", "Sharepoint Server",
            "Fortios", "Pan Os", "Connect Secure",
            "Adaptive Security Appliance", "Firepower Threat Defense",
            "Vcenter Server", "Esxi", "Nsx",
            "Ios Xe", "Ios Xr",
            "Big Ip", "Idrac", "Ilo",
            "Windows Server 2019", "Windows Server 2022",
        ],
        "transportation": [
            "Ios Xe", "Ios Xr", "Nx Os",
            "Adaptive Security Appliance", "Fortios",
            "Exchange Server", "Vcenter Server",
            "Windows Server 2019",
        ],
        "hospitality": [
            "Exchange Server", "Adaptive Security Appliance",
            "Fortios", "Vcenter Server",
            "Ios Xe", "Windows Server 2019",
        ],
    }
    
    defaults = INDUSTRY_TECH_DEFAULTS.get(industry, [])
    tech_added = []
    for product in defaults:
        try:
            async with db.begin_nested():
                await _add_asset("tech_stack", product)
                tech_added.append(product)
        except Exception as e:
            logger.debug(f"Suppressed: {e}")  # Skip duplicates or enum issues
    
    if tech_added:
        # Mark these as industry defaults, not confirmed
        try:
            await db.execute(text(
                "UPDATE customer_assets SET discovery_source = 'industry_default', "
                "criticality = 'medium' "
                "WHERE customer_id = :cid AND asset_type = 'tech_stack' "
                "AND discovery_source = 'onboarding_auto'"
            ), {"cid": cid})
        except Exception as e:
            logger.debug(f"Suppressed: {e}")
    
    await db.commit()
    
    result = {
        "customer_id": cid,
        "name": name,
        "industry": industry,
        "domain": domain,
        "assets_auto_registered": auto_assets,
        "tech_stack_defaults": tech_added,
        "tech_stack_note": f"{len(tech_added)} probable products added based on {industry} industry. Review in customer Tech Stack tab." if tech_added else "No industry defaults for this sector.",
    }
    
    # ── STEP 3: Trigger recon (non-blocking attempt) ──
    import httpx as httpx_client
    recon_url = os.environ.get("RECON_ENGINE_URL", "http://recon-engine:9001")
    try:
        async with httpx_client.AsyncClient(timeout=120.0) as c:
            resp = await c.post(f"{recon_url}/recon/{cid}", params={"domain": domain})
            recon_result = resp.json()
            result["recon"] = {
                "triggered": True,
                "assets_discovered": recon_result.get("assets_created", 0),
                "subdomains": recon_result.get("subdomains_found", 0),
                "ips": recon_result.get("ips_found", 0),
            }
            customer.recon_status = "success"
    except Exception as e:
        result["recon"] = {"triggered": False, "reason": str(e)[:100]}
        customer.recon_status = "failed"
        customer.recon_error = str(e)[:200]
        # Schedule async retry via Celery
        try:
            from arguswatch.tasks import retry_recon
            retry_recon.apply_async(args=[cid, domain], countdown=120)  # retry in 2min
            result["recon"]["retry_scheduled"] = True
        except Exception as e:
            result["recon"]["retry_scheduled"] = False
    
    # ── STEP 3b: V16.4.5 Trigger customer-targeted collectors immediately ──
    # These search FOR this specific customer's domain on free threat intel sources.
    # Without this, collectors only run on the hourly cycle = customer waits 1h for findings.
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    targeted_collectors = ["hudsonrock", "hibp_breaches", "typosquat", "pulsedive",
                           "leakix", "urlscan_community", "ransomwatch", "epss_top",
                           "shodan_internetdb", "crtsh"]  # V16.4.7: shodan + crtsh added
    targeted_results = {}
    try:
        async with httpx_client.AsyncClient(timeout=30.0) as c:
            for coll_name in targeted_collectors:
                try:
                    resp = await c.post(f"{proxy_url}/collect/{coll_name}")
                    if resp.status_code == 200:
                        coll_data = resp.json()
                        new_count = coll_data.get("new", 0)
                        if new_count > 0:
                            targeted_results[coll_name] = new_count
                except Exception as e:
                    logger.debug(f"Suppressed: {e}")  # Non-blocking - don't fail onboard if a collector times out
        result["targeted_collection"] = {
            "collectors_triggered": len(targeted_collectors),
            "new_detections": targeted_results,
            "total_new": sum(targeted_results.values()),
        }
    except Exception as e:
        result["targeted_collection"] = {"error": str(e)[:100]}

    # ── STEP 4: Immediate intel matching (don't wait 30min) ──
    try:
        from arguswatch.engine.customer_intel_matcher import match_customer_intel
        match_result = await match_customer_intel(cid, db)
        result["intel_match"] = {
            "total_matches": match_result.get("total_matches", 0),
            "ip": match_result.get("ip_matches", 0),
            "domain": match_result.get("domain_matches", 0),
            "tech": match_result.get("tech_matches", 0),
            "brand": match_result.get("brand_matches", 0),
            "context": match_result.get("context_matches", 0),
            "token_decode": match_result.get("token_decode_matches", 0),
        }
    except Exception as e:
        print(f"  ! Onboard intel match error for {name}: {e}",flush=True)
        result["intel_match"] = {"error": str(e)[:100]}
    
    # ── STEP 4a: Correlate ALL unrouted detections to this customer ──
    try:
        from arguswatch.engine.correlation_engine import correlate_new_detections
        cr = await correlate_new_detections(db, limit=5000)
        await db.commit()
        result["correlation"] = {"routed": cr.get("routed", 0), "unrouted": cr.get("unrouted", 0)}
    except Exception as e:
        print(f"  ! Onboard correlation error for {name}: {e}",flush=True)
        result["correlation"] = {"error": str(e)[:100]}
    
    # ── STEP 4a2: Promote routed detections -> Findings ──
    # Catches detections routed by correlation engine (Step 4a) that weren't
    # matched by intel matcher (Step 4). These MUST go through the full pipeline.
    try:
        from arguswatch.engine.finding_manager import get_or_create_finding
        from arguswatch.models import Detection
        routed_r = await db.execute(
            select(Detection).where(
                Detection.customer_id == cid,
                Detection.finding_id == None,
            )
        )
        promoted = 0
        _promoted_ids = []
        for d in routed_r.scalars().all():
            try:
                f, is_new = await get_or_create_finding(d, db)
                if is_new:
                    promoted += 1
                    _promoted_ids.append(f.id)
            except Exception as e:
                logger.debug(f"Suppressed: {e}")
        await db.commit()
        # BUG FIX: Run full pipeline for promoted findings (was missing entirely)
        # Without this: no severity scoring, no enrichment, no AI triage, no MITRE tag
        from arguswatch.engine.customer_intel_matcher import _post_match_pipeline
        for _pid in _promoted_ids:
            try:
                await _post_match_pipeline(_pid, db)
            except Exception as _ppe:
                logger.debug(f"Post-promote pipeline error: {_ppe}")
        result["findings_promoted"] = promoted
    except Exception as e:
        print(f"  ! Onboard finding promotion error for {name}: {e}",flush=True)
        result["findings_promoted"] = 0
    
    # ── STEP 4b: Remediations -  HANDLED BY _post_match_pipeline ──
    # Both match_customer_intel (Step 4) and Step 4a2 now call _post_match_pipeline()
    # which includes remediation generation. No need to duplicate.
    # The dedup guard in generate_action() would prevent crashes, but it's wasted work.
    
    # ── STEP 4c: Attribute findings to threat actors ──
    # This is a GLOBAL pass (not per-finding) -  runs across all findings for patterns.
    # Kept separate because _post_match_pipeline does per-finding campaign detection,
    # but attribution looks at cross-finding patterns.
    try:
        from arguswatch.engine.attribution_engine import run_attribution_pass
        attr_result = await run_attribution_pass(db, limit=500)
        result["attribution"] = {
            "processed": attr_result.get("processed", 0),
            "attributed": attr_result.get("attributed", 0),
        }
    except Exception as e:
        result["attribution"] = {"error": str(e)[:100]}
    
    # ── STEP 4d: Campaign detection -  HANDLED BY _post_match_pipeline ──
    # _post_match_pipeline() calls check_and_create_campaign() for each new finding.
    # Running it again here would just hit the dedup guard.
    
    # Count remediations + campaigns created by pipeline
    try:
        from arguswatch.models import FindingRemediation, Campaign
        rem_count = (await db.execute(
            select(func.count(FindingRemediation.id)).join(Finding).where(Finding.customer_id == cid)
        )).scalar() or 0
        camp_count = (await db.execute(
            select(func.count(Campaign.id)).where(Campaign.customer_id == cid)
        )).scalar() or 0
        result["remediations_created"] = rem_count
        result["campaigns_detected"] = camp_count
    except Exception:
        result["remediations_created"] = 0
        result["campaigns_detected"] = 0

    # ── STEP 5: Calculate initial exposure score ──
    try:
        from arguswatch.services.exposure_scorer import calculate_customer_exposure
        exp = await calculate_customer_exposure(cid, db)
        result["exposure"] = exp
    except Exception as e:
        result["exposure"] = {"error": str(e)[:100]}
    
    # ── STEP 5b: Seed exposure history for day-1 trend chart ──
    try:
        from arguswatch.models import ExposureHistory
        exp_data = result.get("exposure", {})
        if isinstance(exp_data, dict) and "error" not in exp_data:
            db.add(ExposureHistory(
                customer_id=cid,
                snapshot_date=datetime.utcnow(),
                overall_score=exp_data.get("overall_score", exp_data.get("score", 0)),
                d1_score=exp_data.get("d1", exp_data.get("d1_score", 0)),
                d2_score=exp_data.get("d2", exp_data.get("d2_score", 0)),
                d3_score=exp_data.get("d3", exp_data.get("d3_score", 0)),
                d4_score=exp_data.get("d4", exp_data.get("d4_score", 0)),
                d5_score=exp_data.get("d5", exp_data.get("d5_score", 0)),
            ))
    except Exception as e:
        logger.debug(f"Suppressed: {e}")
    
    # ── STEP 6: Set onboarding state ──
    total_matches = result.get("intel_match", {}).get("total_matches", 0)
    if total_matches > 0:
        customer.onboarding_state = "monitoring"
    else:
        customer.onboarding_state = "monitoring"  # Still monitoring, just no findings yet
    customer.onboarding_updated_at = datetime.utcnow()
    await db.commit()
    result["onboarding_state"] = customer.onboarding_state
    
    # ── STEP 7: Coverage gap analysis -  industry-aware, prioritized, actionable ──
    gaps = []
    asset_r = await db.execute(
        select(CustomerAsset.asset_type, func.count(CustomerAsset.id)).where(
            CustomerAsset.customer_id == cid
        ).group_by(CustomerAsset.asset_type)
    )
    asset_counts = {r[0]: r[1] for r in asset_r.all()}
    registered_types = set(asset_counts.keys())

    # Industry-specific gap definitions with priority + impact
    # Priority: P0 = critical for this industry, P1 = important, P2 = nice to have
    INDUSTRY_GAPS = {
        "technology": [
            ("github_org",       "P0", "No code leak scanning (leaked API keys, secrets, configs in repos)", "Add via Settings -> Customer -> Assets"),
            ("aws_account",      "P1", "No S3 bucket attribution -  public buckets won't link to this customer", "Add AWS account ID (12 digits)"),
            ("internal_domain",  "P1", "No internal hostname leak detection (.corp, .internal, .local)", "Add internal domain suffix"),
            ("tech_stack",       "P0", "No CVE matching -  won't detect vulnerabilities in their software", "Auto-populated from industry defaults"),
            ("ip",               "P0", "No C2/scanning IP correlation -  network threats invisible", "Discovered by recon or add manually"),
        ],
        "healthcare": [
            ("tech_stack",       "P0", "No CVE matching -  HIPAA requires vulnerability management", "Auto-populated from industry defaults"),
            ("ip",               "P0", "No network threat correlation -  ePHI systems unmonitored", "Discovered by recon or add manually"),
            ("internal_domain",  "P0", "No internal hostname leak detection -  ePHI server names in pastes", "Add internal domain suffix"),
            ("github_org",       "P2", "Code leak scanning disabled -  lower priority for non-tech healthcare", "Add if org has public repos"),
            ("aws_account",      "P1", "No cloud asset attribution -  HIPAA cloud compliance gap", "Add AWS/Azure account ID"),
        ],
        "financial": [
            ("tech_stack",       "P0", "No CVE matching -  PCI DSS requires vulnerability scanning", "Auto-populated from industry defaults"),
            ("ip",               "P0", "No C2 correlation -  payment infrastructure unmonitored", "Discovered by recon or add manually"),
            ("aws_account",      "P0", "No cloud attribution -  PCI DSS cloud compliance gap", "Add AWS account ID"),
            ("internal_domain",  "P1", "No internal hostname leak detection", "Add internal domain suffix"),
            ("github_org",       "P1", "No code leak scanning -  financial apps may leak keys", "Add if org has repos"),
        ],
        "retail": [
            ("tech_stack",       "P0", "No CVE matching for e-commerce platform", "Auto-populated from industry defaults"),
            ("ip",               "P0", "No C2/scanning correlation -  POS/e-commerce threats invisible", "Discovered by recon or add manually"),
            ("github_org",       "P2", "Code leak scanning -  lower priority for retail", "Add if org has public repos"),
            ("aws_account",      "P1", "No cloud attribution", "Add AWS account ID"),
            ("internal_domain",  "P2", "Internal hostname leak detection", "Add internal domain suffix"),
        ],
    }

    # Default gaps for unknown industries
    DEFAULT_GAPS = [
        ("github_org",       "P1", "No code leak scanning (leaked API keys, secrets)", "Add GitHub org name"),
        ("aws_account",      "P2", "No S3 bucket attribution", "Add AWS account ID"),
        ("internal_domain",  "P2", "No internal hostname leak detection", "Add internal domain suffix"),
        ("tech_stack",       "P1", "No CVE matching", "Auto-populated from industry defaults"),
        ("ip",               "P1", "No C2/scanning IP correlation", "Discovered by recon or add manually"),
    ]

    industry_gaps = INDUSTRY_GAPS.get(industry, DEFAULT_GAPS)
    recon_ips = result.get("recon", {}).get("ips", 0)
    recon_subs = result.get("recon", {}).get("subdomains", 0)
    findings_count = result.get("intel_match", {}).get("total_matches", 0)

    for asset_type, priority, impact, action in industry_gaps:
        # Skip if asset type already registered
        if asset_type in registered_types:
            continue
        # Skip IP gap if recon discovered IPs
        if asset_type == "ip" and recon_ips > 0:
            continue
        # Skip tech_stack gap if industry defaults were loaded
        if asset_type == "tech_stack" and "tech_stack" in registered_types:
            continue

        gaps.append({
            "asset_type": asset_type,
            "priority": priority,
            "impact": impact,
            "action": action,
            "industry_specific": industry in INDUSTRY_GAPS,
        })

    # Sort by priority
    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    gaps.sort(key=lambda g: priority_order.get(g["priority"], 9))

    # Calculate meaningful coverage percentage
    # Based on: what % of possible detection strategies are active for this customer?
    total_strategies = 8  # S1-S8
    active_strategies = 0
    if "ip" in registered_types or recon_ips > 0: active_strategies += 1  # S1
    if "ip" in registered_types: active_strategies += 1  # S2 (CIDR needs IP assets)
    if "domain" in registered_types: active_strategies += 2  # S3 + S6 (domain + context)
    if "tech_stack" in registered_types: active_strategies += 1  # S4
    if "brand_name" in registered_types or "keyword" in registered_types: active_strategies += 1  # S5
    if "github_org" in registered_types or "aws_account" in registered_types: active_strategies += 1  # S7
    # S8 (token decode) always works if domain is registered
    if "domain" in registered_types: active_strategies += 1
    coverage_pct = min(100, round((active_strategies / total_strategies) * 100))

    result["coverage_gaps"] = gaps
    result["coverage_pct"] = coverage_pct
    result["coverage_detail"] = {
        "strategies_active": active_strategies,
        "strategies_total": total_strategies,
        "assets_registered": sum(asset_counts.values()),
        "asset_types": dict(asset_counts),
        "p0_gaps": sum(1 for g in gaps if g["priority"] == "P0"),
        "p1_gaps": sum(1 for g in gaps if g["priority"] == "P1"),
        "p2_gaps": sum(1 for g in gaps if g["priority"] == "P2"),
    }
    
    # ── STEP 8: Schedule background re-match (catches IOCs that arrive after onboard) ──
    import asyncio
    async def _delayed_rematch():
        await asyncio.sleep(90)  # Wait for collectors to finish current cycle
        try:
            from arguswatch.database import async_session
            from arguswatch.engine.customer_intel_matcher import match_customer_intel, _post_match_pipeline
            from arguswatch.services.exposure_scorer import calculate_customer_exposure
            async with async_session() as _db:
                await match_customer_intel(cid, _db)
                # Promote any new detections to findings
                from arguswatch.engine.finding_manager import get_or_create_finding
                from arguswatch.models import Detection
                _dr = await _db.execute(
                    select(Detection).where(Detection.customer_id == cid, Detection.finding_id == None)
                )
                _promoted_bg = []
                for _d in _dr.scalars().all():
                    try:
                        _f, _is_new = await get_or_create_finding(_d, _db)
                        if _is_new:
                            _promoted_bg.append(_f.id)
                    except Exception as e:
                        logger.debug(f"Suppressed: {e}")
                await _db.commit()
                # Run full pipeline for promoted findings
                for _bgid in _promoted_bg:
                    try:
                        await _post_match_pipeline(_bgid, _db)
                    except Exception as _bge:
                        logger.debug(f"BG pipeline error: {_bge}")
                await calculate_customer_exposure(cid, _db)
                await _db.commit()
            print(f"  + Background re-match for {name}: complete ({len(_promoted_bg)} new findings pipelined)",flush=True)
        except Exception as e:
            print(f"  ! Background re-match for {name}: {e}",flush=True)
    asyncio.create_task(_delayed_rematch())
    
    return result


@app.get("/api/customers/{cid}/coverage")
async def customer_coverage(cid: int, db: AsyncSession = Depends(get_db)):
    """Get IOC category coverage analysis for a customer.
    Shows which of the 17 categories are active vs need configuration."""
    
    # Load customer
    cr = await db.execute(select(Customer).where(Customer.id == cid))
    customer = cr.scalar_one_or_none()
    if not customer:
        raise HTTPException(404, "Customer not found")
    
    # Load assets
    ar = await db.execute(
        select(CustomerAsset.asset_type).where(CustomerAsset.customer_id == cid)
    )
    asset_types = {r[0] for r in ar.all()}
    
    has_domain = "domain" in asset_types or "email_domain" in asset_types
    has_ip = "ip" in asset_types
    has_cidr = "cidr" in asset_types
    has_tech = "tech_stack" in asset_types
    has_github = "github_org" in asset_types
    has_aws = "aws_account" in asset_types
    has_azure = "azure_tenant" in asset_types
    has_internal = "internal_domain" in asset_types
    has_brand = "brand_name" in asset_types or "keyword" in asset_types
    has_industry = bool(customer.industry)
    
    # Detection count per ioc_type
    det_r = await db.execute(
        select(Detection.ioc_type, func.count(Detection.id)).where(
            Detection.customer_id == cid,
        ).group_by(Detection.ioc_type)
    )
    det_counts = dict(det_r.all())
    
    # Finding count per ioc_type (more meaningful for coverage)
    from arguswatch.models import Finding
    fi_r = await db.execute(
        select(Finding.ioc_type, func.count(Finding.id)).where(
            Finding.customer_id == cid,
        ).group_by(Finding.ioc_type)
    )
    fi_counts = dict(fi_r.all())
    
    # Also count by source for richer coverage data
    fi_src_r = await db.execute(
        select(Finding.all_sources).where(Finding.customer_id == cid)
    )
    source_set = set()
    for row in fi_src_r.scalars().all():
        if row:
            for s in (row if isinstance(row, list) else [row]):
                source_set.add(s)
    
    # Helper: sum counts from both detections and findings for given types
    # Bidirectional matching: search term in db_type OR db_type in search term
    all_counts = {}
    for k, v in det_counts.items():
        all_counts[k] = all_counts.get(k, 0) + v
    for k, v in fi_counts.items():
        all_counts[k] = all_counts.get(k, 0) + v
    
    def _count(types):
        total = 0
        matched_types = []
        types_lower = [t.lower() for t in types]
        for db_type, db_count in all_counts.items():
            if not db_type:
                continue
            dt = db_type.lower()
            # Exact match
            if dt in types_lower:
                total += db_count
                matched_types.append(db_type)
                continue
            # Bidirectional partial: search term in db_type OR db_type in search term
            for t in types_lower:
                if t in dt or dt in t:
                    total += db_count
                    matched_types.append(db_type)
                    break
        return total
    
    # Build categories using REAL IOC types that collectors actually produce
    categories = [
        {"cat": 1, "name": "Stolen Credentials", "emoji": "🔑", "status": "active" if has_domain else "needs_domain",
         "requirement": "domain", "detections": _count(
            ["email_password_combo", "username_password_combo", "credential", "breachdirectory",
             "stealer_log", "password", "combo"])},
        {"cat": 2, "name": "API Keys & Tokens", "emoji": "🔐", "status": "active" if has_github else ("partial" if has_domain else "inactive"),
         "requirement": "github_org", "detections": _count(
            ["aws_access_key", "github_pat", "api_key", "private_key", "secret_key",
             "token", "bearer", "openai_api_key", "stripe"])},
        {"cat": 3, "name": "Network IOCs", "emoji": "🌐", "status": "active" if (has_ip or has_cidr) else "needs_ip",
         "requirement": "ip or cidr", "detections": _count(["ipv4", "ipv6", "ip", "ip_address", "c2_ip"])},
        {"cat": 4, "name": "Domain & URL IOCs", "emoji": "🔗", "status": "active" if has_domain else "needs_domain",
         "requirement": "domain", "detections": _count(
            ["url", "domain", "fqdn", "malicious_url", "phishing_url", "dark_web_url",
             "subdomain", "hostname"])},
        {"cat": 5, "name": "Email IOCs", "emoji": "📧", "status": "active" if has_domain else "needs_domain",
         "requirement": "domain", "detections": _count(["email", "email_address", "executive_email"])},
        {"cat": 6, "name": "File & Hash IOCs", "emoji": "#️⃣", "status": "active" if has_industry else "inactive",
         "requirement": "industry (sector-level via D3)", "detections": _count(
            ["md5", "sha1", "sha256", "hash", "ssdeep", "hash_md5", "hash_sha1", "hash_sha256",
             "file_hash", "malware_hash"])},
        {"cat": 7, "name": "Infrastructure Leaks", "emoji": "🏗️", "status": "active" if has_github else ("partial" if has_internal else "inactive"),
         "requirement": "github_org or internal_domain", "detections": _count(
            ["config_file", "db_config", "internal_hostname", "backup_file", "exposed_service",
             "misconfiguration", "open_port"])},
        {"cat": 8, "name": "Financial & Identity", "emoji": "💳", "status": "global_indicator",
         "requirement": "None - sector-level signal",
         "detections": _count(["credit_card", "ssn", "financial", "swift_bic", "iban", "bank"]),
         "note": "Global threat indicator"},
        {"cat": 9, "name": "Threat Actor Intel", "emoji": "🎭", "status": "active" if has_brand else "needs_brand",
         "requirement": "brand_name", "detections": _count(
            ["ransomware", "apt_group", "ransom_note", "data_auction", "advisory",
             "ransomware_leak", "ransomware_claim", "actor"])},
        {"cat": 10, "name": "Session & Auth Tokens", "emoji": "🍪", "status": "context_only",
         "requirement": "Context attribution (S6)",
         "detections": _count(["session_cookie", "ntlm_hash", "saml", "jwt_token", "cookie"])},
        {"cat": 11, "name": "OAuth / SaaS Tokens", "emoji": "🔓", "status": "active" if has_github else "token_decode",
         "requirement": "github_org or JWT decoding (S8)",
         "detections": _count(["jwt", "azure_bearer", "google_oauth", "oauth_token", "oauth"])},
        {"cat": 12, "name": "SaaS Misconfiguration", "emoji": "☁️", "status": "active" if (has_aws or has_azure or has_ip) else "needs_cloud",
         "requirement": "aws_account, azure_tenant, or IP",
         "detections": _count(["s3_bucket", "elasticsearch", "cloud_misconfig", "exposed_bucket",
              "open_database", "misconfiguration"])},
        {"cat": 13, "name": "Privileged Account Anomaly", "emoji": "👑", "status": "context_only",
         "requirement": "Context attribution (S6)",
         "detections": _count(["privileged", "breakglass", "golden_ticket", "admin_credential"])},
        {"cat": 14, "name": "Shadow IT Discovery", "emoji": "👻", "status": "partial" if has_github else "context_only",
         "requirement": "github_org or cloud match",
         "detections": _count(["personal_cloud", "dev_tunnel", "rogue_endpoint", "shadow_it"])},
        {"cat": 15, "name": "Data Exfiltration", "emoji": "📤", "status": "context_only",
         "requirement": "Context attribution (S6). Full coverage needs SIEM.",
         "detections": _count(["data_transfer", "exfiltration", "archive_exfil", "data_leak"])},
        {"cat": 16, "name": "CVE", "emoji": "🛡️", "status": "active" if has_tech else ("partial" if has_domain else "needs_tech"),
         "requirement": "tech_stack",
         "detections": _count(["cve_id", "cve", "vulnerability", "exploit"])},
        {"cat": 17, "name": "Crypto Addresses", "emoji": "₿", "status": "context_only",
         "requirement": "Context attribution (S6).",
         "detections": _count(["bitcoin", "ethereum", "monero", "crypto_address", "btc", "eth"])},
    ]
    
    # Distribute any uncategorized detections/findings to the most relevant category
    categorized_total = sum(c["detections"] for c in categories)
    raw_total = sum(all_counts.values())
    
    active = sum(1 for c in categories if c["status"] == "active")
    partial = sum(1 for c in categories if c["status"] in ("partial", "token_decode", "sector_signal"))
    context = sum(1 for c in categories if c["status"] == "context_only")
    
    return {
        "customer": customer.name, "industry": customer.industry,
        "asset_types_registered": sorted(asset_types),
        "categories": categories,
        "summary": {
            "active": active, "partial": partial,
            "context_only": context,
            "global_indicator": 1,
            "total": 17,
        },
        "debug_ioc_types": all_counts,
        "debug_total_iocs": raw_total,
        "debug_categorized": categorized_total,
    }


@app.get("/api/customers/{cid}/collection-status")
async def customer_collection_status(cid: int, db: AsyncSession = Depends(get_db)):
    """Per-customer collection status - when was each source last queried for this customer."""
    from arguswatch.models import CollectorRun
    
    # Last collection runs (correct column names: collector_name, completed_at)
    runs_r = await db.execute(
        select(CollectorRun.collector_name, func.max(CollectorRun.completed_at))
        .group_by(CollectorRun.collector_name)
        .order_by(func.max(CollectorRun.completed_at).desc())
    )
    runs = runs_r.all()
    
    # Per-source detection count for THIS customer
    det_r = await db.execute(
        select(Detection.source, func.count(Detection.id)).where(
            Detection.customer_id == cid,
        ).group_by(Detection.source)
    )
    det_counts = dict(det_r.all())
    
    sources = []
    for collector_name, last_run in runs:
        sources.append({
            "source": collector_name,
            "name": collector_name,
            "last_run": last_run.isoformat() if last_run else None,
            "detections_for_customer": det_counts.get(collector_name, 0),
            "ioc_count": det_counts.get(collector_name, 0),
            "is_customer_aware": collector_name in ("hudsonrock", "breachdirectory", "spycloud",
                                             "shodan", "grep_app", "github"),
        })
    
    return {"customer_id": cid, "sources": sources}


@app.get("/api/customers/{cid}/attribution-breakdown")  
async def customer_attribution_breakdown(cid: int, db: AsyncSession = Depends(get_db)):
    """How were detections attributed to this customer? Breakdown by strategy."""
    
    r = await db.execute(
        select(Detection.correlation_type, func.count(Detection.id)).where(
            Detection.customer_id == cid,
        ).group_by(Detection.correlation_type)
    )
    
    strategy_names = {
        "exact_ip": "S1: Exact IP match",
        "ip_range": "S2: CIDR range match",
        "email_domain": "S3: Email domain boundary",
        "url_domain": "S3: URL domain boundary",
        "keyword": "S3: Domain keyword in raw_text",
        "cve_tech_stack": "S4: CVE->tech stack correlation",
        "brand_name": "S5: Brand keyword in dark web",
        "context_proximity": "S6: Context attribution (raw_text proximity)",
        "context_metadata": "S6: Context attribution (same paste/message)",
        "cloud_org_match": "S7: Cloud/org asset match",
        "token_decode": "S8: JWT/SAML body decoding",
    }
    
    breakdown = []
    for corr_type, count in r.all():
        breakdown.append({
            "strategy": strategy_names.get(corr_type, corr_type or "unknown"),
            "correlation_type": corr_type,
            "count": count,
        })
    
    return {"customer_id": cid, "breakdown": sorted(breakdown, key=lambda x: -x["count"])}


@app.get("/api/customers/{cid}/threat-summary")
async def customer_threat_summary(cid: int, db: AsyncSession = Depends(get_db)):
    """Auto-generated threat summary for a customer - no AI needed, pure data.
    Returns structured summary from REAL data, not LLM hallucination."""
    
    cr = await db.execute(select(Customer).where(Customer.id == cid))
    cust = cr.scalar_one_or_none()
    if not cust:
        raise HTTPException(404, "Customer not found")
    
    # Detection breakdown by severity (from Findings for consistency with customer header)
    from arguswatch.models import Finding
    sev_r = await db.execute(
        select(Finding.severity, func.count(Finding.id)).where(
            Finding.customer_id == cid,
        ).group_by(Finding.severity)
    )
    severity_counts = {str(r[0].value if hasattr(r[0], 'value') else r[0]): r[1] for r in sev_r.all()}
    
    # Also get detection count for the headline
    det_total_r = await db.execute(
        select(func.count(Detection.id)).where(Detection.customer_id == cid)
    )
    total_det_count = det_total_r.scalar() or 0
    
    # Top IOC types
    type_r = await db.execute(
        select(Detection.ioc_type, func.count(Detection.id)).where(
            Detection.customer_id == cid,
        ).group_by(Detection.ioc_type).order_by(func.count(Detection.id).desc()).limit(5)
    )
    top_types = [{"type": r[0], "count": r[1]} for r in type_r.all()]
    
    # Top sources
    src_r = await db.execute(
        select(Detection.source, func.count(Detection.id)).where(
            Detection.customer_id == cid,
        ).group_by(Detection.source).order_by(func.count(Detection.id).desc()).limit(5)
    )
    top_sources = [{"source": r[0], "count": r[1]} for r in src_r.all()]
    
    # Exposure score - use ExposureHistory (has overall_score + d1-d5 dimensions)
    from arguswatch.models import ExposureHistory
    exp_r = await db.execute(
        select(ExposureHistory).where(ExposureHistory.customer_id == cid)
        .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
    )
    exp = exp_r.scalar_one_or_none()
    
    # Recent critical detections
    crit_r = await db.execute(
        select(Detection.ioc_type, Detection.ioc_value, Detection.source, Detection.created_at).where(
            Detection.customer_id == cid,
            Detection.severity == SeverityLevel.CRITICAL,
        ).order_by(Detection.created_at.desc()).limit(5)
    )
    critical_items = [{"type": r[0], "value": r[1][:40], "source": r[2],
                       "when": r[3].isoformat() if r[3] else None} for r in crit_r.all()]
    
    total_findings = sum(severity_counts.values())
    risk_label = "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0 else \
                 "HIGH" if severity_counts.get("HIGH", 0) > 0 else \
                 "MEDIUM" if total_findings > 0 else "LOW"
    
    return {
        "customer": cust.name,
        "industry": cust.industry,
        "risk_level": risk_label,
        "total_open_detections": total_det_count,
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
        "top_ioc_types": top_types,
        "top_sources": top_sources,
        "critical_items": critical_items,
        "exposure": {
            "score": exp.overall_score if exp else 0,
            "d1_direct": exp.d1_score if exp else 0,
            "d2_exploitation": exp.d2_score if exp else 0,
            "d3_actor_intent": exp.d3_score if exp else 0,
            "d4_attack_surface": exp.d4_score if exp else 0,
            "d5_business_criticality": exp.d5_score if exp else 0,
        } if exp else None,
        "headline": f"{cust.name}: {total_det_count} detections, {total_findings} findings, {severity_counts.get('CRITICAL', 0)} critical. "
                    f"Exposure score {exp.overall_score if exp else 0:.0f}/100. "
                    f"Top threat: {top_types[0]['type'] if top_types else 'none'} ({top_types[0]['count'] if top_types else 0} hits)."
                    + (f" ⚠️ {len(critical_items)} critical items need immediate attention." if critical_items else ""),
    }


# ════════════════════════════════════════════════════════════
# BREACH STATUS - "Has our data been confirmed exposed?"
# One call answers the #1 MSSP customer question.
# ════════════════════════════════════════════════════════════

@app.get("/api/customers/{cid}/breach-status")
async def customer_breach_status(cid: int, db: AsyncSession = Depends(get_db)):
    """Breach status for a customer. Returns confirmed exposure events from real evidence."""
    from arguswatch.models import Customer, Finding, Detection, DarkWebMention
    from sqlalchemy import or_, func

    # Verify customer exists
    cr = await db.execute(select(Customer).where(Customer.id == cid))
    cust = cr.scalar_one_or_none()
    if not cust:
        raise HTTPException(404, "Customer not found")

    exposure_events = []

    # 1. Findings explicitly flagged as confirmed exposure
    flagged = await db.execute(
        select(Finding).where(
            Finding.customer_id == cid,
            Finding.confirmed_exposure == True,
        ).order_by(Finding.first_seen.desc()).limit(50)
    )
    for f in flagged.scalars().all():
        exposure_events.append({
            "type": f.exposure_type or "confirmed_exposure",
            "ioc_value": f.ioc_value[:100],
            "severity": _sev(f.severity) or "HIGH",
            "source": (f.all_sources or ["unknown"])[0] if f.all_sources else "unknown",
            "discovered": f.first_seen.isoformat() if f.first_seen else None,
            "actor": f.actor_name,
            "finding_id": f.id,
        })

    # 2. Ransomware leak site mentions (ransomwatch/ransomfeed)
    ransom_hits = await db.execute(text("""
        SELECT d.source, d.raw_text, d.created_at, d.severity, d.metadata
        FROM detections d
        WHERE d.customer_id = :cid
          AND d.source IN ('ransomwatch', 'ransomfeed')
        ORDER BY d.created_at DESC LIMIT 20
    """), {"cid": cid})
    for row in ransom_hits.all():
        meta = row[4] if isinstance(row[4], dict) else {}
        exposure_events.append({
            "type": "ransomware_leak_site",
            "actor": meta.get("group", "unknown"),
            "detail": (row[1] or "")[:200],
            "discovered": row[2].isoformat() if row[2] else None,
            "source": row[0],
        })

    # 3. Stealer logs (hudsonrock)
    stealer_count = await db.execute(text("""
        SELECT COUNT(*) FROM detections
        WHERE customer_id = :cid AND source = 'hudsonrock'
    """), {"cid": cid})
    stealer_n = stealer_count.scalar() or 0
    if stealer_n > 0:
        stealer_first = await db.execute(text("""
            SELECT MIN(created_at) FROM detections
            WHERE customer_id = :cid AND source = 'hudsonrock'
        """), {"cid": cid})
        sf_val = stealer_first.scalar()
        exposure_events.append({
            "type": "stealer_log",
            "emails_found": stealer_n,
            "source": "hudsonrock",
            "discovered": sf_val.isoformat() if sf_val else None,
        })

    # 4. Credential dumps in pastes
    cred_dumps = await db.execute(text("""
        SELECT COUNT(*), MIN(created_at) FROM detections
        WHERE customer_id = :cid
          AND source = 'paste'
          AND ioc_type IN ('email_password_combo', 'csv_credential_dump')
    """), {"cid": cid})
    cred_row = cred_dumps.one()
    if cred_row[0] and cred_row[0] > 0:
        exposure_events.append({
            "type": "credential_dump",
            "credentials_found": cred_row[0],
            "source": "paste",
            "discovered": cred_row[1].isoformat() if cred_row[1] else None,
        })

    # 5. Dark web mentions
    dw_hits = await db.execute(text("""
        SELECT content_snippet, threat_actor, severity, discovered_at FROM darkweb_mentions
        WHERE customer_id = :cid
        ORDER BY discovered_at DESC LIMIT 10
    """), {"cid": cid})
    for row in dw_hits.all():
        exposure_events.append({
            "type": "dark_web_mention",
            "detail": (row[0] or "")[:200],
            "actor": row[1],
            "severity": row[2],
            "source": "darkweb",
            "discovered": row[3].isoformat() if row[3] else None,
        })

    # 6. EDR/SIEM exfiltration events
    exfil_events = await db.execute(text("""
        SELECT COUNT(*), MIN(created_at) FROM detections
        WHERE customer_id = :cid
          AND ioc_type = 'data_exfiltration_evidence'
    """), {"cid": cid})
    exfil_row = exfil_events.one()
    if exfil_row[0] and exfil_row[0] > 0:
        exposure_events.append({
            "type": "data_exfiltration",
            "events_count": exfil_row[0],
            "source": "edr/siem",
            "discovered": exfil_row[1].isoformat() if exfil_row[1] else None,
        })

    # Determine overall status
    confirmed = len(exposure_events) > 0
    first_seen = None
    if exposure_events:
        dates = [e.get("discovered") for e in exposure_events if e.get("discovered")]
        if dates:
            first_seen = min(dates)

    # Risk label logic
    has_ransom = any(e["type"] == "ransomware_leak_site" for e in exposure_events)
    has_stealer = any(e["type"] == "stealer_log" for e in exposure_events)
    has_creds = any(e["type"] == "credential_dump" for e in exposure_events)
    has_exfil = any(e["type"] == "data_exfiltration" for e in exposure_events)
    has_dw = any(e["type"] == "dark_web_mention" for e in exposure_events)

    if has_ransom or has_exfil:
        risk_label = "CONFIRMED BREACH"
    elif has_stealer and has_creds:
        risk_label = "CREDENTIALS COMPROMISED"
    elif has_stealer or has_creds:
        risk_label = "CREDENTIALS EXPOSED"
    elif has_dw:
        risk_label = "DARK WEB EXPOSURE"
    else:
        risk_label = "NO CONFIRMED EXPOSURE"

    return {
        "customer_id": cid,
        "customer_name": cust.name,
        "confirmed_exposed": confirmed,
        "risk_label": risk_label,
        "exposure_events": exposure_events,
        "event_count": len(exposure_events),
        "first_seen": first_seen,
        "summary": {
            "ransomware_claims": sum(1 for e in exposure_events if e["type"] == "ransomware_leak_site"),
            "stealer_log_emails": stealer_n,
            "credential_dumps": cred_row[0] if cred_row[0] else 0,
            "dark_web_mentions": sum(1 for e in exposure_events if e["type"] == "dark_web_mention"),
            "exfiltration_events": exfil_row[0] if exfil_row[0] else 0,
        },
    }


@app.get("/api/customers/{cid}/threat-graph")
async def customer_threat_graph(cid: int, db: AsyncSession = Depends(get_db)):
    """3D force-directed graph data for a customer's threat universe.
    Returns nodes (assets, findings, actors, campaigns, dark web) and edges between them.
    """
    from arguswatch.models import (
        Customer, CustomerAsset, Finding, Detection, ThreatActor,
        Campaign, DarkWebMention,
    )

    cr = await db.execute(select(Customer).where(Customer.id == cid))
    cust = cr.scalar_one_or_none()
    if not cust:
        raise HTTPException(404, "Customer not found")

    nodes = []
    links = []
    node_ids = set()

    # ── Central customer node ──
    cust_nid = f"customer_{cust.id}"
    nodes.append({"id": cust_nid, "type": "customer", "label": cust.name,
                  "size": 18, "severity": "none", "meta": {"sector": cust.industry or ""}})
    node_ids.add(cust_nid)

    # ── Assets ──
    ar = await db.execute(
        select(CustomerAsset).where(CustomerAsset.customer_id == cid).limit(100)
    )
    assets = ar.scalars().all()
    for a in assets:
        nid = f"asset_{a.id}"
        nodes.append({"id": nid, "type": "asset", "label": a.asset_value,
                      "size": 6, "severity": "none",
                      "meta": {"asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type), "confidence": round(getattr(a, "confidence", 1.0) or 1.0, 2)}})
        node_ids.add(nid)
        links.append({"source": cust_nid, "target": nid, "type": "owns"})

    # ── Findings ──
    fr = await db.execute(
        select(Finding).where(Finding.customer_id == cid).order_by(Finding.created_at.desc()).limit(200)
    )
    findings = fr.scalars().all()
    sev_size = {"CRITICAL": 16, "HIGH": 12, "MEDIUM": 9, "LOW": 6}
    for f in findings:
        nid = f"finding_{f.id}"
        sev = _sev(f.severity) or "MEDIUM"
        nodes.append({"id": nid, "type": "finding", "label": f.ioc_value[:40],
                      "size": sev_size.get(sev, 8), "severity": sev,
                      "meta": {"ioc_type": f.ioc_type, "status": f.status.value if f.status else "NEW",
                               "confidence": round(f.confidence or 0.5, 2),
                               "sources": f.all_sources or []}})
        node_ids.add(nid)

        # Link finding -> matching asset
        if f.matched_asset:
            for a in assets:
                if a.asset_value and f.matched_asset and a.asset_value.lower() in f.matched_asset.lower():
                    links.append({"source": f"asset_{a.id}", "target": nid, "type": "matched"})
                    break
            else:
                links.append({"source": cust_nid, "target": nid, "type": "detected"})
        else:
            links.append({"source": cust_nid, "target": nid, "type": "detected"})

        # Link finding -> actor
        if f.actor_id:
            anid = f"actor_{f.actor_id}"
            if anid not in node_ids:
                nodes.append({"id": anid, "type": "actor",
                              "label": f.actor_name or f"Actor #{f.actor_id}",
                              "size": 14, "severity": "none", "meta": {}})
                node_ids.add(anid)
            links.append({"source": nid, "target": anid, "type": "attributed"})

        # Link finding -> campaign
        if f.campaign_id:
            cnid = f"campaign_{f.campaign_id}"
            if cnid not in node_ids:
                # Will be enriched below
                nodes.append({"id": cnid, "type": "campaign", "label": f"Campaign #{f.campaign_id}",
                              "size": 14, "severity": "HIGH", "meta": {}})
                node_ids.add(cnid)
            links.append({"source": nid, "target": cnid, "type": "partof"})

    # ── Actors - enrich with details ──
    actor_ids = [int(nid.split("_")[1]) for nid in node_ids if nid.startswith("actor_")]
    if actor_ids:
        acr = await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))
        for ta in acr.scalars().all():
            # Update existing node
            for n in nodes:
                if n["id"] == f"actor_{ta.id}":
                    n["label"] = ta.name
                    n["meta"] = {"country": ta.origin_country or "", "motivation": ta.motivation or "",
                                 "sophistication": ta.sophistication or ""}
                    break

    # ── Campaigns - enrich ──
    camp_ids = [int(nid.split("_")[1]) for nid in node_ids if nid.startswith("campaign_")]
    if camp_ids:
        ccr = await db.execute(select(Campaign).where(Campaign.id.in_(camp_ids)))
        for ca in ccr.scalars().all():
            for n in nodes:
                if n["id"] == f"campaign_{ca.id}":
                    n["label"] = ca.name or f"Campaign #{ca.id}"
                    n["severity"] = _sev(ca.severity) or "HIGH"
                    n["meta"] = {"status": ca.status or "", "kill_chain": ca.kill_chain_stage or ""}
                    break
            # Link campaign -> actor
            if ca.actor_id and f"actor_{ca.actor_id}" in node_ids:
                links.append({"source": f"campaign_{ca.id}", "target": f"actor_{ca.actor_id}", "type": "runby"})

    # ── Dark Web Mentions ──
    dwr = await db.execute(
        select(DarkWebMention).where(DarkWebMention.customer_id == cid)
        .order_by(DarkWebMention.discovered_at.desc()).limit(30)
    )
    for dw in dwr.scalars().all():
        nid = f"darkweb_{dw.id}"
        nodes.append({"id": nid, "type": "darkweb", "label": (dw.source or "dark web")[:30],
                      "size": 10, "severity": "HIGH",
                      "meta": {"source": dw.source or "", "snippet": (dw.content_snippet or "")[:100]}})
        node_ids.add(nid)
        links.append({"source": cust_nid, "target": nid, "type": "mentioned"})

    # ── Detections (sample - link to findings) ──
    dr = await db.execute(
        select(Detection).where(Detection.customer_id == cid, Detection.finding_id.isnot(None))
        .order_by(Detection.created_at.desc()).limit(50)
    )
    det_by_finding = {}
    for d in dr.scalars().all():
        fid = f"finding_{d.finding_id}"
        det_by_finding.setdefault(fid, 0)
        det_by_finding[fid] += 1
    # Add detection counts to finding meta
    for n in nodes:
        if n["id"] in det_by_finding:
            n["meta"]["detection_count"] = det_by_finding[n["id"]]

    import json as _json
    _result = {
        "customer": cust.name,
        "nodes": nodes,
        "links": links,
        "stats": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "assets": sum(1 for n in nodes if n["type"] == "asset"),
            "findings": sum(1 for n in nodes if n["type"] == "finding"),
            "actors": sum(1 for n in nodes if n["type"] == "actor"),
            "campaigns": sum(1 for n in nodes if n["type"] == "campaign"),
            "darkweb": sum(1 for n in nodes if n["type"] == "darkweb"),
        },
    }
    return JSONResponse(content=_json.loads(_json.dumps(_result, default=str)))


@app.get("/api/customers/{cid}/sla-compliance")
async def customer_sla_compliance(cid: int, db: AsyncSession = Depends(get_db)):
    """SLA compliance tracking - how many findings met vs breached SLA deadlines."""
    from arguswatch.models import Finding
    
    # All findings for this customer
    f_r = await db.execute(
        select(Finding).where(Finding.customer_id == cid)
    )
    findings = f_r.scalars().all()
    
    if not findings:
        return {"customer_id": cid, "total": 0, "met": 0, "breached": 0, "open": 0, "compliance_pct": 100}
    
    met = 0
    breached = 0
    open_findings = 0
    breached_items = []
    
    for f in findings:
        deadline = getattr(f, "sla_deadline", None)
        resolved = getattr(f, "resolved_at", None)
        status = getattr(f, "status", "")
        
        if status in ("REMEDIATED", "VERIFIED_CLOSED", "FALSE_POSITIVE", "CLOSED"):
            if deadline and resolved:
                if resolved <= deadline:
                    met += 1
                else:
                    breached += 1
                    breached_items.append({
                        "finding_id": f.id,
                        "severity": str(getattr(f, "severity", "")),
                        "hours_over": round((resolved - deadline).total_seconds() / 3600, 1),
                    })
            else:
                met += 1  # No deadline = no breach
        else:
            open_findings += 1
            # Check if currently breaching
            if deadline and datetime.utcnow() > deadline:
                breached += 1
                breached_items.append({
                    "finding_id": f.id,
                    "severity": str(getattr(f, "severity", "")),
                    "hours_over": round((datetime.utcnow() - deadline).total_seconds() / 3600, 1),
                    "still_open": True,
                })
    
    total_judged = met + breached
    compliance_pct = round(met / total_judged * 100) if total_judged > 0 else 100
    
    return {
        "customer_id": cid,
        "total_findings": len(findings),
        "met": met,
        "breached": breached,
        "open": open_findings,
        "compliance_pct": compliance_pct,
        "breached_items": breached_items[:10],
    }





@app.post("/api/customers/{cid}/tech-stack", dependencies=[Depends(require_role("admin", "analyst"))])
async def add_manual_tech_stack(cid: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Manual tech stack entry - lets operators declare software the customer runs.
    
    This is the fix for Problem B: recon engine only discovers HTTP headers,
    but enterprise stacks like Exchange, FortiOS, Confluence aren't in headers.
    
    Body: {"products": ["Exchange 2019", "FortiOS 7.2", "Confluence 8.5"]}
    """
    body = await request.json()
    products = body.get("products", [])
    if not products:
        return {"error": "products array required"}
    
    added = 0
    for product in products:
        product = product.strip()
        if not product:
            continue
        # Check if already exists
        existing = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == "tech_stack",
                CustomerAsset.asset_value == product,
            ).limit(1)
        )
        if existing.scalar_one_or_none():
            continue
        db.add(CustomerAsset(
            customer_id=cid,
            asset_type="tech_stack",
            asset_value=product,
            criticality="high",
            confidence=1.0,
            confidence_sources=["analyst_manual"],
            discovery_source="manual_entry",
            manual_entry=True,
        ))
        added += 1
    
    await db.commit()
    return {"added": added, "customer_id": cid, "products": products}


@app.post("/api/customers/{cid}/assets", dependencies=[Depends(require_role("admin", "analyst"))])
async def register_customer_assets(cid: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Register customer cloud, org, and identity assets for full IOC coverage.
    
    This is how ALL 17 IOC categories become actionable:
   - github_org: enables GitHub/grep.app per-org secret scanning (Cat 2, 7, 11)
   - aws_account: enables S3 bucket attribution (Cat 12)
   - azure_tenant: enables Azure blob attribution (Cat 12)
   - internal_domain: enables internal hostname matching (Cat 7)
   - org_name: enables brand matching and context attribution (Cat 9, 13, 14)
    
    Body: {
      "assets": [
        {"type": "github_org", "value": "acme-corp"},
        {"type": "aws_account", "value": "123456789012"},
        {"type": "azure_tenant", "value": "acme.onmicrosoft.com"},
        {"type": "internal_domain", "value": "acme.corp"},
        {"type": "org_name", "value": "Acme Corporation"},
        {"type": "gcp_project", "value": "acme-prod-123"},
        {"type": "slack_workspace", "value": "acme-corp"},
        {"type": "email_domain", "value": "acme.com"}
      ]
    }
    """
    body = await request.json()
    assets_input = body.get("assets", [])
    if not assets_input:
        return {"error": "assets array required"}
    
    VALID_TYPES = {
        "github_org", "aws_account", "azure_tenant", "gcp_project",
        "internal_domain", "org_name", "slack_workspace", "email_domain",
        "domain", "subdomain", "ip", "cidr", "tech_stack", "keyword",
        "brand_name",
    }
    
    added = 0
    skipped = 0
    for asset in assets_input:
        asset_type = asset.get("type", "").strip()
        asset_value = asset.get("value", "").strip()
        if not asset_type or not asset_value:
            skipped += 1
            continue
        if asset_type not in VALID_TYPES:
            skipped += 1
            continue
        
        existing = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == asset_type,
                CustomerAsset.asset_value == asset_value,
            ).limit(1)
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue
        
        db.add(CustomerAsset(
            customer_id=cid,
            asset_type=asset_type,
            asset_value=asset_value,
            criticality=asset.get("criticality", "high"),
            confidence=1.0,
            confidence_sources=["analyst_manual"],
            discovery_source="manual_entry",
            manual_entry=True,
        ))
        added += 1
    
    await db.commit()
    return {"added": added, "skipped": skipped, "customer_id": cid}


# ════════════════════════════════════════════════════════════
# EDR TELEMETRY - hash correlation for endpoint visibility
# ════════════════════════════════════════════════════════════

@app.post("/api/edr/telemetry", dependencies=[Depends(require_role("admin", "analyst"))])
async def ingest_edr(request: Request, db: AsyncSession = Depends(get_db)):
    """Ingest file hash observations from EDR agent or SIEM.
    
    Body: {
      "customer_id": 5,
      "observations": [
        {"hostname": "WS-01", "hash_sha256": "abc...", "file_path": "C:\\mal.exe", "process_name": "mal.exe"}
      ]
    }
    
    This enables hash correlation - without EDR data, hash IOCs from
    MalwareBazaar/ThreatFox cannot be matched to customers.
    """
    body = await request.json()
    cid = body.get("customer_id")
    obs = body.get("observations", [])
    if not cid or not obs:
        return {"error": "customer_id and observations array required"}
    from arguswatch.engine.edr_correlator import ingest_edr_telemetry
    return await ingest_edr_telemetry(cid, obs, db)


@app.post("/api/edr/correlate/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def correlate_edr(customer_id: int, db: AsyncSession = Depends(get_db)):
    """Correlate customer's EDR hash observations against threat intel detections.
    Matches file hashes seen on customer endpoints against known malware hashes."""
    from arguswatch.engine.edr_correlator import correlate_edr_hashes
    return await correlate_edr_hashes(customer_id, db)


# ════════════════════════════════════════════════════════════
# EVENT INGEST WEBHOOK - lightweight structured log receiver
# Accepts events from CrowdStrike, Defender, Splunk, any SIEM.
# No vendor SDK. No agent. Just a POST with JSON.
# ════════════════════════════════════════════════════════════

class EventIngestItem(BaseModel):
    customer_id: int
    source: str = "siem"               # crowdstrike, defender, splunk, sentinel, custom
    event_type: str                     # data_exfiltration, lateral_movement, privilege_escalation, etc.
    hostname: str = ""
    process: str = ""
    destination_ip: str = ""
    bytes_transferred: int = 0
    raw: str = ""
    severity: str = "HIGH"             # LOW, MEDIUM, HIGH, CRITICAL
    metadata: dict = {}

class EventIngestRequest(BaseModel):
    events: list[EventIngestItem]

# ════════════════════════════════════════════════════════════
# METRICS - monitoring and observability
# ════════════════════════════════════════════════════════════

# ── IOC Scanner ──
class ScanRequest(BaseModel):
    text: str

# ── Seed ──
## Seed endpoints removed -  platform starts clean. Onboard customers via dashboard.


# ══════════════════════════════════════════════════════════════════════════
# AGENTIC INVESTIGATION (v16.4.7) -  LLM reasons AFTER compromise results
# Regex classifies (0ms) -> compromise check (2-10s) -> LLM investigates (30-90s local)
# ══════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════
# #4 AI MATCH CONFIDENCE (v16.4.7) -  AI scores ambiguous matches
# Only runs on keyword/brand matches, not exact_domain (which is definitive)
# ══════════════════════════════════════════════════════════════════════════

# ── Enterprise activation status ──
# ── Escalation tiers ──
# ══════════════════════════════════════════════════════
# FINDINGS - V12 analyst-facing endpoints
# ══════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════
# AI AGENT - 10 tools
# ══════════════════════════════════════════════════════
class AgentQuery(BaseModel):
    question: str
    provider: str = "auto"
    conversation_history: list = []

class ToolRequest(BaseModel):
    args: dict = {}

# ══════════════════════════════════════════════════════
# EXPOSURE SCORING
# ══════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════
# PDF REPORTS
# ══════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════
# ENRICHMENT
# ══════════════════════════════════════════════════════
@app.post("/api/enrich/{detection_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def enrich_detection_endpoint(detection_id: int):
    from arguswatch.services.enrichment_pipeline import enrich_detection
    result = await enrich_detection(detection_id)
    return result

@app.post("/api/enrich/batch", dependencies=[Depends(require_role("admin", "analyst"))])
async def enrich_batch(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Enrich latest unenriched detections."""
    from arguswatch.services.enrichment_pipeline import enrich_detection
    from arguswatch.models import Enrichment as EnrichModel
    r = await db.execute(
        select(Detection.id).outerjoin(EnrichModel, EnrichModel.detection_id == Detection.id)
        .where(EnrichModel.id == None)
        .order_by(desc(Detection.created_at)).limit(limit)
    )
    ids = [row[0] for row in r.all()]
    results = []
    for did in ids:
        r = await enrich_detection(did)
        results.append(r)
    return {"enriched": len(results), "results": results}

# ══════════════════════════════════════════════════════
# REMEDIATION TRACKER
# ══════════════════════════════════════════════════════
# Remediations list handled by remed_router (api/enrichments.py)

@app.patch("/api/remediations/{action_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def update_remediation(action_id: int, status: str,
                              notes: str = "", db: AsyncSession = Depends(get_db)):
    from arguswatch.models import RemediationAction
    from arguswatch.services.recheck import schedule_recheck
    r = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = r.scalar_one_or_none()
    if not action: raise HTTPException(404, "Remediation not found")
    action.status = status
    if status == "completed":
        action.completed_at = datetime.utcnow()
        await db.flush()
        await schedule_recheck(action.detection_id, action.id)
    await db.commit()
    return {"id": action.id, "status": action.status}

# ══════════════════════════════════════════════════════
# SLA / ESCALATION
# ══════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════
# STIX EXPORT
# ══════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════
# ATTRIBUTION  (Playbooks handled by playbook_router above)
# ══════════════════════════════════════════════════════
# ── Exposure / Risk ──
# ── Attribution ──
# ── Correlation ──
# ── Playbooks ──
# ── STIX + CEF ──
# ── Remediation status update ──
# Detection status update handled by detections_router (api/detections.py)


# ═══════════════════════════════════════════════════════════════════════
# ASSET DISCOVERY - file upload endpoints (GAP 1 fix)
# ═══════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════
# V16.4: AGENTIC AI ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

