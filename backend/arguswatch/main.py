"""ArgusWatch AI-Agentic Threat Intelligence V16.4.1 - FastAPI backend."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
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
    CustomerAsset, ThreatActor, CustomerExposure, DarkWebMention, CollectorRun, Enrichment)
from arguswatch.api.customers import router as customers_router
from arguswatch.api.detections import router as detections_router
from arguswatch.api.enrichments import enrich_router, remed_router
from arguswatch.auth import (
    get_current_user, require_role, authenticate_user, create_user,
    delete_user, list_users, create_access_token, UserInfo, LoginRequest, LoginResponse,
    AUTH_DISABLED,
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from arguswatch.metrics import setup_metrics

STATIC = Path(__file__).parent / "static"

def _sev(val):
    """Safe severity value extraction - handles both enum and string."""
    if val is None: return None
    return val.value if hasattr(val, 'value') else str(val)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"{'='*55}\n  ArgusWatch AI-Agentic Threat Intelligence V16.4.1 -- Starting\n{'='*55}")
    
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
            ]
            for stmt in migrations:
                await db.execute(text(stmt))
            await db.commit()
            print(f"  + Auto-migrate: {len(migrations)} statements OK")
    except Exception as e:
        print(f"  ! Auto-migrate: {e}")
    
    import asyncio, httpx
    print(f"  Dashboard: http://localhost:7777")
    async def auto_bootstrap():
        await asyncio.sleep(2)
        # NO SEED DATA - platform starts clean. Onboard real customers via dashboard.

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
                        print(f"  + Intel Proxy: ONLINE (internet access confirmed)")
                        proxy_ok = True
                        break
                    else:
                        print(f"  ! Intel Proxy: running but no internet (attempt {attempt+1})")
            except Exception as e:
                if attempt < 5:
                    await asyncio.sleep(3)
                else:
                    print(f"  ! Intel Proxy not ready (attempt {attempt+1}): {str(e)[:60]}")
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
                    print(f"  + {det_count} detections collected - proceeding")
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
            print(f"  + Real data collected: {det_count} detections, {actor_count} actors, {dw_count} dark web, {run_count} collector runs")
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
            print(f"  + Correlation: {routed} routed to customers, {unrouted} unmatched (global intel)")
        except Exception as e:
            print(f"  ! Correlation: {e}")

        # -- PROMOTE routed detections → Finding rows --
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
                for d in dets:
                    try:
                        f, is_new = await get_or_create_finding(d, db)
                        if is_new:
                            created += 1
                    except Exception as fe:
                        pass  # skip individual failures
                await db.commit()
            print(f"  + Finding Promotion: {created} new findings from {len(dets)} routed detections")
        except Exception as e:
            print(f"  ! Finding Promotion: {e}")

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
            print(f"  + Customer Intel Match: {total} detections linked to customers")
            for cname, cnt in per.items():
                if cnt > 0:
                    print(f"    -> {cname}: {cnt} matched")
        except Exception as e:
            print(f"  ! Customer Intel Match: {e}")

        # -- Auto-run attribution --
        try:
            from arguswatch.engine.attribution_engine import run_attribution_pass
            from arguswatch.database import async_session
            async with async_session() as db:
                ar = await run_attribution_pass(db)
            print(f"  + Attribution: {ar.get('attributed', 0)} findings attributed")
        except Exception as e:
            print(f"  ! Attribution: {e}")

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
                print(f"  + Campaigns: {campaigns_created} campaigns detected")
        except Exception as e:
            print(f"  ! Campaign detection: {e}")

        # -- Auto-run exposure --
        try:
            from arguswatch.services.exposure_scorer import calculate_all_exposures
            await calculate_all_exposures()
            print(f"  + Exposure: recalculated")
        except Exception as e:
            print(f"  ! Exposure: {e}")

        print(f"{'='*55}\n  ArgusWatch AI-Agentic Threat Intelligence V16.4.1 -- READY (Real Intel)")
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

app = FastAPI(title="ArgusWatch AI-Agentic Threat Intelligence", version="16.4.1", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(customers_router)
app.include_router(detections_router)
app.include_router(enrich_router)
app.include_router(remed_router)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

# ── Rate Limiting (app-level defense-in-depth, nginx handles per-route) ──
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"], storage_uri="memory://")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
        except:
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
        except:
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
    user = authenticate_user(req.username, req.password)
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
    return {"users": list_users()}


@app.post("/api/auth/users", tags=["auth"], dependencies=[Depends(require_role("admin"))])
async def post_user(username: str, password: str, role: str = "analyst"):
    """Create a new user (admin only)."""
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "Role must be admin, analyst, or viewer")
    ok = create_user(username, password, role)
    if not ok:
        raise HTTPException(409, f"User '{username}' already exists")
    return {"status": "created", "username": username, "role": role}


@app.delete("/api/auth/users/{username}", tags=["auth"], dependencies=[Depends(require_role("admin"))])
async def del_user(username: str):
    """Delete a user (admin only). Cannot delete last admin."""
    ok = delete_user(username)
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
        return {"status": "ok", "version": "13.0.0", "database": "connected"}
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
@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    sev_counts = {}
    for sev in SeverityLevel:
        r = await db.execute(select(func.count()).where(Detection.severity == sev))
        sev_counts[sev.value] = r.scalar() or 0
    status_counts = {}
    for st in DetectionStatus:
        r = await db.execute(select(func.count()).where(Detection.status == st))
        status_counts[st.value] = r.scalar() or 0
    total = await db.execute(select(func.count(Detection.id)))
    cust_count = await db.execute(select(func.count(Customer.id)))
    actor_count = await db.execute(select(func.count(ThreatActor.id)))
    darkweb_count = await db.execute(select(func.count(DarkWebMention.id)))
    # 24h trend
    since_24h = datetime.utcnow() - timedelta(hours=24)
    new_24h = await db.execute(select(func.count()).where(Detection.created_at >= since_24h))
    # Findings + campaigns counts for dashboard
    from arguswatch.models import Finding, Campaign
    try:
        total_findings = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
        open_findings = (await db.execute(select(func.count(Finding.id)).where(
            Finding.status.in_(["NEW", "ENRICHED", "ALERTED", "ESCALATION"])))).scalar() or 0
        crit_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "CRITICAL"))).scalar() or 0
        high_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "HIGH"))).scalar() or 0
        medium_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "MEDIUM"))).scalar() or 0
        low_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "LOW"))).scalar() or 0
        active_campaigns = (await db.execute(select(func.count(Campaign.id)).where(Campaign.status == "active"))).scalar() or 0
    except Exception:
        total_findings = open_findings = crit_findings = high_findings = medium_findings = low_findings = active_campaigns = 0
    _cust = cust_count.scalar() or 0
    _actors = actor_count.scalar() or 0
    # Formula-relevant: assets (D4/D5) and exposure score (formula output)
    asset_count = await db.execute(select(func.count(CustomerAsset.id)))
    _assets = asset_count.scalar() or 0
    max_exp_r = await db.execute(select(func.max(CustomerExposure.exposure_score)))
    _max_exp = round(max_exp_r.scalar() or 0, 1)
    # Noise elimination metric  -  what % of IOCs were filtered as irrelevant
    total_det = total.scalar() or 0
    try:
        matched_r = await db.execute(select(func.count(Detection.id)).where(Detection.customer_id.isnot(None)))
        matched = matched_r.scalar() or 0
        unmatched = total_det - matched
        noise_pct = round((unmatched / total_det * 100), 1) if total_det > 0 else 0.0
    except Exception:
        matched = 0; unmatched = 0; noise_pct = 0.0
    
    return {
        "total_detections": total_det,
        "severity": sev_counts,
        "status": status_counts,
        "customers": _cust, "total_customers": _cust,
        "threat_actors": _actors, "total_actors": _actors,
        "total_assets": _assets,
        "darkweb_mentions": darkweb_count.scalar() or 0,
        "max_exposure_score": _max_exp,
        "total_findings": total_findings, "open_findings": open_findings,
        "critical_findings": crit_findings, "high_findings": high_findings,
        "medium_findings": medium_findings, "low_findings": low_findings,
        "active_campaigns": active_campaigns,
        "new_24h": new_24h.scalar() or 0,
        "noise_elimination": {
            "total_iocs": total_det,
            "customer_attributed": matched,
            "unmatched_noise": unmatched,
            "noise_pct": noise_pct,
            "signal_pct": round(100 - noise_pct, 1),
        },
    }

# ── Source breakdown ──
@app.get("/api/stats/sources")
async def stats_by_source(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(Detection.source, func.count(Detection.id).label("count"))
        .group_by(Detection.source).order_by(desc("count"))
    )
    sources = [{**row._mapping} for row in r]
    # Enrich with last_run from CollectorRun
    try:
        cr = await db.execute(
            select(CollectorRun.collector_name, func.max(CollectorRun.completed_at).label("last_run"))
            .group_by(CollectorRun.collector_name)
        )
        run_map = {row.collector_name: row.last_run for row in cr}
        for s in sources:
            lr = run_map.get(s["source"])
            s["last_run"] = lr.isoformat() if lr else None
            s["name"] = s["source"]  # alias for frontend
    except Exception:
        for s in sources:
            s["last_run"] = None
            s["name"] = s["source"]
    return sources

# ── IOC type breakdown ──
@app.get("/api/stats/ioc-types")
async def stats_by_ioc_type(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(Detection.ioc_type, func.count(Detection.id).label("count"))
        .group_by(Detection.ioc_type).order_by(desc("count"))
    )
    return [{"ioc_type": row.ioc_type, "type": row.ioc_type, "count": row.count} for row in r]

# ── Timeline (last 7 days by day) ──
@app.get("/api/stats/timeline")
async def detection_timeline(db: AsyncSession = Depends(get_db)):
    days = []
    for i in range(6, -1, -1):
        day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        r = await db.execute(
            select(func.count()).where(and_(Detection.created_at >= day_start, Detection.created_at < day_end))
        )
        days.append({"date": day_start.strftime("%Y-%m-%d"), "count": r.scalar() or 0})
    return days

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

@app.post("/api/collect/{collector}", dependencies=_write_deps)
async def trigger_collector(collector: str):
    """Trigger collection via Intel Proxy Gateway (real internet data)."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            if collector == "all":
                resp = await c.post(f"{proxy_url}/collect/all")
            else:
                resp = await c.post(f"{proxy_url}/collect/{collector}")
            return {"status": "ok", "collector": collector, "result": resp.json()}
    except httpx.ConnectError:
        raise HTTPException(503, f"Intel Proxy Gateway not reachable at {proxy_url}")
    except Exception as e:
        raise HTTPException(500, f"Collection failed: {str(e)[:200]}")

@app.post("/api/collect-all", dependencies=_write_deps)
async def trigger_all_collectors():
    """Trigger ALL collectors via Intel Proxy, then auto-run full pipeline:
    collect → correlate → match all customers → recalculate exposure scores."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    result = {"collection": {}, "correlation": {}, "matching": {}, "scoring": {}}
    
    # Step 1: Collect
    try:
        async with httpx.AsyncClient(timeout=300.0) as c:
            resp = await c.post(f"{proxy_url}/collect/all")
            result["collection"] = resp.json()
    except Exception as e:
        result["collection"] = {"error": str(e)[:200]}
    
    # Step 2: Correlate (assign customer_id to unmatched detections)
    try:
        from arguswatch.engine.correlation_engine import correlate_new_detections
        from arguswatch.database import async_session
        async with async_session() as db:
            cr = await correlate_new_detections(db, limit=5000)
            await db.commit()
            result["correlation"] = cr
    except Exception as e:
        result["correlation"] = {"error": str(e)[:200]}
    
    # Step 3: Match all customers (create findings from correlated detections)
    try:
        from arguswatch.engine.customer_intel_matcher import match_all_customers
        async with async_session() as db:
            mr = await match_all_customers(db)
            await db.commit()
            result["matching"] = mr
    except Exception as e:
        result["matching"] = {"error": str(e)[:200]}
    
    # Step 4: Recalculate exposure scores for all customers
    try:
        from arguswatch.services.exposure_scorer import calculate_all_exposures
        sr = await calculate_all_exposures()
        result["scoring"] = sr
    except Exception as e:
        result["scoring"] = {"error": str(e)[:200]}
    
    return result

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
    """Universal compromise search  -  checks local DB, HudsonRock, HIBP, Sourcegraph, VirusTotal.
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

@app.post("/api/recon/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def trigger_recon(customer_id: int, domain: str = None):
    """Trigger full recon via Recon Engine - subfinder, nmap, whois, DNS, crt.sh, httpx.
    After recon completes, auto-runs customer intel matching + exposure recalculation."""
    import httpx as httpx_client
    recon_url = os.environ.get("RECON_ENGINE_URL", "http://recon-engine:9001")
    try:
        params = {"domain": domain} if domain else {}
        async with httpx_client.AsyncClient(timeout=120.0) as c:
            resp = await c.post(f"{recon_url}/recon/{customer_id}", params=params)
            recon_result = resp.json()

        # After recon discovers assets, run customer intel matching
        if recon_result.get("assets_created", 0) > 0:
            try:
                from arguswatch.engine.customer_intel_matcher import match_customer_intel
                from arguswatch.database import async_session
                async with async_session() as db:
                    match_result = await match_customer_intel(customer_id, db)
                recon_result["intel_matched"] = match_result.get("total_matches", 0)
                recon_result["match_details"] = {
                    "ip": match_result.get("ip_matches", 0),
                    "cidr": match_result.get("cidr_matches", 0),
                    "domain": match_result.get("domain_matches", 0),
                    "tech": match_result.get("tech_matches", 0),
                    "brand": match_result.get("brand_matches", 0),
                    "darkweb": match_result.get("darkweb_matches", 0),
                }
            except Exception as e:
                recon_result["intel_match_error"] = str(e)[:100]

            # Recalculate exposure with real matched data
            try:
                from arguswatch.services.exposure_scorer import calculate_all_exposures
                await calculate_all_exposures()
                recon_result["exposure_recalculated"] = True
            except Exception as e:
                recon_result["exposure_error"] = str(e)[:100]

        return recon_result
    except httpx_client.ConnectError:
        raise HTTPException(503, f"Recon Engine not reachable at {recon_url}")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/match-intel/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def match_intel_endpoint(customer_id: int, db: AsyncSession = Depends(get_db)):
    """Manually trigger customer intel matching - searches ALL global detections
    for matches against this customer's assets."""
    from arguswatch.engine.customer_intel_matcher import match_customer_intel
    return await match_customer_intel(customer_id, db)


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
    """One-call customer onboarding: create → register assets → recon → match → score.
    
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
    
    # ── STEP 1: Create customer ──
    existing = await db.execute(select(Customer).where(Customer.name == name))
    if existing.scalar_one_or_none():
        return {"error": f"Customer '{name}' already exists"}
    
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
    except Exception:
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
    # so CVE→product matching works even before operator confirms.
    # Lower confidence than manual entry  -  tagged as probable.
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
        except Exception:
            pass  # Skip duplicates or enum issues
    
    if tech_added:
        # Mark these as industry defaults, not confirmed
        try:
            await db.execute(text(
                "UPDATE customer_assets SET discovery_source = 'industry_default', "
                "criticality = 'medium' "
                "WHERE customer_id = :cid AND asset_type = 'tech_stack' "
                "AND discovery_source = 'onboarding_auto'"
            ), {"cid": cid})
        except Exception:
            pass
    
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
        except Exception:
            result["recon"]["retry_scheduled"] = False
    
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
        print(f"  ! Onboard intel match error for {name}: {e}")
        result["intel_match"] = {"error": str(e)[:100]}
    
    # ── STEP 4a: Correlate ALL unrouted detections to this customer ──
    try:
        from arguswatch.engine.correlation_engine import correlate_new_detections
        cr = await correlate_new_detections(db, limit=5000)
        await db.commit()
        result["correlation"] = {"routed": cr.get("routed", 0), "unrouted": cr.get("unrouted", 0)}
    except Exception as e:
        print(f"  ! Onboard correlation error for {name}: {e}")
        result["correlation"] = {"error": str(e)[:100]}
    
    # ── STEP 4a2: Promote routed detections → Findings ──
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
        for d in routed_r.scalars().all():
            try:
                f, is_new = await get_or_create_finding(d, db)
                if is_new: promoted += 1
            except Exception:
                pass
        await db.commit()
        result["findings_promoted"] = promoted
    except Exception as e:
        print(f"  ! Onboard finding promotion error for {name}: {e}")
        result["findings_promoted"] = 0
    
    # ── STEP 4b: Generate remediations for new findings ──
    try:
        from arguswatch.engine.action_generator import generate_action
        from sqlalchemy import select as sel2
        new_findings = await db.execute(
            sel2(Finding).where(
                Finding.customer_id == cid,
                Finding.severity.in_(["CRITICAL", "HIGH", "MEDIUM"]),
            )
        )
        remed_count = 0
        for f in new_findings.scalars().all():
            try:
                action = await generate_action(f.id, db)
                if action:
                    remed_count += 1
            except Exception:
                pass
        await db.commit()
        result["remediations_created"] = remed_count
    except Exception as e:
        result["remediations_created"] = 0
        result["remediations_note"] = str(e)[:100]
    
    # ── STEP 4c: Attribute findings to threat actors ──
    try:
        from arguswatch.engine.attribution_engine import run_attribution_pass
        attr_result = await run_attribution_pass(db, limit=500)
        result["attribution"] = {
            "processed": attr_result.get("processed", 0),
            "attributed": attr_result.get("attributed", 0),
        }
    except Exception as e:
        result["attribution"] = {"error": str(e)[:100]}
    
    # ── STEP 4d: Campaign detection for new findings ──
    try:
        from arguswatch.engine.campaign_detector import check_and_create_campaign
        new_f_r = await db.execute(
            select(Finding).where(Finding.customer_id == cid)
        )
        campaigns_created = 0
        for f in new_f_r.scalars().all():
            try:
                camp = await check_and_create_campaign(f, db)
                if camp:
                    campaigns_created += 1
            except Exception:
                pass
        await db.commit()
        result["campaigns_detected"] = campaigns_created
    except Exception as e:
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
    except Exception:
        pass
    
    # ── STEP 6: Set onboarding state ──
    total_matches = result.get("intel_match", {}).get("total_matches", 0)
    if total_matches > 0:
        customer.onboarding_state = "monitoring"
    else:
        customer.onboarding_state = "monitoring"  # Still monitoring, just no findings yet
    customer.onboarding_updated_at = datetime.utcnow()
    await db.commit()
    result["onboarding_state"] = customer.onboarding_state
    
    # ── STEP 7: Coverage gap analysis ──
    gaps = []
    asset_r = await db.execute(
        select(CustomerAsset.asset_type).where(CustomerAsset.customer_id == cid)
    )
    registered_types = {r[0] for r in asset_r.all()}
    
    if "github_org" not in registered_types:
        gaps.append("No github_org registered - Cat 2 API key scanning and Cat 7 code leak scanning disabled")
    if "aws_account" not in registered_types:
        gaps.append("No aws_account registered - Cat 12 S3 bucket attribution disabled")
    if "internal_domain" not in registered_types:
        gaps.append("No internal_domain registered - Cat 7 internal hostname matching disabled")
    if "tech_stack" not in registered_types:
        gaps.append("No tech_stack registered - Cat 16 CVE matching limited to recon-discovered software only")
    if "ip" not in registered_types and result.get("recon", {}).get("ips", 0) == 0:
        gaps.append("No IPs discovered - Cat 3 network IOC matching disabled")
    
    result["coverage_gaps"] = gaps
    result["coverage_pct"] = max(0, 100 - len(gaps) * 15)
    
    # ── STEP 8: Schedule background re-match (catches IOCs that arrive after onboard) ──
    import asyncio
    async def _delayed_rematch():
        await asyncio.sleep(90)  # Wait for collectors to finish current cycle
        try:
            from arguswatch.database import async_session
            from arguswatch.engine.customer_intel_matcher import match_customer_intel
            from arguswatch.services.exposure_scorer import calculate_customer_exposure
            async with async_session() as _db:
                await match_customer_intel(cid, _db)
                # Promote any new detections to findings
                from arguswatch.engine.finding_manager import get_or_create_finding
                from arguswatch.models import Detection
                _dr = await _db.execute(
                    select(Detection).where(Detection.customer_id == cid, Detection.finding_id == None)
                )
                for _d in _dr.scalars().all():
                    try:
                        await get_or_create_finding(_d, _db)
                    except Exception:
                        pass
                await calculate_customer_exposure(cid, _db)
                await _db.commit()
            print(f"  + Background re-match for {name}: complete")
        except Exception as e:
            print(f"  ! Background re-match for {name}: {e}")
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
        "cve_tech_stack": "S4: CVE→tech stack correlation",
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

        # Link finding → matching asset
        if f.matched_asset:
            for a in assets:
                if a.asset_value and f.matched_asset and a.asset_value.lower() in f.matched_asset.lower():
                    links.append({"source": f"asset_{a.id}", "target": nid, "type": "matched"})
                    break
            else:
                links.append({"source": cust_nid, "target": nid, "type": "detected"})
        else:
            links.append({"source": cust_nid, "target": nid, "type": "detected"})

        # Link finding → actor
        if f.actor_id:
            anid = f"actor_{f.actor_id}"
            if anid not in node_ids:
                nodes.append({"id": anid, "type": "actor",
                              "label": f.actor_name or f"Actor #{f.actor_id}",
                              "size": 14, "severity": "none", "meta": {}})
                node_ids.add(anid)
            links.append({"source": nid, "target": anid, "type": "attributed"})

        # Link finding → campaign
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
            # Link campaign → actor
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


@app.post("/api/match-intel-all", dependencies=[Depends(require_role("admin", "analyst"))])
async def match_all_intel_endpoint(db: AsyncSession = Depends(get_db)):
    """Match ALL global detections against ALL customers' assets."""
    from arguswatch.engine.customer_intel_matcher import match_all_customers
    return await match_all_customers(db)


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


@app.get("/api/threat-pressure")
async def get_threat_pressure(db: AsyncSession = Depends(get_db)):
    """Compute global threat pressure index for dashboard gauge.
    Combines finding severity, active campaigns, and 24h velocity."""
    from arguswatch.models import Finding, Campaign
    try:
        crit = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "CRITICAL"))).scalar() or 0
        high = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "HIGH"))).scalar() or 0
        total_f = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
        active_camps = (await db.execute(select(func.count(Campaign.id)).where(Campaign.status == "active"))).scalar() or 0
        since_24h = datetime.utcnow() - timedelta(hours=24)
        new_24h = (await db.execute(select(func.count(Detection.id)).where(Detection.created_at >= since_24h))).scalar() or 0
        # Pressure formula: weighted severity + campaigns + velocity
        pressure = min(100, int(crit * 12 + high * 5 + active_camps * 8 + min(new_24h, 100) * 0.3))
        if pressure < 20:
            level_text = "LOW"
        elif pressure < 40:
            level_text = "MODERATE"
        elif pressure < 70:
            level_text = "ELEVATED"
        else:
            level_text = "CRITICAL"
        return {
            "pressure_index": pressure,
            "level": pressure,
            "level_text": level_text,
            "summary": f"{crit + high} active threats across monitored landscape",
            "active_threats": crit + high,
            "active_campaigns": active_camps,
            "new_last_24h": new_24h,
            "critical_findings": crit,
            "high_findings": high,
            "total_findings": total_f,
        }
    except Exception:
        return {"pressure_index": 0, "level": 0, "level_text": "UNKNOWN",
                "summary": "Unable to compute", "active_threats": 0,
                "active_campaigns": 0, "new_last_24h": 0}


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

@app.post("/api/ingest/events", dependencies=[Depends(require_role("admin", "analyst"))])
async def ingest_events(req: EventIngestRequest, db: AsyncSession = Depends(get_db)):
    """Lightweight webhook for structured security events.

    Push from any EDR/SIEM/SOAR that can POST JSON. No vendor lock-in.
    Each event becomes a Detection with full customer attribution.

    Example - CrowdStrike exfiltration alert:
        POST /api/ingest/events
        {"events": [{
            "customer_id": 5,
            "source": "crowdstrike",
            "event_type": "data_exfiltration",
            "hostname": "WORKSTATION-01",
            "process": "7za.exe",
            "bytes_transferred": 2400000000,
            "destination_ip": "185.220.101.47",
            "raw": "Process 7za.exe transferred 2.4GB to external IP"
        }]}
    """
    results = []
    for ev in req.events:
        # Map event_type to IOC type
        ioc_type_map = {
            "data_exfiltration": "data_exfiltration_evidence",
            "lateral_movement": "lateral_movement_indicator",
            "privilege_escalation": "privilege_escalation_indicator",
            "malware_execution": "malware_execution_indicator",
            "credential_theft": "credential_theft_indicator",
            "c2_communication": "c2_communication_indicator",
        }
        ioc_type = ioc_type_map.get(ev.event_type, ev.event_type)

        # Build IOC value from best available identifier
        ioc_value = ev.destination_ip or ev.process or ev.hostname or ev.event_type
        ioc_value = f"{ev.source}:{ioc_value}"[:500]

        # Build raw text
        raw_parts = [f"[{ev.source.upper()}] {ev.event_type}"]
        if ev.hostname:
            raw_parts.append(f"host={ev.hostname}")
        if ev.process:
            raw_parts.append(f"process={ev.process}")
        if ev.destination_ip:
            raw_parts.append(f"dest_ip={ev.destination_ip}")
        if ev.bytes_transferred:
            size_gb = ev.bytes_transferred / (1024**3)
            raw_parts.append(f"transferred={size_gb:.2f}GB" if size_gb >= 1 else f"transferred={ev.bytes_transferred / (1024**2):.0f}MB")
        if ev.raw:
            raw_parts.append(ev.raw[:500])
        raw_text = " | ".join(raw_parts)

        sev_sla = {"CRITICAL": 4, "HIGH": 24, "MEDIUM": 72, "LOW": 168}
        sla = sev_sla.get(ev.severity, 24)

        # Dedup key
        dedup = hashlib.sha256(f"{ev.customer_id}:{ev.source}:{ioc_value}:{ev.hostname}".encode()).hexdigest()[:16]

        # Check for existing detection with same dedup
        existing = await db.execute(
            text("SELECT id FROM detections WHERE ioc_value = :iv AND customer_id = :cid LIMIT 1"),
            {"iv": f"event:{dedup}", "cid": ev.customer_id}
        )
        if existing.scalar_one_or_none():
            results.append({"event_type": ev.event_type, "status": "duplicate", "ioc_value": f"event:{dedup}"})
            continue

        # Insert detection
        await db.execute(text("""
            INSERT INTO detections (source, ioc_type, ioc_value, severity, sla_hours,
                                    raw_text, confidence, customer_id, metadata, created_at)
            VALUES (:src, :iot, :iov, :sev, :sla, :raw, :conf, :cid, :meta, NOW())
        """), {
            "src": ev.source, "iot": ioc_type, "iov": f"event:{dedup}",
            "sev": ev.severity, "sla": sla, "raw": raw_text,
            "conf": 0.90,  # High confidence - came from customer's own EDR
            "cid": ev.customer_id,
            "meta": json.dumps({**ev.metadata, "hostname": ev.hostname, "process": ev.process,
                                "destination_ip": ev.destination_ip, "bytes_transferred": ev.bytes_transferred,
                                "original_event_type": ev.event_type}),
        })
        results.append({"event_type": ev.event_type, "status": "created", "ioc_value": f"event:{dedup}",
                         "severity": ev.severity, "customer_id": ev.customer_id})

    await db.commit()
    created = sum(1 for r in results if r["status"] == "created")
    return {"ingested": created, "duplicates": len(results) - created, "total": len(results), "details": results}


# ════════════════════════════════════════════════════════════
# METRICS - monitoring and observability
# ════════════════════════════════════════════════════════════

@app.get("/api/metrics")
async def get_metrics(db: AsyncSession = Depends(get_db)):
    """Platform health metrics for monitoring dashboards."""
    metrics = {}
    
    # Match rate per customer
    r = await db.execute(text("""
        SELECT c.name, c.id,
            COUNT(CASE WHEN d.customer_id IS NOT NULL THEN 1 END) as matched,
            COUNT(*) as total
        FROM customers c
        LEFT JOIN detections d ON d.customer_id = c.id
        WHERE c.active = true
        GROUP BY c.id, c.name
    """))
    metrics["match_rates"] = [{
        "customer": row[0], "customer_id": row[1],
        "matched": row[2], "total": row[3],
        "rate": round(row[2] / max(row[3], 1) * 100, 1),
    } for row in r.all()]
    
    # Collector health
    r = await db.execute(text("""
        SELECT collector_name,
            MAX(completed_at) as last_run,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as successes,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failures,
            COUNT(*) as total_runs
        FROM collector_runs
        GROUP BY collector_name
        ORDER BY last_run DESC NULLS LAST
    """))
    metrics["collector_health"] = [{
        "collector": row[0],
        "last_run": row[1].isoformat() if row[1] else None,
        "successes": row[2], "failures": row[3], "total": row[4],
        "stale": (datetime.utcnow() - row[1]).total_seconds() > 28800 if row[1] else True,
    } for row in r.all()]
    
    # Detection counts by source
    r = await db.execute(text("""
        SELECT source, COUNT(*) as count,
            COUNT(CASE WHEN customer_id IS NOT NULL THEN 1 END) as matched
        FROM detections
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY source
        ORDER BY count DESC
    """))
    metrics["detections_by_source"] = [{
        "source": row[0], "count": row[1], "matched": row[2],
        "match_rate": round(row[2] / max(row[1], 1) * 100, 1),
    } for row in r.all()]
    
    # Threat pressure by sector
    from arguswatch.models import GlobalThreatActivity
    gta_r = await db.execute(
        select(GlobalThreatActivity)
        .where(GlobalThreatActivity.activity_level > 0)
        .order_by(GlobalThreatActivity.activity_level.desc())
    )
    metrics["threat_pressure"] = [{
        "category": a.category,
        "malware_family": a.malware_family,
        "activity_level": round(a.activity_level, 1),
        "sectors": a.targeted_sectors,
    } for a in gta_r.scalars().all()]
    
    # Finding counts
    r = await db.execute(text("""
        SELECT severity, COUNT(*) FROM findings
        WHERE status IN ('NEW', 'ENRICHED', 'ALERTED')
        GROUP BY severity
    """))
    metrics["open_findings"] = {row[0]: row[1] for row in r.all()}
    
    # Single-source domination check
    r = await db.execute(text("""
        SELECT source, COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM detections WHERE created_at > NOW() - INTERVAL '24 hours'), 0)
        FROM detections
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY source
        ORDER BY 2 DESC
        LIMIT 5
    """))
    metrics["source_concentration"] = [{
        "source": row[0],
        "percentage": round(float(row[1] or 0), 1),
        "warning": float(row[1] or 0) > 30,
    } for row in r.all()]
    
    return metrics

@app.get("/api/collectors/status")
async def collectors_status(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(CollectorRun.collector_name,
               func.max(CollectorRun.completed_at).label("last_run"),
               func.count(CollectorRun.id).label("total_runs"))
        .group_by(CollectorRun.collector_name)
    )
    rows = r.all()
    # Count detections per source for real IOC count
    det_r = await db.execute(
        select(Detection.source, func.count(Detection.id).label("det_count"))
        .group_by(Detection.source)
    )
    det_counts = {row.source: row.det_count for row in det_r.all()}
    
    return {row.collector_name: {
        "name": row.collector_name,
        "last_run": row.last_run.isoformat() if row.last_run else None,
        "total_runs": row.total_runs,
        "ioc_count": det_counts.get(row.collector_name, 0),
        "status": "active" if row.last_run and (datetime.utcnow() - row.last_run).total_seconds() < 86400 else "stale",
    } for row in rows}

# ── IOC Scanner ──
class ScanRequest(BaseModel):
    text: str

@app.post("/api/scan", dependencies=[Depends(require_role("admin", "analyst"))])
async def scan_text_endpoint(req: ScanRequest):
    from arguswatch.engine import scan_text, score
    matches = scan_text(req.text)
    results = []
    for m in matches[:50]:
        s = score(m.category, m.ioc_type, confidence=m.confidence)
        results.append({
            "category": m.category, "ioc_type": m.ioc_type, "value": m.value,
            "context": m.context, "confidence": m.confidence,
            "severity": s.severity, "sla_hours": s.sla_hours,
            "line": m.line_number,
        })
    return {"count": len(results), "results": results}

# ── Seed ──
## Seed endpoints removed  -  platform starts clean. Onboard customers via dashboard.

# ── AI Query ──
class AIQuery(BaseModel):
    question: Optional[str] = None
    query: Optional[str] = None
    provider: str = "auto"
    customer_id: Optional[int] = None  # Optional: scope to specific customer
    conversation_history: list = []  # Multi-turn conversation

    @property
    def text(self):
        return self.question or self.query or ""

@app.post("/api/ai/query", dependencies=[Depends(require_role("admin", "analyst"))])
async def ai_query(req: AIQuery, db: AsyncSession = Depends(get_db)):
    """AI query with FULL platform context - customer-specific when customer_id provided."""
    if not req.text:
        raise HTTPException(422, "Either 'question' or 'query' field required")
    
    # ── Build rich context ──
    stats = {}
    try:
        r = await db.execute(select(func.count(Detection.id)))
        stats["total_detections"] = r.scalar() or 0
        r = await db.execute(select(func.count(Detection.id)).where(Detection.severity == SeverityLevel.CRITICAL))
        stats["critical"] = r.scalar() or 0
        r = await db.execute(select(func.count()).where(Detection.status == "NEW"))
        stats["new_open"] = r.scalar() or 0
        r = await db.execute(select(func.count(Customer.id)).where(Customer.active == True))
        stats["active_customers"] = r.scalar() or 0
    except Exception: pass

    # Customer-specific context
    customer_context = ""
    if req.customer_id:
        try:
            cr = await db.execute(select(Customer).where(Customer.id == req.customer_id))
            cust = cr.scalar_one_or_none()
            if cust:
                # Detection summary - full values + raw_text for AI analysis
                det_r = await db.execute(
                    select(Detection.ioc_type, Detection.severity, Detection.source,
                           Detection.ioc_value, Detection.raw_text, Detection.created_at)
                    .where(Detection.customer_id == req.customer_id)
                    .order_by(Detection.created_at.desc()).limit(20)
                )
                recent_dets = [{"type": r[0], "severity": r[1].value if hasattr(r[1], 'value') else str(r[1]),
                                "source": r[2], "value": r[3],
                                "raw_text": (r[4] or "")[:300],
                                "detected": r[5].isoformat() if r[5] else None} for r in det_r.all()]
                
                # Exposure score - use ExposureHistory (has overall_score + d1-d5)
                from arguswatch.models import ExposureHistory
                exp_r = await db.execute(
                    select(ExposureHistory).where(ExposureHistory.customer_id == req.customer_id)
                    .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
                )
                exp = exp_r.scalar_one_or_none()
                exp_data = {}
                if exp:
                    exp_data = {"score": exp.overall_score, "d1": exp.d1_score,
                                "d2": exp.d2_score, "d3": exp.d3_score,
                                "d4": exp.d4_score, "d5": exp.d5_score}
                
                # Asset count
                ar = await db.execute(
                    select(CustomerAsset.asset_type, func.count(CustomerAsset.id))
                    .where(CustomerAsset.customer_id == req.customer_id)
                    .group_by(CustomerAsset.asset_type)
                )
                asset_summary = dict(ar.all())
                
                customer_context = f"""
CUSTOMER CONTEXT for {cust.name}:
  Industry: {cust.industry or 'unknown'}
  Tier: {cust.tier}
  Onboarding state: {cust.onboarding_state}
  Assets registered: {dict(asset_summary)}
  Exposure score: {exp_data}
  Recent detections (last 20): {recent_dets}
"""
                # Load coverage gaps for recommendation capability
                try:
                    from arguswatch.models import CustomerAsset as CA2
                    ca_r = await db.execute(select(CA2.asset_type).where(CA2.customer_id == req.customer_id))
                    reg_types = {r[0] for r in ca_r.all()}
                    gaps = []
                    if "github_org" not in reg_types:
                        gaps.append("Register github_org to enable API key and code leak scanning (Cat 2, 7, 11)")
                    if "aws_account" not in reg_types:
                        gaps.append("Register aws_account to enable S3 bucket attribution (Cat 12)")
                    if "tech_stack" not in reg_types:
                        gaps.append("Register tech_stack to enable CVE matching (Cat 16)")
                    if "ip" not in reg_types:
                        gaps.append("Register IPs to enable network IOC matching (Cat 3)")
                    if "internal_domain" not in reg_types:
                        gaps.append("Register internal_domain to enable internal hostname matching (Cat 7)")
                    if gaps:
                        customer_context += f"  Coverage gaps (RECOMMEND these to the operator): {gaps}\n"
                except Exception:
                    pass
        except Exception as e:
            customer_context = f"\n(Customer context error: {e})\n"
    
    # Check for natural language onboarding commands
    q_lower = req.text.lower()
    if any(phrase in q_lower for phrase in ["add customer", "onboard", "start monitoring", "register customer"]):
        # Try to parse: "add customer Acme Corp domain acme.com industry financial"
        import re as _re
        # Extract domain (anything.tld pattern)
        domain_m = _re.search(r'(?:domain\s+)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,})', q_lower)
        # Extract industry
        ind_m = _re.search(r'industry\s+(\w+)', q_lower)
        # Extract name - text after "customer" or "onboard" keyword, before "domain"/"industry"
        name_m = _re.search(r'(?:add customer|onboard|register customer|start monitoring)\s+(.+?)(?:\s+(?:domain|industry|$))', q_lower)
        
        parsed_domain = domain_m.group(1) if domain_m else None
        parsed_industry = ind_m.group(1) if ind_m else None
        parsed_name = name_m.group(1).strip().title() if name_m else None
        
        if parsed_domain and parsed_name:
            # Actually onboard the customer
            try:
                existing = await db.execute(select(Customer).where(Customer.name == parsed_name))
                if existing.scalar_one_or_none():
                    return {"answer": f"Customer '{parsed_name}' already exists. Use the customer selector to view their profile.",
                            "model": "system", "provider": "builtin"}
                
                if not parsed_industry:
                    return {"answer": f"I can create '{parsed_name}' with domain {parsed_domain}, but I need an industry. "
                                      f"Try: 'add customer {parsed_name} domain {parsed_domain} industry financial' "
                                      f"(options: {', '.join(sorted(VALID_INDUSTRIES))})",
                            "model": "system", "provider": "builtin"}
                
                if parsed_industry not in VALID_INDUSTRIES:
                    return {"answer": f"Industry '{parsed_industry}' isn't recognized. Valid options: {', '.join(sorted(VALID_INDUSTRIES))}",
                            "model": "system", "provider": "builtin"}
                
                # Create customer + assets
                customer = Customer(name=parsed_name, industry=parsed_industry, tier="standard",
                                    onboarding_state="assets_added")
                db.add(customer)
                await db.flush()
                await db.refresh(customer)
                cid = customer.id
                
                for atype, aval in [("domain", parsed_domain), ("email_domain", parsed_domain),
                                     ("brand_name", parsed_name)]:
                    db.add(CustomerAsset(customer_id=cid, asset_type=atype, asset_value=aval,
                                         criticality="high", discovery_source="ai_onboarding"))
                
                brand_short = parsed_name.split()[0]
                if len(brand_short) >= 4 and brand_short.lower() != "the":
                    db.add(CustomerAsset(customer_id=cid, asset_type="keyword",
                                         asset_value=brand_short.lower(), criticality="high",
                                         discovery_source="ai_onboarding"))
                
                # Run matching + exposure
                match_info = ""
                try:
                    from arguswatch.engine.customer_intel_matcher import match_customer_intel
                    mr = await match_customer_intel(cid, db)
                    total = mr.get("total_matches", 0)
                    match_info = f" Found {total} threat intel matches." if total > 0 else " No matching threats found yet in current intel feeds."
                except Exception:
                    pass
                
                exp_info = ""
                try:
                    from arguswatch.services.exposure_scorer import calculate_customer_exposure
                    exp = await calculate_customer_exposure(cid, db)
                    score = exp.get("overall_score", exp.get("score", 0))
                    exp_info = f" Initial exposure score: {round(score)}/100."
                    # Seed exposure history for day-1 trend
                    from arguswatch.models import ExposureHistory
                    db.add(ExposureHistory(customer_id=cid, snapshot_date=datetime.utcnow(),
                                           overall_score=score,
                                           d1_score=exp.get("d1", 0), d2_score=exp.get("d2", 0),
                                           d3_score=exp.get("d3", 0), d4_score=exp.get("d4", 0),
                                           d5_score=exp.get("d5", 0)))
                except Exception:
                    pass
                
                customer.onboarding_state = "monitoring"
                customer.onboarding_updated_at = datetime.utcnow()
                await db.commit()
                
                return {
                    "answer": f"✅ Customer '{parsed_name}' created and onboarded!\n\n"
                              f"• Domain: {parsed_domain}\n"
                              f"• Industry: {parsed_industry}\n"
                              f"• Assets auto-registered: domain, email_domain, brand_name, keyword\n"
                              f"• State: monitoring\n"
                              f"{match_info}{exp_info}\n\n"
                              f"Next steps: Register github_org, IPs, and tech_stack to expand coverage. "
                              f"Select '{parsed_name}' from the customer dropdown to see the full dashboard.",
                    "model": "system", "provider": "builtin",
                    "customer_created": cid,
                }
            except Exception as e:
                return {"answer": f"Onboarding failed: {str(e)[:200]}. Use the '+ Add Customer' button instead.",
                        "model": "system", "provider": "builtin"}
        else:
            missing = []
            if not parsed_name: missing.append("customer name")
            if not parsed_domain: missing.append("domain")
            return {
                "answer": f"I need {' and '.join(missing)} to onboard. Try:\n\n"
                          f"'add customer Acme Corp domain acme.com industry financial'\n\n"
                          f"Or use the '+ Add Customer' button in the Customers tab.",
                "model": "system", "provider": "builtin",
            }

    context = f"""You are ArgusWatch AI, a cybersecurity threat intelligence analyst for an MSSP platform.
Platform stats: {stats}
{customer_context}
You have access to customer detections, exposure scores (D1-D5), assets, and attribution strategies (S1-S8).

INSTRUCTIONS:
- Answer concisely and professionally. Reference specific detections and scores when available.
- If asked about a customer and no customer_id was provided, ask which customer they mean.
- When coverage gaps exist, PROACTIVELY RECOMMEND which assets to register and explain why (e.g. "Register your GitHub org to enable API key scanning - this would activate 22 additional IOC types").
- When asked for a threat summary, provide: top risks by severity, exposure score interpretation, most concerning detection types, active threat actor targeting for this sector, and specific remediation priorities.
- If the customer has no detections yet, explain what the system is monitoring and when they can expect results."""

    prompt = req.text
    
    # Build conversation history for multi-turn
    conv_msgs = []
    for msg in (req.conversation_history or [])[-10:]:  # Last 10 turns
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role in ("user", "assistant") and content:
            conv_msgs.append({"role": role, "content": content[:500]})

    # Auto-detect provider: Ollama+Qwen is the DEFAULT (always-on, local)
    # Other providers (Claude, OpenAI, Gemini) are used ONLY when explicitly selected
    provider = req.provider
    if provider == "auto":
        provider = "ollama"  # Ollama+Qwen is always the default

    if provider == "ollama":
        try:
            import httpx
            history_text = "\n".join(f"{m['role'].title()}: {m['content']}" for m in conv_msgs)
            full_prompt = f"{context}\n\n{history_text}\nUser: {prompt}\nAssistant:" if history_text else f"{context}\n\nUser: {prompt}\nAssistant:"
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f"{settings.OLLAMA_URL}/api/generate",
                    json={"model": settings.OLLAMA_MODEL, "prompt": full_prompt, "stream": False})
                data = resp.json()
                return {"answer": data.get("response", "No response"), "model": settings.OLLAMA_MODEL, "provider": "ollama"}
        except Exception as e:
            return {"answer": f"Ollama+Qwen is starting up (may take 5-15 min on first boot to download model). Check: docker logs arguswatch-ollama. Error: {str(e)[:100]}", "model": "offline", "provider": "ollama"}

    elif provider == "anthropic" and settings.ANTHROPIC_API_KEY:
        try:
            import httpx
            messages = conv_msgs + [{"role": "user", "content": prompt}]
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 1024,
                          "system": context, "messages": messages})
                data = resp.json()
                return {"answer": data["content"][0]["text"], "model": settings.ANTHROPIC_MODEL, "provider": "anthropic"}
        except Exception as e:
            return {"answer": f"Claude API error: {e}", "model": "error"}

    elif provider == "openai" and settings.OPENAI_API_KEY:
        try:
            import httpx
            messages = [{"role": "system", "content": context}] + conv_msgs + [{"role": "user", "content": prompt}]
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post("https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={"model": settings.OPENAI_MODEL, "max_tokens": 1024, "messages": messages})
                data = resp.json()
                return {"answer": data["choices"][0]["message"]["content"], "model": settings.OPENAI_MODEL, "provider": "openai"}
        except Exception as e:
            return {"answer": f"OpenAI error: {e}", "model": "error"}

    elif provider == "google" and getattr(settings, "GOOGLE_AI_API_KEY", ""):
        try:
            import httpx
            model = getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro")
            # Gemini uses a different message format than OpenAI/Anthropic
            gemini_contents = []
            # System instruction goes in systemInstruction field
            for msg in conv_msgs:
                role = "user" if msg["role"] == "user" else "model"
                gemini_contents.append({"role": role, "parts": [{"text": msg["content"]}]})
            gemini_contents.append({"role": "user", "parts": [{"text": prompt}]})
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                    f"?key={settings.GOOGLE_AI_API_KEY}",
                    json={
                        "systemInstruction": {"parts": [{"text": context}]},
                        "contents": gemini_contents,
                        "generationConfig": {"maxOutputTokens": 1024},
                    })
                data = resp.json()
                candidates = data.get("candidates", [{}])
                parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
                text = " ".join(p.get("text", "") for p in parts)
                if not text:
                    error = data.get("error", {}).get("message", "Empty response")
                    return {"answer": f"Gemini returned no content: {error}", "model": model, "provider": "google"}
                return {"answer": text, "model": model, "provider": "google"}
        except Exception as e:
            return {"answer": f"Gemini API error: {e}", "model": "error"}

    return {"answer": f"No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_AI_API_KEY, or start Ollama locally.", "model": "none"}

# ── V12 routers ──
from arguswatch.api.enrichments import playbook_router, export_router
app.include_router(playbook_router)
app.include_router(export_router)

# ── Enterprise activation status ──
@app.get("/api/enterprise/status")
async def enterprise_status():
    """Check which paid collectors have API keys configured.
    Proxies to intel-proxy /collectors/status for real env var checks."""
    import httpx
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            resp = await c.get(f"{proxy_url}/collectors/status")
            if resp.status_code == 200:
                data = resp.json()
                collectors = data.get("collectors", [])
                # Convert to format frontend expects: {id: {active: bool, ...}}
                result = {}
                for col in collectors:
                    result[col["id"]] = {
                        "name": col.get("name", col["id"]),
                        "active": col.get("active", False),
                        "key_configured": col.get("key_configured", False),
                        "key_hint": col.get("key_hint", ""),
                        "needs_key": col.get("needs_key", False),
                        "tier": col.get("tier", "free"),
                        "last_run": col.get("last_run"),
                        "last_status": col.get("last_status"),
                    }
                return result
    except Exception:
        pass
    # Fallback: check local env vars for ALL key-requiring collectors
    def _ent_entry(env_var, name):
        val = os.environ.get(env_var, "")
        configured = bool(val)
        hint = f"{val[:4]}...{val[-4:]}" if len(val) > 8 else ("set" if val else "")
        return {"active": configured, "key_configured": configured, "key_hint": hint, "name": name}
    return {
        "otx":             _ent_entry("OTX_API_KEY", "AlienVault OTX"),
        "urlscan":         _ent_entry("URLSCAN_API_KEY", "URLScan.io"),
        "hibp":            _ent_entry("HIBP_API_KEY", "HIBP + BreachDir"),
        "github":          _ent_entry("GITHUB_TOKEN", "GitHub Secrets"),
        "shodan":          _ent_entry("SHODAN_API_KEY", "Shodan"),
        "virustotal":      _ent_entry("VIRUSTOTAL_API_KEY", "VirusTotal"),
        "intelx":          _ent_entry("INTELX_API_KEY", "IntelX"),
        "censys":          _ent_entry("CENSYS_API_ID", "Censys"),
        "greynoise":       _ent_entry("GREYNOISE_API_KEY", "GreyNoise"),
        "binaryedge":      _ent_entry("BINARYEDGE_API_KEY", "BinaryEdge"),
        "leakcheck":       _ent_entry("LEAKCHECK_API_KEY", "LeakCheck"),
        "mandiant":        _ent_entry("MANDIANT_API_KEY", "Mandiant"),
        "grayhatwarfare":  _ent_entry("GRAYHATWARFARE_API_KEY", "GrayHatWarfare"),
        "leakix":          _ent_entry("LEAKIX_API_KEY", "LeakIX"),
        "socradar":        _ent_entry("SOCRADAR_API_KEY", "SocRadar"),
        "spycloud":        _ent_entry("SPYCLOUD_API_KEY", "SpyCloud"),
        "recordedfuture":  _ent_entry("RECORDED_FUTURE_KEY", "Recorded Future"),
        "crowdstrike":     _ent_entry("CROWDSTRIKE_CLIENT_ID", "CrowdStrike"),
        "cyberint":        _ent_entry("CYBERINT_API_KEY", "CyberInt"),
        "flare":           _ent_entry("FLARE_API_KEY", "Flare"),
    }

@app.get("/api/debug/env-check")
async def debug_env_check():
    """Debug: shows which API key env vars are set (not empty) in the backend container.
    If this shows 0 keys but your .env has keys, docker needs: docker compose down && docker compose up --build -d"""
    key_vars = [
        "OTX_API_KEY", "URLSCAN_API_KEY", "HIBP_API_KEY", "GITHUB_TOKEN",
        "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "INTELX_API_KEY", "CENSYS_API_ID",
        "GREYNOISE_API_KEY", "BINARYEDGE_API_KEY", "LEAKCHECK_API_KEY", "MANDIANT_API_KEY",
        "GRAYHATWARFARE_API_KEY", "LEAKIX_API_KEY", "SOCRADAR_API_KEY", "SPYCLOUD_API_KEY",
        "RECORDED_FUTURE_KEY", "CROWDSTRIKE_CLIENT_ID", "CYBERINT_API_KEY", "FLARE_API_KEY",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_AI_API_KEY",
    ]
    results = {}
    for k in key_vars:
        val = os.environ.get(k, "")
        results[k] = {
            "set": bool(val),
            "length": len(val),
            "hint": f"{val[:4]}...{val[-4:]}" if len(val) > 8 else ("(short)" if val else "(empty)"),
        }
    set_count = sum(1 for v in results.values() if v["set"])
    return {
        "container": "backend",
        "keys_set": set_count,
        "keys_total": len(key_vars),
        "fix_if_zero": "docker compose down && docker compose up --build -d",
        "keys": results,
    }

@app.post("/api/enterprise/{source_id}/trigger", dependencies=[Depends(require_role("admin"))])
async def trigger_enterprise(source_id: str):
    import importlib
    ent_map = {
        "spycloud": "arguswatch.collectors.enterprise.spycloud",
        "cybersixgill": "arguswatch.collectors.enterprise.cybersixgill",
    }
    if source_id not in ent_map:
        return {"status": "stub", "message": f"{source_id}: architecture wired, enterprise license required"}
    mod = importlib.import_module(ent_map[source_id])
    result = await mod.run_collection()
    return {"source": source_id, "result": result}

# ── Escalation tiers ──
@app.get("/api/escalation/overdue")
async def get_overdue(db: AsyncSession = Depends(get_db)):
    """Level 1 escalation: remediations past SLA."""
    from arguswatch.models import RemediationAction
    from datetime import datetime
    r = await db.execute(
        select(RemediationAction).where(RemediationAction.status == "pending")
    )
    overdue = []
    now = datetime.utcnow()
    for action in r.scalars().all():
        if action.created_at:
            from arguswatch.engine.severity_scorer import score as score_ioc
            # Get detection to know SLA
            try:
                det_r = await db.execute(select(Detection).where(Detection.id == action.detection_id))
                det = det_r.scalar_one_or_none()
                sla_hours = det.sla_hours if det else 72
                elapsed_h = (now - action.created_at).total_seconds() / 3600
                if elapsed_h > sla_hours:
                    overdue.append({
                        "action_id": action.id, "detection_id": action.detection_id,
                        "elapsed_hours": round(elapsed_h, 1), "sla_hours": sla_hours,
                        "assigned_to": action.assigned_to, "action_type": action.action_type,
                    })
            except Exception: continue
    return {"overdue_count": len(overdue), "items": overdue[:50]}


# ══════════════════════════════════════════════════════
# FINDINGS - V12 analyst-facing endpoints
# ══════════════════════════════════════════════════════

@app.get("/api/findings")
async def list_findings(
    severity: str = None,
    status: str = None,
    customer_id: int = None,
    actor_id: int = None,
    campaign_id: int = None,
    has_action: bool = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List findings with full filter support. Primary analyst view."""
    from arguswatch.models import Finding, FindingRemediation
    q = select(Finding)
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if status:
        q = q.where(Finding.status == status.upper())
    if customer_id:
        q = q.where(Finding.customer_id == customer_id)
    if actor_id:
        q = q.where(Finding.actor_id == actor_id)
    if campaign_id:
        q = q.where(Finding.campaign_id == campaign_id)
    if has_action is True:
        q = q.where(exists().where(FindingRemediation.finding_id == Finding.id))
    q = q.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    r = await db.execute(q)
    findings = r.scalars().all()
    
    # Batch-load customer names to avoid N+1
    cust_ids = list({f.customer_id for f in findings if f.customer_id})
    cust_names = {}
    if cust_ids:
        cr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(cust_ids)))
        cust_names = {row.id: row.name for row in cr.all()}
    
    result = []
    for f in findings:
        result.append({
            "id": f.id, "ioc_type": f.ioc_type, "ioc_value": f.ioc_value,
            "severity": _sev(f.severity) or None,
            "status": f.status.value if f.status else None,
            "customer_id": f.customer_id,
            "customer_name": cust_names.get(f.customer_id, ""),
            "actor_name": f.actor_name,
            "campaign_id": f.campaign_id, "source_count": f.source_count,
            "source": f.all_sources[0] if f.all_sources else None,
            "all_sources": f.all_sources, "confidence": f.confidence,
            "correlation_type": f.correlation_type,
            "match_strategy": f.correlation_type,
            "matched_asset": f.matched_asset,
            "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "ai_narrative": getattr(f, "ai_narrative", None),
            "ai_severity_decision": getattr(f, "ai_severity_decision", None),
            "ai_false_positive_flag": getattr(f, "ai_false_positive_flag", False),
        })
    return result


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    """Full finding detail including sources, remediations, attribution."""
    from arguswatch.models import Finding, FindingSource, FindingRemediation, ThreatActor, Campaign
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    # Sources
    rs = await db.execute(select(FindingSource).where(FindingSource.finding_id == finding_id))
    sources = [{"source": s.source, "detection_id": s.detection_id,
                "contributed_at": s.contributed_at.isoformat() if s.contributed_at else None}
               for s in rs.scalars().all()]
    # Remediations
    rr = await db.execute(select(FindingRemediation).where(FindingRemediation.finding_id == finding_id))
    remediations = []
    for rem in rr.scalars().all():
        remediations.append({
            "id": rem.id, "playbook_key": rem.playbook_key, "title": rem.title,
            "action_type": rem.action_type, "status": rem.status,
            "assigned_to": rem.assigned_to, "assigned_role": rem.assigned_role,
            "deadline": rem.deadline.isoformat() if rem.deadline else None,
            "sla_hours": rem.sla_hours,
            "steps_technical": rem.steps_technical,
            "steps_governance": rem.steps_governance,
            "evidence_required": rem.evidence_required,
        })
    # Actor
    actor = None
    if f.actor_id:
        ra = await db.execute(select(ThreatActor).where(ThreatActor.id == f.actor_id))
        a = ra.scalar_one_or_none()
        if a:
            actor = {"id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                     "origin_country": a.origin_country}
    # Campaign
    campaign = None
    if f.campaign_id:
        rc = await db.execute(select(Campaign).where(Campaign.id == f.campaign_id))
        c = rc.scalar_one_or_none()
        if c:
            campaign = {"id": c.id, "name": c.name, "kill_chain_stage": c.kill_chain_stage,
                        "finding_count": c.finding_count, "status": c.status,
                        "severity": _sev(c.severity) or None}

    # ═══ PROOF CHAIN: CVE → affected products (from NVD CPE data) ═══
    affected_products = []
    if f.ioc_type == "cve_id" and f.ioc_value:
        from arguswatch.models import CveProductMap
        cpe_r = await db.execute(
            select(CveProductMap).where(CveProductMap.cve_id == f.ioc_value).limit(10)
        )
        for cpe in cpe_r.scalars().all():
            affected_products.append({
                "product": cpe.product_name,
                "vendor": cpe.vendor,
                "version_range": cpe.version_range,
                "cvss_score": cpe.cvss_score,
                "severity": cpe.severity,
                "actively_exploited": cpe.actively_exploited,
                "source": cpe.source or "nvd",
            })

    # ═══ PROOF CHAIN: Asset discovery source ═══
    asset_proof = None
    if f.matched_asset and f.customer_id:
        from arguswatch.models import CustomerAsset
        asset_r = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == f.customer_id,
                CustomerAsset.asset_value == f.matched_asset,
            ).limit(1)
        )
        asset = asset_r.scalar_one_or_none()
        if asset:
            # Determine real discovery source - NEVER return null/unknown
            ds = asset.discovery_source
            if not ds or ds == 'unknown' or ds == 'null':
                at = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
                if at in ('domain', 'email_domain'):
                    ds = 'onboarding'
                elif at == 'tech_stack':
                    ds = 'industry_default'
                elif at in ('brand_name', 'keyword'):
                    ds = 'auto_from_name'
                elif at in ('ip', 'cidr', 'subdomain'):
                    ds = 'recon'
                elif at == 'github_org':
                    ds = 'manual_entry'
                else:
                    ds = 'onboarding'
                # Fix it in DB too so it never happens again
                try:
                    asset.discovery_source = ds
                    await db.commit()
                except Exception:
                    pass
            asset_proof = {
                "asset_value": asset.asset_value,
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                "discovery_source": ds,
                "confidence": asset.confidence,
                "confidence_sources": asset.confidence_sources or [],
                "manual_entry": getattr(asset, "manual_entry", False),
                "ioc_hit_count": asset.ioc_hit_count or 0,
                "last_seen_in_ioc": asset.last_seen_in_ioc.isoformat() if asset.last_seen_in_ioc else None,
                "created_at": asset.created_at.isoformat() if asset.created_at else None,
                "criticality": asset.criticality,
            }

    return {
        "id": f.id, "ioc_type": f.ioc_type, "ioc_value": f.ioc_value,
        "severity": _sev(f.severity) or None,
        "status": f.status.value if f.status else None,
        "customer_id": f.customer_id,
        "customer_name": (await db.execute(select(Customer.name).where(Customer.id == f.customer_id))).scalar() if f.customer_id else None,
        "customer_industry": (await db.execute(select(Customer.industry).where(Customer.id == f.customer_id))).scalar() if f.customer_id else None,
        "correlation_type": f.correlation_type,
        "match_strategy": f.correlation_type,
        "actor_name": f.actor_name,
        "source": f.all_sources[0] if f.all_sources else None,
        "matched_asset": f.matched_asset, "source_count": f.source_count,
        "all_sources": f.all_sources, "confidence": f.confidence,
        "sla_hours": f.sla_hours,
        "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "actor": actor, "campaign": campaign,
        "sources": sources, "remediations": remediations,
        # V13 AI fields
        "ai_narrative": getattr(f, "ai_narrative", None),
        "ai_severity_decision": getattr(f, "ai_severity_decision", None),
        "ai_severity_reasoning": getattr(f, "ai_severity_reasoning", None),
        "ai_severity_confidence": getattr(f, "ai_severity_confidence", None),
        "ai_rescore_decision": getattr(f, "ai_rescore_decision", None),
        "ai_rescore_reasoning": getattr(f, "ai_rescore_reasoning", None),
        "ai_rescore_confidence": getattr(f, "ai_rescore_confidence", None),
        "ai_attribution_reasoning": getattr(f, "ai_attribution_reasoning", None),
        "ai_false_positive_flag": getattr(f, "ai_false_positive_flag", False),
        "ai_false_positive_reason": getattr(f, "ai_false_positive_reason", None),
        "ai_enriched_at": f.ai_enriched_at.isoformat() if getattr(f, "ai_enriched_at", None) else None,
        "ai_provider": getattr(f, "ai_provider", None),
        # ═══ PROOF CHAIN ═══
        "affected_products": affected_products,
        "asset_proof": asset_proof,
    }


@app.patch("/api/findings/{finding_id}/status", dependencies=_write_deps)
async def update_finding_status(finding_id: int, status: str, db: AsyncSession = Depends(get_db)):
    """Update finding status. Valid: VERIFIED_CLOSED, FALSE_POSITIVE, IN_REVIEW, ESCALATION."""
    from arguswatch.models import Finding, DetectionStatus
    from datetime import datetime
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    try:
        f.status = DetectionStatus(status.upper())
    except ValueError:
        raise HTTPException(400, f"Invalid status: {status}")
    if status.upper() in ("VERIFIED_CLOSED", "FALSE_POSITIVE", "CLOSED"):
        f.resolved_at = datetime.utcnow()
    # V16.4: Record FP pattern for learning
    if status.upper() == "FALSE_POSITIVE" and f.customer_id:
        try:
            from arguswatch.engine.fp_memory import record_fp_pattern
            await record_fp_pattern(
                customer_id=f.customer_id,
                ioc_type=f.ioc_type or "",
                ioc_value=f.ioc_value or "",
                source=(f.all_sources or ["unknown"])[0] if f.all_sources else "",
                reason=f"Analyst marked FP on finding#{finding_id}",
                created_by="analyst",
                db=db,
            )
        except Exception as _fp_e:
            logger.debug(f"[fp_memory] Failed to record FP pattern: {_fp_e}")
    await db.commit()
    return {"finding_id": finding_id, "status": f.status.value}


@app.patch("/api/findings/{finding_id}/remediations/{rem_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def update_remediation_status(
    finding_id: int, rem_id: int, status: str,
    db: AsyncSession = Depends(get_db)
):
    """Update a remediation action status."""
    from arguswatch.models import FindingRemediation
    from datetime import datetime
    r = await db.execute(
        select(FindingRemediation).where(
            FindingRemediation.id == rem_id,
            FindingRemediation.finding_id == finding_id,
        )
    )
    rem = r.scalar_one_or_none()
    if not rem:
        raise HTTPException(404, "Remediation not found")
    rem.status = status.lower()
    if status.lower() == "completed":
        rem.completed_at = datetime.utcnow()
    await db.commit()
    return {"rem_id": rem_id, "status": rem.status}


@app.get("/api/campaigns")
async def list_campaigns(
    status: str = "active",
    customer_id: int = None,
    db: AsyncSession = Depends(get_db),
):
    """List attack campaigns."""
    from arguswatch.models import Campaign, Customer
    q = select(Campaign)
    if status:
        q = q.where(Campaign.status == status)
    if customer_id:
        q = q.where(Campaign.customer_id == customer_id)
    # Sort: severity priority (CRITICAL first), then most recent activity
    sev_order = case(
        (Campaign.severity == SeverityLevel.CRITICAL, 0),
        (Campaign.severity == SeverityLevel.HIGH, 1),
        (Campaign.severity == SeverityLevel.MEDIUM, 2),
        (Campaign.severity == SeverityLevel.LOW, 3),
        else_=4
    )
    q = q.order_by(sev_order, Campaign.last_activity.desc()).limit(50)
    r = await db.execute(q)
    campaigns = r.scalars().all()
    # Batch-fetch customer names
    cust_ids = list(set(c.customer_id for c in campaigns if c.customer_id))
    cust_map = {}
    if cust_ids:
        cr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(cust_ids)))
        cust_map = {row.id: row.name for row in cr.all()}
    return [{
        "id": c.id, "name": c.name, "customer_id": c.customer_id,
        "customer_name": cust_map.get(c.customer_id, "Unknown"),
        "actor_name": c.actor_name, "kill_chain_stage": c.kill_chain_stage,
        "finding_count": c.finding_count,
        "severity": _sev(c.severity) or None,
        "status": c.status,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_activity": c.last_activity.isoformat() if c.last_activity else None,
        "ai_narrative": getattr(c, "ai_narrative", None),
    } for c in campaigns]


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, db: AsyncSession = Depends(get_db)):
    """Get full campaign detail with findings, actor, customer, remediations, and sources."""
    from arguswatch.models import Campaign, Finding, Customer, FindingSource, FindingRemediation
    r = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Campaign not found")
    # Get linked findings sorted: CRITICAL first
    sev_order = case(
        (Finding.severity == SeverityLevel.CRITICAL, 0),
        (Finding.severity == SeverityLevel.HIGH, 1),
        (Finding.severity == SeverityLevel.MEDIUM, 2),
        (Finding.severity == SeverityLevel.LOW, 3),
        else_=4
    )
    fr = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id).order_by(sev_order, Finding.created_at.desc()).limit(50)
    )
    findings = []
    finding_ids = []
    for f in fr.scalars().all():
        sev = f.severity
        sev_str = sev.value if hasattr(sev, 'value') else str(sev) if sev else None
        finding_ids.append(f.id)
        findings.append({
            "id": f.id, "ioc_value": f.ioc_value, "ioc_type": f.ioc_type,
            "severity": sev_str,
            "source": f.source if hasattr(f, 'source') else None,
            "all_sources": f.all_sources or [],
            "confidence": f.confidence,
            "matched_asset": f.matched_asset,
            "correlation_type": f.correlation_type,
            "ai_title": getattr(f, "ai_title", None),
            "ai_narrative": getattr(f, "ai_narrative", None),
            "ai_severity_reasoning": getattr(f, "ai_severity_reasoning", None),
            "confirmed_exposure": getattr(f, "confirmed_exposure", False),
            "exposure_type": getattr(f, "exposure_type", None),
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "status": f.status.value if hasattr(f.status, 'value') else str(f.status) if f.status else None,
            "remediations": [],
            "sources_detail": [],
        })
    # Batch-fetch remediations for all findings
    if finding_ids:
        rem_r = await db.execute(
            select(FindingRemediation).where(FindingRemediation.finding_id.in_(finding_ids)).order_by(FindingRemediation.created_at.desc())
        )
        rem_map = {}
        for rem in rem_r.scalars().all():
            rem_map.setdefault(rem.finding_id, []).append({
                "id": rem.id, "title": rem.title, "action_type": rem.action_type,
                "steps_technical": rem.steps_technical or [],
                "steps_governance": rem.steps_governance or [],
                "assigned_to": rem.assigned_to, "status": rem.status,
                "deadline": rem.deadline.isoformat() if rem.deadline else None,
            })
        # Batch-fetch sources
        src_r = await db.execute(
            select(FindingSource).where(FindingSource.finding_id.in_(finding_ids)).order_by(FindingSource.contributed_at.desc())
        )
        src_map = {}
        for s in src_r.scalars().all():
            src_map.setdefault(s.finding_id, []).append({
                "source": s.source,
                "contributed_at": s.contributed_at.isoformat() if s.contributed_at else None,
            })
        # Attach to findings
        for fd in findings:
            fd["remediations"] = rem_map.get(fd["id"], [])
            fd["sources_detail"] = src_map.get(fd["id"], [])
    # Get customer info
    cr = await db.execute(select(Customer).where(Customer.id == c.customer_id))
    cust = cr.scalar_one_or_none()
    cust_info = None
    if cust:
        cust_info = {
            "id": cust.id, "name": cust.name,
            "industry": getattr(cust, "industry", None),
            "tier": getattr(cust, "tier", None),
            "primary_domain": getattr(cust, "primary_domain", None),
        }
    # Get actor info
    actor_info = None
    if c.actor_id:
        from arguswatch.models import ThreatActor
        ar = await db.execute(select(ThreatActor).where(ThreatActor.id == c.actor_id))
        a = ar.scalar_one_or_none()
        if a:
            actor_info = {
                "id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                "origin_country": a.origin_country, "motivation": a.motivation,
                "description": (a.description or "")[:500],
                "techniques": a.techniques or [], "aliases": a.aliases or [],
            }
    c_sev = c.severity
    c_sev_str = c_sev.value if hasattr(c_sev, 'value') else str(c_sev) if c_sev else None
    return {
        "id": c.id, "name": c.name, "customer_id": c.customer_id,
        "customer_name": cust_info["name"] if cust_info else "Unknown",
        "customer": cust_info,
        "actor_name": c.actor_name,
        "actor_id": c.actor_id, "actor": actor_info,
        "kill_chain_stage": c.kill_chain_stage, "finding_count": c.finding_count,
        "severity": c_sev_str,
        "status": c.status, "ai_narrative": c.ai_narrative,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_activity": c.last_activity.isoformat() if c.last_activity else None,
        "findings": findings,
    }


@app.get("/api/actor-iocs")
async def list_actor_iocs(actor_id: int = None, ioc_type: str = None,
                           limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List known actor IOCs from the DB-driven attribution table."""
    from arguswatch.models import ActorIoc
    q = select(ActorIoc)
    if actor_id:
        q = q.where(ActorIoc.actor_id == actor_id)
    if ioc_type:
        q = q.where(ActorIoc.ioc_type == ioc_type)
    q = q.limit(limit)
    r = await db.execute(q)
    return [{"id": ai.id, "actor_id": ai.actor_id, "actor_name": ai.actor_name,
             "ioc_type": ai.ioc_type, "ioc_value": ai.ioc_value,
             "ioc_role": ai.ioc_role, "confidence": ai.confidence, "source": ai.source}
            for ai in r.scalars().all()]


@app.post("/api/actor-iocs", dependencies=[Depends(require_role("admin", "analyst"))])
async def create_actor_ioc(
    actor_id: int, ioc_type: str, ioc_value: str,
    ioc_role: str = None, source: str = "manual",
    db: AsyncSession = Depends(get_db),
):
    """Manually add a known actor IOC to the attribution table."""
    from arguswatch.models import ActorIoc, ThreatActor
    r = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = r.scalar_one_or_none()
    if not actor:
        raise HTTPException(404, "Actor not found")
    ai = ActorIoc(actor_id=actor_id, actor_name=actor.name,
                  ioc_type=ioc_type, ioc_value=ioc_value,
                  ioc_role=ioc_role, source=source)
    db.add(ai)
    await db.commit()
    return {"id": ai.id, "actor_name": actor.name, "ioc_value": ioc_value}


@app.get("/api/unattributed-intel")
async def unattributed_intel(limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Detections not yet matched to any customer - valuable intel for new customer onboarding.
    When you onboard a new customer, run /api/customers/{cid}/recorrelate to match these."""
    r = await db.execute(
        select(Detection)
        .where(Detection.customer_id == None)
        .order_by(Detection.created_at.desc())
        .limit(limit)
    )
    return [{
        "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
        "severity": _sev(d.severity) or None,
        "source": d.source, "confidence": d.confidence,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    } for d in r.scalars().all()]

# ══════════════════════════════════════════════════════
# AI AGENT - 10 tools
# ══════════════════════════════════════════════════════
class AgentQuery(BaseModel):
    question: str
    provider: str = "auto"
    conversation_history: list = []

@app.post("/api/agent/query", dependencies=[Depends(require_role("admin", "analyst"))])
async def agent_query(req: AgentQuery):
    from arguswatch.agent.agent_core import run_agent
    result = await run_agent(req.text, req.provider, req.conversation_history)
    return result

@app.get("/api/settings/ai")
async def get_ai_settings():
    """Return current AI configuration - mode, provider, autonomous status."""
    from arguswatch.config import settings as _s
    from arguswatch.services.ai_pipeline_hooks import _provider, _pipeline_ai_available
    from arguswatch.agent.tools import TOOL_REGISTRY
    tool_count = len(TOOL_REGISTRY)
    rag_available = False
    try:
        import importlib
        importlib.import_module("arguswatch.services.ai_rag_context")
        rag_available = True
    except Exception:
        pass
    prov = _provider()
    return {
        "autonomous": getattr(_s, "AI_AUTONOMOUS", False),
        "provider": prov,
        "active_provider": prov,
        "pipeline_ai_available": _pipeline_ai_available(),
        "anthropic_configured": bool(getattr(_s, "ANTHROPIC_API_KEY", "")),
        "openai_configured": bool(getattr(_s, "OPENAI_API_KEY", "")),
        "google_configured": bool(getattr(_s, "GOOGLE_AI_API_KEY", "")),
        "ollama_url": getattr(_s, "OLLAMA_URL", ""),
        "model": (getattr(_s, "ANTHROPIC_MODEL", "") if getattr(_s, "ANTHROPIC_API_KEY", "")
                  else getattr(_s, "OPENAI_MODEL", "") if getattr(_s, "OPENAI_API_KEY", "")
                  else getattr(_s, "OLLAMA_MODEL", "")),
        "rag_available": rag_available,
        "tool_count": tool_count,
    }


@app.get("/api/agent/tools")
async def list_tools():
    from arguswatch.agent.tools import TOOL_REGISTRY
    return {"tools": list(TOOL_REGISTRY.keys()), "count": len(TOOL_REGISTRY)}

@app.get("/api/agent/providers")
async def agent_provider_health():
    """Check which LLM providers are available right now."""
    from arguswatch.agent.agent_core import check_provider_health
    from arguswatch.config import settings
    from arguswatch.services.ai_pipeline_hooks import _provider, _get_active_provider_from_redis
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]
    current = _provider()  # What the pipeline is actually using right now

    # Provider metadata for UI
    provider_meta = {
        "ollama": {
            "status": health.get("ollama", "unknown"),
            "model": settings.OLLAMA_MODEL,
            "has_key": True,  # no key needed
            "label": "Local AI",
            "icon": "llama",
            "is_active": current == "ollama",
        },
        "anthropic": {
            "status": health.get("anthropic", "unknown"),
            "model": settings.ANTHROPIC_MODEL if settings.ANTHROPIC_API_KEY else "",
            "has_key": bool(settings.ANTHROPIC_API_KEY),
            "label": "Claude",
            "icon": "claude",
            "is_active": current == "anthropic",
        },
        "openai": {
            "status": health.get("openai", "unknown"),
            "model": settings.OPENAI_MODEL if settings.OPENAI_API_KEY else "",
            "has_key": bool(settings.OPENAI_API_KEY),
            "label": "GPT",
            "icon": "gpt",
            "is_active": current == "openai",
        },
        "google": {
            "status": health.get("google", "unknown"),
            "model": getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro") if getattr(settings, "GOOGLE_AI_API_KEY", "") else "",
            "has_key": bool(getattr(settings, "GOOGLE_AI_API_KEY", "")),
            "label": "Gemini",
            "icon": "gemini",
            "is_active": current == "google",
        },
    }

    return {
        "providers": provider_meta,
        "active": active,
        "current": current,  # What pipeline is actually using
        "selected": _get_active_provider_from_redis(),
        "recommended": active[0] if active else "none",
        "pipeline_ai_enabled": len(active) > 0,
    }


@app.post("/api/settings/active-provider", dependencies=_admin_deps)
async def set_active_provider(request: Request):
    """Switch which AI provider the pipeline uses.
    Called by the dashboard AI switcher when user clicks a provider button.
    Body: {"provider": "ollama"|"anthropic"|"openai"|"google"|"auto"}
    """
    from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis, _provider
    body = await request.json()
    prov = body.get("provider", "ollama")
    # Map aliases
    if prov == "local": prov = "ollama"
    if prov == "claude": prov = "anthropic"
    if prov not in ("ollama", "anthropic", "openai", "google", "auto"):
        raise HTTPException(400, f"Invalid provider: {prov}")
    _set_active_provider_in_redis(prov)
    current = _provider()  # What it resolved to after the switch
    return {"selected": prov, "resolved": current, "status": "ok"}

# Individual tool endpoints
class ToolRequest(BaseModel):
    args: dict = {}

@app.post("/api/agent/tools/{tool_name}", dependencies=[Depends(require_role("admin", "analyst"))])
async def call_tool(tool_name: str, req: ToolRequest):
    from arguswatch.agent.tools import TOOL_REGISTRY
    if tool_name not in TOOL_REGISTRY:
        raise HTTPException(404, f"Tool not found: {tool_name}")
    try:
        result = await TOOL_REGISTRY[tool_name](**req.args)
        return result
    except Exception as e:
        raise HTTPException(400, str(e))

# ══════════════════════════════════════════════════════
# EXPOSURE SCORING
# ══════════════════════════════════════════════════════
@app.post("/api/exposure/recalculate", dependencies=[Depends(require_role("admin", "analyst"))])
async def recalculate_exposure():
    from arguswatch.services.exposure_scorer import calculate_all_exposures
    result = await calculate_all_exposures()
    return {"status": "ok", "result": result}

@app.get("/api/exposure/customer/{customer_id}")
async def customer_exposure_scores(customer_id: int):
    from arguswatch.services.exposure_scorer import get_customer_top_threats
    threats = await get_customer_top_threats(customer_id, limit=20)
    return {"customer_id": customer_id, "top_threats": threats}

@app.get("/api/exposure/leaderboard")
async def exposure_leaderboard(sector: str = None, db: AsyncSession = Depends(get_db)):
    """Top customers by exposure score. Uses LEFT JOIN so new customers appear too.
    Falls back to ExposureHistory overall_score for customers without per-actor exposure."""
    from arguswatch.models import CustomerExposure, Customer as CustomerModel, ExposureHistory
    from sqlalchemy import case
    
    # Primary: per-actor exposure scores (LEFT JOIN so all customers included)
    q = (
        select(CustomerModel.id, CustomerModel.name, CustomerModel.industry,
               func.coalesce(func.max(CustomerExposure.exposure_score), 0.0).label("max_score"),
               func.count(CustomerExposure.id).label("actor_count"))
        .outerjoin(CustomerExposure, CustomerExposure.customer_id == CustomerModel.id)
        .where(CustomerModel.active == True)
    )
    if sector:
        q = q.where(CustomerModel.industry == sector.lower())
    q = q.group_by(CustomerModel.id, CustomerModel.name, CustomerModel.industry
        ).order_by(desc("max_score")).limit(20)
    r = await db.execute(q)
    results = []
    for row in r:
        score = row.max_score
        d1 = d2 = d3 = d4 = d5 = 0.0
        # Always fetch latest ExposureHistory for D1-D5 + fallback overall score
        eh = await db.execute(
            select(ExposureHistory)
            .where(ExposureHistory.customer_id == row.id)
            .order_by(ExposureHistory.snapshot_date.desc())
            .limit(1)
        )
        eh_row = eh.scalar_one_or_none()
        if eh_row:
            d1 = eh_row.d1_score or 0.0
            d2 = eh_row.d2_score or 0.0
            d3 = eh_row.d3_score or 0.0
            d4 = eh_row.d4_score or 0.0
            d5 = eh_row.d5_score or 0.0
            if score == 0 and eh_row.overall_score:
                score = eh_row.overall_score
        # Fallback: severity-weighted estimate when D1-D5 scorer hasn't run
        if score == 0:
            from arguswatch.models import Finding as FindingModel
            fc_r = await db.execute(select(func.count(FindingModel.id)).where(FindingModel.customer_id == row.id))
            fc = fc_r.scalar() or 0
            if fc > 0:
                cc_r = await db.execute(select(func.count(FindingModel.id)).where(
                    FindingModel.customer_id == row.id, FindingModel.severity == "CRITICAL"))
                hc_r = await db.execute(select(func.count(FindingModel.id)).where(
                    FindingModel.customer_id == row.id, FindingModel.severity == "HIGH"))
                cc = cc_r.scalar() or 0
                hc = hc_r.scalar() or 0
                score = min(75, cc * 6 + hc * 3 + max(0, fc - cc - hc) * 0.5)
        results.append({"id": row.id, "name": row.name, "industry": row.industry,
                        "max_exposure_score": round(score, 1),
                        "actor_count": row.actor_count,
                        "d1": round(d1, 1), "d2": round(d2, 1), "d3": round(d3, 1),
                        "d4": round(d4, 1), "d5": round(d5, 1),
                        "d1_score": round(d1, 1), "d2_score": round(d2, 1),
                        "d3_score": round(d3, 1), "d4_score": round(d4, 1),
                        "d5_score": round(d5, 1)})
    # Re-sort after fallback scores applied
    results.sort(key=lambda x: x["max_exposure_score"], reverse=True)
    return results


@app.get("/api/customers/{cid}/exposure-trend")
async def customer_exposure_trend(cid: int, days: int = 30, db: AsyncSession = Depends(get_db)):
    """Historical exposure trend from daily snapshots. Returns up to {days} data points."""
    from arguswatch.models import ExposureHistory
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    r = await db.execute(
        select(ExposureHistory).where(
            ExposureHistory.customer_id == cid,
            ExposureHistory.snapshot_date >= cutoff,
        ).order_by(ExposureHistory.snapshot_date.asc())
    )
    snapshots = r.scalars().all()
    
    if not snapshots:
        return {
            "customer_id": cid,
            "days": days,
            "data_points": 0,
            "trend": [],
            "note": "No historical data yet. Snapshots are taken daily - check back tomorrow.",
        }
    
    return {
        "customer_id": cid,
        "days": days,
        "data_points": len(snapshots),
        "trend": [{
            "date": s.snapshot_date.strftime("%Y-%m-%d"),
            "overall": s.overall_score,
            "d1": s.d1_score, "d2": s.d2_score, "d3": s.d3_score,
            "d4": s.d4_score, "d5": s.d5_score,
            "detections": s.total_detections,
            "critical": s.critical_count,
        } for s in snapshots],
    }

# ══════════════════════════════════════════════════════
# PDF REPORTS
# ══════════════════════════════════════════════════════
@app.post("/api/reports/generate/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def generate_report(customer_id: int, period_days: int = 30):
    from arguswatch.services.pdf_report import generate_pdf_report
    result = await generate_pdf_report(customer_id, period_days)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@app.get("/api/reports/download/{file_name}")
async def download_report(file_name: str):
    from fastapi.responses import FileResponse
    from pathlib import Path
    fpath = Path("/app/reports") / file_name
    if not fpath.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(str(fpath), media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={file_name}"})

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

@app.get("/api/remediations/stats")
async def remediation_stats(db: AsyncSession = Depends(get_db)):
    from arguswatch.models import RemediationAction
    r = await db.execute(
        select(RemediationAction.status, func.count(RemediationAction.id).label("cnt"))
        .group_by(RemediationAction.status)
    )
    by_status = {row.status: row.cnt for row in r}
    total = sum(by_status.values())
    closed = by_status.get("completed", 0)
    return {"total": total, "by_status": by_status,
            "resolution_rate": round(closed / max(total, 1) * 100, 1)}

# ══════════════════════════════════════════════════════
# SLA / ESCALATION
# ══════════════════════════════════════════════════════
@app.get("/api/sla/breaches")
async def sla_breaches(db: AsyncSession = Depends(get_db)):
    """Detections that have exceeded their SLA without resolution."""
    breaches = []
    r = await db.execute(
        select(Detection).where(
            Detection.status.in_(["NEW", "ENRICHED"]),
            Detection.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        ).order_by(desc(Detection.created_at)).limit(100)
    )
    all_dets = r.scalars().all()
    # Batch-load customer names
    sla_cust_ids = list({d.customer_id for d in all_dets if d.customer_id})
    sla_cust_names = {}
    if sla_cust_ids:
        cnr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(sla_cust_ids)))
        sla_cust_names = {row.id: row.name for row in cnr.all()}
    for d in all_dets:
        elapsed_h = (datetime.utcnow() - d.created_at).total_seconds() / 3600 if d.created_at else 0
        if elapsed_h > (d.sla_hours or 72):
            breaches.append({
                "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value[:60],
                "severity": _sev(d.severity) or None,
                "sla_hours": d.sla_hours, "elapsed_hours": round(elapsed_h, 1),
                "overdue_by": round(elapsed_h - (d.sla_hours or 72), 1),
                "actual_hours": round(elapsed_h, 1),
                "customer_id": d.customer_id,
                "customer_name": sla_cust_names.get(d.customer_id, ""),
                "finding_id": d.finding_id,
                "breached": True,
            })
    return {"total_breaches": len(breaches), "breaches": breaches}

# ══════════════════════════════════════════════════════
# STIX EXPORT
# ══════════════════════════════════════════════════════
@app.post("/api/stix/export/{detection_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_stix(detection_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.stix_exporter import export_detection_to_stix
    r = await db.execute(select(Detection).where(Detection.id == detection_id))
    d = r.scalar_one_or_none()
    if not d: raise HTTPException(404, "Detection not found")
    bundle = export_detection_to_stix(d)
    return bundle

# ══════════════════════════════════════════════════════
# ATTRIBUTION  (Playbooks handled by playbook_router above)
# ══════════════════════════════════════════════════════
@app.get("/api/attribution/cve/{cve_id}")
async def cve_attribution(cve_id: str, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import CVE_ACTOR_MAP
    actors = CVE_ACTOR_MAP.get(cve_id.upper(), [])
    if not actors:
        return {"cve_id": cve_id, "actors": [], "message": "No known actor attribution"}
    r = await db.execute(
        select(ThreatActor).where(ThreatActor.name.in_(actors))
    )
    found = r.scalars().all()
    return {
        "cve_id": cve_id,
        "actor_names": actors,
        "actors": [{"id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                    "origin_country": a.origin_country, "technique_count": len(a.techniques or [])}
                   for a in found]
    }

@app.post("/api/attribution/enrich-detection/{detection_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def enrich_detection_attribution(detection_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import attribute_detection_by_id
    result = await attribute_detection_by_id(detection_id, db)
    return result

# ── Exposure / Risk ──
@app.get("/api/customers/{customer_id}/risk")
async def get_customer_risk(customer_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.services.exposure_scorer import get_customer_risk_summary
    return await get_customer_risk_summary(customer_id, db)


@app.get("/api/customers/{cid}/exposure-breakdown")
async def customer_exposure_breakdown(cid: int, db: AsyncSession = Depends(get_db)):
    """Live D1-D5 exposure breakdown with step-by-step calculation."""
    from arguswatch.models import Customer, CustomerExposure, ThreatActor, ExposureHistory, Finding
    
    r = await db.execute(select(Customer).where(Customer.id == cid))
    customer = r.scalar_one_or_none()
    if not customer:
        raise HTTPException(404, "Customer not found")
    
    # Severity counts
    sev_r = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.customer_id == cid).group_by(Finding.severity)
    )
    sev_counts = {(s.value if hasattr(s, 'value') else str(s)): c for s, c in sev_r.all() if s}
    
    det_count = (await db.execute(
        select(func.count(Detection.id)).where(Detection.customer_id == cid)
    )).scalar() or 0
    asset_count = (await db.execute(
        select(func.count(CustomerAsset.id)).where(CustomerAsset.customer_id == cid)
    )).scalar() or 0
    
    d1, d2, d3, d4, d5 = 0.0, 0.0, 0.0, 0.0, 0.0
    f1, f2, f3, f4, f5 = {}, {}, {}, {}, {}
    try:
        from arguswatch.engine.exposure_scorer import (
            _dim1_direct_exposure, _dim2_active_exploitation,
            _dim3_actor_intent, _dim4_attack_surface, _dim5_asset_criticality,
        )
        d1, f1 = await _dim1_direct_exposure(cid, db)
        d2, f2 = await _dim2_active_exploitation(cid, db)
        d4, f4 = await _dim4_attack_surface(cid, db)
        d5, f5 = await _dim5_asset_criticality(cid, db)
        top_r = await db.execute(
            select(CustomerExposure, ThreatActor)
            .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
            .where(CustomerExposure.customer_id == cid)
            .order_by(CustomerExposure.exposure_score.desc()).limit(1)
        )
        top = top_r.one_or_none()
        if top:
            d3, f3 = await _dim3_actor_intent(customer, top.ThreatActor, db)
    except Exception as e:
        pass
    
    eh_r = await db.execute(
        select(ExposureHistory).where(ExposureHistory.customer_id == cid)
        .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
    )
    eh = eh_r.scalar_one_or_none()
    if eh and eh.overall_score and d1 == 0 and d2 == 0:
        d1, d2, d3, d4, d5 = eh.d1_score, eh.d2_score, eh.d3_score, eh.d4_score, eh.d5_score
    
    exposure_base = (d1 * 0.50) + (d2 * 0.30) + (d3 * 0.20)
    surface_floor = d4 * 0.20
    base = max(exposure_base, surface_floor)
    impact_modifier = 0.75 + (d4 * 0.00125) + (d5 * 0.00125)
    final = min(base * impact_modifier, 100.0)
    stored_score = eh.overall_score if eh else None
    # Live D1-D5 calculation is authoritative  -  no stale overrides
    
    def _clean_factors(fdict):
        out = {}
        for k, v in fdict.items():
            if isinstance(v, dict):
                out[k] = {kk: (vv if not hasattr(vv, '__dict__') else str(vv)) for kk, vv in v.items()}
            else:
                out[k] = v
        return out
    
    return {
        "customer": customer.name, "final_score": round(final, 1),
        "label": "CRITICAL" if final >= 80 else "HIGH" if final >= 60 else "MEDIUM" if final >= 40 else "LOW",
        "dimensions": {
            "d1": {"name": "Direct Exposure", "score": round(d1, 1), "weight": "50%", "weighted": round(d1 * 0.50, 1), "factors": _clean_factors(f1)},
            "d2": {"name": "Active Exploitation", "score": round(d2, 1), "weight": "30%", "weighted": round(d2 * 0.30, 1), "factors": _clean_factors(f2)},
            "d3": {"name": "Actor Intent", "score": round(d3, 1), "weight": "20%", "weighted": round(d3 * 0.20, 1), "factors": _clean_factors(f3)},
            "d4": {"name": "Attack Surface", "score": round(d4, 1), "weight": "floor", "weighted": round(d4 * 0.20, 1), "factors": _clean_factors(f4)},
            "d5": {"name": "Asset Criticality", "score": round(d5, 1), "weight": "impact", "weighted": round(d5 * 0.00125, 3), "factors": _clean_factors(f5)},
        },
        "steps": {
            "exposure_base": round(exposure_base, 1), "surface_floor": round(surface_floor, 1),
            "base": round(base, 1), "impact_modifier": round(impact_modifier, 3), "final": round(final, 1),
        },
        "context": {"detections": det_count, "findings_by_severity": sev_counts, "assets": asset_count},
    }

# ── Attribution ──
@app.post("/api/attribution/run", dependencies=[Depends(require_role("admin", "analyst"))])
async def run_attribution(db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import run_attribution_pass
    return await run_attribution_pass(db)

# ── Correlation ──
@app.post("/api/correlate", dependencies=[Depends(require_role("admin", "analyst"))])
async def run_correlation(db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.correlation_engine import correlate_new_detections
    return await correlate_new_detections(db)

# ── Playbooks ──
# ── STIX + CEF ──
@app.post("/api/export/stix", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_stix_bulk():
    """V10: Renamed from export_stix to avoid duplicate route function name."""
    from arguswatch.engine.stix_exporter import export_all_to_stix
    return await export_all_to_stix()

@app.post("/api/export/siem", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_siem():
    from arguswatch.engine.syslog_exporter import send_recent_to_siem
    return await send_recent_to_siem()

# ── Remediation status update ──
# Detection status update handled by detections_router (api/detections.py)


# ═══════════════════════════════════════════════════════════════════════
# ASSET DISCOVERY - file upload endpoints (GAP 1 fix)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/customers/{cid}/discover", dependencies=[Depends(require_role("admin", "analyst"))])
async def discover_assets(cid: int, request: Request):
    """Upload asset discovery file. Accepts CSV, JSON, BIND zone, DHCP, CT log, agent bundle.
    Query param: ?type=auto|csv|json|bind_zone|dhcp_lease|ct_log|agent_bundle
    Body: raw file content."""
    from arguswatch.services.asset_discovery import (
        parse_csv_import, parse_json_import, parse_bind_zone,
        parse_dhcp_leases, parse_ct_log, parse_agent_bundle,
        ingest_assets, AGENT_SCHEMA,
    )
    from arguswatch.models import Customer, CustomerAsset
    from arguswatch.database import async_session
    from sqlalchemy import select

    # Verify customer exists
    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.id == cid))
        cust = r.scalar_one_or_none()
        if not cust:
            from fastapi import HTTPException
            raise HTTPException(404, "Customer not found")
        customer_domain = ""
        # Get primary domain from existing assets
        ar = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == "domain",
            ).limit(1)
        )
        da = ar.scalar_one_or_none()
        if da:
            customer_domain = da.asset_value

    body = await request.body()
    content = body.decode("utf-8", errors="replace")
    file_type = request.query_params.get("type", "auto")

    # Auto-detect file type
    if file_type == "auto":
        stripped = content.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            # Could be JSON, CT log, or agent bundle
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict) and "agent_id" in parsed:
                    file_type = "agent_bundle"
                elif isinstance(parsed, dict) and any(k in parsed for k in ("common_name", "name_value")):
                    file_type = "ct_log"
                elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    if "common_name" in parsed[0] or "name_value" in parsed[0]:
                        file_type = "ct_log"
                    else:
                        file_type = "json"
                else:
                    file_type = "json"
            except json.JSONDecodeError:
                file_type = "csv"
        elif stripped.startswith("$ORIGIN") or stripped.startswith("$TTL") or "\tIN\t" in stripped:
            file_type = "bind_zone"
        elif "lease " in stripped and "{" in stripped:
            file_type = "dhcp_lease"
        else:
            file_type = "csv"

    # Parse based on detected type
    records = []
    metadata = {}
    if file_type == "csv":
        records = parse_csv_import(content)
    elif file_type == "json":
        records = parse_json_import(content)
    elif file_type == "bind_zone":
        records = parse_bind_zone(content, customer_domain=customer_domain)
    elif file_type == "dhcp_lease":
        records = parse_dhcp_leases(content)
    elif file_type == "ct_log":
        customer_domains = [customer_domain] if customer_domain else []
        records = parse_ct_log(content, customer_domains=customer_domains)
    elif file_type == "agent_bundle":
        from arguswatch.config import settings
        signing_key = getattr(settings, "AGENT_SIGNING_KEY", "")
        records, metadata = parse_agent_bundle(content, signing_key=signing_key)
    else:
        return {"error": f"Unknown file_type: {file_type}"}

    if not records:
        return {"parsed": 0, "added": 0, "file_type": file_type,
                "message": "No valid asset records found in uploaded file"}

    # Ingest into DB
    result = await ingest_assets(cid, records)
    result["file_type"] = file_type
    if metadata:
        result["agent_metadata"] = metadata
    return result


@app.get("/api/discovery/agent-schema")
async def get_agent_schema():
    """Return the canonical agent telemetry bundle schema."""
    from arguswatch.services.asset_discovery import AGENT_SCHEMA
    return AGENT_SCHEMA


@app.get("/api/discovery/providers")
async def list_discovery_providers():
    """Return available discovery providers and their configuration status."""
    from arguswatch.services.discovery_providers import get_configured_providers
    return {"providers": get_configured_providers()}


@app.post("/api/customers/{cid}/discover/external", dependencies=[Depends(require_role("admin", "analyst"))])
async def discover_external(cid: int, provider: str = ""):
    """Smart asset discovery for a customer.
    1. Auto-infers domain from customer name if no domain asset exists
    2. Adds the domain asset automatically
    3. Runs offline discovery (always works, no network needed)
    4. Tries online OSINT if network available (bonus)
    5. Auto-advances onboarding state
    """
    from arguswatch.services.asset_discovery import AssetRecord, ingest_assets
    from arguswatch.services.osint_discovery import run_osint_discovery
    from arguswatch.models import Customer, CustomerAsset, AssetType
    from arguswatch.database import async_session
    from sqlalchemy import select
    from datetime import datetime as _dt

    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.id == cid))
        cust = r.scalar_one_or_none()
        if not cust:
            raise HTTPException(404, "Customer not found")

        # Check for existing domain asset
        ar = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == "domain",
            ).limit(1)
        )
        domain_asset = ar.scalar_one_or_none()

        # Auto-infer domain from customer name if none exists
        if not domain_asset:
            # Smart domain inference: "Paypal" → "paypal.com", "Amazon Web Services" → "aws.amazon.com"
            name_lower = (cust.name or "").strip().lower()
            # Common company → domain mappings
            known_domains = {
                "paypal": "paypal.com", "amazon": "amazon.com", "google": "google.com",
                "microsoft": "microsoft.com", "apple": "apple.com", "meta": "meta.com",
                "facebook": "facebook.com", "netflix": "netflix.com", "tesla": "tesla.com",
                "twitter": "twitter.com", "x": "x.com", "github": "github.com",
                "stripe": "stripe.com", "shopify": "shopify.com", "adobe": "adobe.com",
                "oracle": "oracle.com", "ibm": "ibm.com", "cisco": "cisco.com",
                "intel": "intel.com", "nvidia": "nvidia.com", "uber": "uber.com",
                "airbnb": "airbnb.com", "slack": "slack.com", "zoom": "zoom.us",
                "salesforce": "salesforce.com", "twilio": "twilio.com",
                "cloudflare": "cloudflare.com", "crowdstrike": "crowdstrike.com",
                "paloalto": "paloaltonetworks.com", "fortinet": "fortinet.com",
                "solvent": "solventcyber.com", "solvent cybersecurity": "solventcyber.com",
            }
            domain = known_domains.get(name_lower)
            if not domain:
                # Fallback: derive from name - take first word, add .com
                slug = name_lower.split()[0].replace(" ", "")
                # If email exists, extract domain from it
                if cust.email and "@" in cust.email:
                    domain = cust.email.split("@")[1]
                else:
                    domain = slug + ".com"

            # Auto-create the domain asset
            db.add(CustomerAsset(
                customer_id=cid,
                asset_type=AssetType.DOMAIN,
                asset_value=domain,
                criticality="critical",
                confidence=0.9,
                confidence_sources=["auto_inferred"],
                discovery_source="auto_infer",
            ))
            await db.commit()
        else:
            domain = domain_asset.asset_value

    # Run OSINT discovery (handles network failure gracefully with offline fallback)
    raw = await run_osint_discovery(domain, customer_name=cust.name)

    # Convert to AssetRecords and ingest
    records = []
    for item in raw:
        if isinstance(item, dict) and "error" not in item:
            records.append(AssetRecord(
                asset_type=item.get("asset_type", "subdomain"),
                asset_value=item.get("asset_value", ""),
                criticality=item.get("criticality", "medium"),
                confidence=item.get("confidence", 0.5),
                source=f"osint_discovery",
            ))

    if not records:
        return {"added": 0, "domain": domain, "message": "No new assets discovered"}

    result = await ingest_assets(cid, records)
    result["domain"] = domain

    # Auto-advance onboarding if assets were added
    if result.get("added", 0) > 0:
        async with async_session() as db:
            cr = await db.execute(select(Customer).where(Customer.id == cid))
            cu = cr.scalar_one_or_none()
            if cu and cu.onboarding_state in ("created", None):
                cu.onboarding_state = "assets_added"
                cu.onboarding_updated_at = _dt.utcnow()
                await db.commit()

    return result


# ══════════════════════════════════════════════════════════════════════
# V16.4: AGENTIC AI ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@app.get("/api/sector/advisories")
async def list_sector_advisories(
    status: str = "active", limit: int = 20, db: AsyncSession = Depends(get_db)
):
    """List sector advisories - cross-customer threat intelligence."""
    from arguswatch.models import SectorAdvisory
    q = select(SectorAdvisory).order_by(SectorAdvisory.created_at.desc()).limit(limit)
    if status:
        q = q.where(SectorAdvisory.status == status)
    r = await db.execute(q)
    return [{
        "id": a.id, "ioc_value": a.ioc_value, "ioc_type": a.ioc_type,
        "affected_customer_count": a.affected_customer_count,
        "affected_industries": a.affected_industries,
        "severity": _sev(a.severity) or "HIGH",
        "classification": a.classification, "ai_narrative": a.ai_narrative,
        "ai_recommended_actions": a.ai_recommended_actions, "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    } for a in r.scalars().all()]

@app.post("/api/sector/detect-now", dependencies=[Depends(require_role("admin", "analyst"))])
async def trigger_sector_detection(db: AsyncSession = Depends(get_db)):
    """Manually trigger cross-customer sector detection."""
    from arguswatch.engine.sector_detection import detect_sector_campaigns
    result = await detect_sector_campaigns(db, hours=48)
    await db.commit()
    return result

@app.get("/api/fp-patterns")
async def list_fp_patterns(customer_id: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db)):
    """List learned false positive patterns."""
    from arguswatch.models import FPPattern
    q = select(FPPattern).order_by(FPPattern.created_at.desc()).limit(limit)
    if customer_id:
        q = q.where(FPPattern.customer_id == customer_id)
    r = await db.execute(q)
    return [{
        "id": p.id, "customer_id": p.customer_id, "ioc_type": p.ioc_type,
        "ioc_value_pattern": p.ioc_value_pattern, "match_type": p.match_type,
        "source": p.source, "reason": p.reason, "confidence": p.confidence,
        "hit_count": p.hit_count, "created_by": p.created_by,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in r.scalars().all()]

@app.get("/api/fp-patterns/stats")
async def fp_memory_stats(db: AsyncSession = Depends(get_db)):
    """FP memory statistics - how much the system has learned."""
    from arguswatch.models import FPPattern
    from sqlalchemy import func as _fn
    total = (await db.execute(select(_fn.count(FPPattern.id)))).scalar() or 0
    total_hits = (await db.execute(select(_fn.sum(FPPattern.hit_count)))).scalar() or 0
    auto_closeable = (await db.execute(
        select(_fn.count(FPPattern.id)).where(FPPattern.confidence >= 0.85)
    )).scalar() or 0
    return {
        "total_patterns": total, "total_hits_saved": total_hits,
        "auto_closeable_patterns": auto_closeable,
        "ai_api_calls_saved_estimate": total_hits,
    }

@app.post("/api/darkweb/triage-now", dependencies=[Depends(require_role("admin", "analyst"))])
async def trigger_darkweb_triage(db: AsyncSession = Depends(get_db)):
    """Manually trigger dark web mention triage."""
    from arguswatch.engine.darkweb_triage import triage_untriaged_mentions
    result = await triage_untriaged_mentions(db, limit=50)
    await db.commit()
    return result

@app.get("/api/darkweb/triage-stats")
async def darkweb_triage_stats(db: AsyncSession = Depends(get_db)):
    """Dark web triage statistics."""
    from arguswatch.models import DarkWebMention
    from sqlalchemy import func as _fn
    total = (await db.execute(select(_fn.count(DarkWebMention.id)))).scalar() or 0
    triaged = (await db.execute(
        select(_fn.count(DarkWebMention.id)).where(DarkWebMention.triaged_at.isnot(None))
    )).scalar() or 0
    return {"total_mentions": total, "triaged": triaged, "pending_triage": total - triaged}

@app.get("/api/customers/{customer_id}/narrative")
async def get_exposure_narrative(customer_id: int, db: AsyncSession = Depends(get_db)):
    """AI-generated exposure narrative for a customer."""
    from arguswatch.models import CustomerExposure
    r = await db.execute(
        select(CustomerExposure).where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc()).limit(1)
    )
    exp = r.scalar_one_or_none()
    if not exp:
        return {"narrative": None, "score": 0}
    return {
        "narrative": exp.score_narrative,
        "score": round(exp.exposure_score, 1),
        "last_calculated": exp.last_calculated.isoformat() if exp.last_calculated else None,
    }

@app.post("/api/settings/ai-keys", dependencies=_admin_deps)
async def set_ai_keys(request: Request):
    """Set API keys at runtime  -  AI providers AND collector keys.
    AI keys: set in backend memory (instant effect).
    Collector keys: forwarded to intel-proxy as env vars + persisted to .env file.
    
    Accepts: {provider: "shodan", api_key: "xxx"} 
         or: {anthropic: "sk-...", openai: "sk-..."} (legacy format)
    """
    from arguswatch.config import settings
    body = await request.json()
    updated = []
    
    # ── Legacy format: {anthropic: "sk-...", openai: "sk-..."}
    if "anthropic" in body and body["anthropic"]:
        settings.ANTHROPIC_API_KEY = body["anthropic"].strip()
        updated.append("anthropic")
    if "openai" in body and body["openai"]:
        settings.OPENAI_API_KEY = body["openai"].strip()
        updated.append("openai")
    if "google" in body and body["google"]:
        settings.GOOGLE_AI_API_KEY = body["google"].strip()
        updated.append("google")
    
    # ── New format: {provider: "shodan", api_key: "xxx"}
    provider = body.get("provider", "")
    api_key = body.get("api_key", "").strip()
    
    if provider and api_key:
        # Map UI ids to env var names
        KEY_MAP = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_AI_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "virustotal": "VIRUSTOTAL_API_KEY",
            "hibp": "HIBP_API_KEY",
            "otx": "OTX_API_KEY",
            "urlscan": "URLSCAN_API_KEY",
            "censys": "CENSYS_API_ID",
            "intelx": "INTELX_API_KEY",
            "greynoise": "GREYNOISE_API_KEY",
            "binaryedge": "BINARYEDGE_API_KEY",
            "leakcheck": "LEAKCHECK_API_KEY",
            "spycloud": "SPYCLOUD_API_KEY",
            "recordedfuture": "RECORDED_FUTURE_KEY",
            "crowdstrike": "CROWDSTRIKE_CLIENT_ID",
            "mandiant": "MANDIANT_API_KEY",
            "flare": "FLARE_API_KEY",
            "cyberint": "CYBERINT_API_KEY",
            "socradar": "SOCRADAR_API_KEY",
            "grayhatwarfare": "GRAYHATWARFARE_API_KEY",
            "leakix": "LEAKIX_API_KEY",
            "github": "GITHUB_TOKEN",
            "pulsedive": "PULSEDIVE_API_KEY",
            "hudsonrock": "HUDSON_ROCK_API_KEY",
        }
        env_var = KEY_MAP.get(provider)
        if env_var:
            # Set in backend memory
            if hasattr(settings, env_var):
                setattr(settings, env_var, api_key)
            os.environ[env_var] = api_key
            
            # Forward to intel-proxy (where collectors actually run)
            import httpx
            proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
            try:
                async with httpx.AsyncClient(timeout=10.0) as c:
                    await c.post(f"{proxy_url}/settings/key",
                        json={"key": env_var, "value": api_key})
            except Exception:
                pass  # Intel-proxy may not have /settings/key yet
            
            # Also set AI provider settings specifically
            if provider == "anthropic":
                settings.ANTHROPIC_API_KEY = api_key
            elif provider == "openai":
                settings.OPENAI_API_KEY = api_key
            elif provider == "google":
                settings.GOOGLE_AI_API_KEY = api_key
            
            updated.append(provider)

    # Verify AI provider health
    from arguswatch.agent.agent_core import check_provider_health
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]

    # Auto-switch pipeline to the newly connected AI provider
    ai_providers = {"anthropic", "openai", "google"}
    if updated and updated[0] in active and updated[0] in ai_providers:
        from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis
        _set_active_provider_in_redis(updated[0])

    return {
        "updated": updated,
        "providers": health,
        "active": active,
        "recommended": active[0] if active else "ollama",
        "note": "Keys are active now. For persistence across restarts, also add to .env file.",
    }


@app.delete("/api/settings/ai-keys/{provider}", dependencies=_admin_deps)
async def remove_ai_key(provider: str):
    """Remove an AI provider API key at runtime. Auto-switches back to Local AI."""
    from arguswatch.config import settings
    if provider == "anthropic":
        settings.ANTHROPIC_API_KEY = ""
    elif provider == "openai":
        settings.OPENAI_API_KEY = ""
    elif provider == "google":
        settings.GOOGLE_AI_API_KEY = ""
    else:
        raise HTTPException(400, f"Unknown provider: {provider}")

    # Switch back to ollama
    from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis
    _set_active_provider_in_redis("ollama")

    from arguswatch.agent.agent_core import check_provider_health
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]
    return {"removed": provider, "providers": health, "active": active, "switched_to": "ollama"}


@app.get("/api/agent/status")
async def agent_status(db: AsyncSession = Depends(get_db)):
    """Full agentic AI system status."""
    from arguswatch.models import FPPattern, SectorAdvisory, DarkWebMention, CustomerExposure
    from sqlalchemy import func as _fn
    from arguswatch.services.ai_pipeline_hooks import _pipeline_ai_available
    fp_count = (await db.execute(select(_fn.count(FPPattern.id)))).scalar() or 0
    fp_hits = (await db.execute(select(_fn.sum(FPPattern.hit_count)))).scalar() or 0
    advisories = (await db.execute(
        select(_fn.count(SectorAdvisory.id)).where(SectorAdvisory.status == "active")
    )).scalar() or 0
    dw_triaged = (await db.execute(
        select(_fn.count(DarkWebMention.id)).where(DarkWebMention.triaged_at.isnot(None))
    )).scalar() or 0
    narratives = (await db.execute(
        select(_fn.count(CustomerExposure.id)).where(CustomerExposure.score_narrative.isnot(None))
    )).scalar() or 0
    return {
        "ai_available": _pipeline_ai_available(),
        "agents": {
            "fp_memory": {"status": "active", "patterns_learned": fp_count, "detections_auto_closed": fp_hits or 0},
            "darkweb_triage": {"status": "active", "mentions_triaged": dw_triaged, "schedule": "every 30 min"},
            "sector_detection": {"status": "active", "active_advisories": advisories, "schedule": "every 6 hours"},
            "exposure_narrative": {"status": "active", "narratives_generated": narratives},
            "campaign_killchain": {"status": "active", "description": "AI kill chain analysis on campaign creation"},
            "attribution_fallback": {"status": "active", "description": "AI reasoning when rules return nothing"},
            "raw_text_triage": {"status": "active", "description": "Raw source text fed to AI triage"},
        },
    }

