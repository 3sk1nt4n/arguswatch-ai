"""ArgusWatch Operations Routes -  Extracted from main.py"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, case, distinct, desc, text
from pydantic import BaseModel

from arguswatch.database import get_db
from arguswatch.auth import require_role
from arguswatch.config import settings
from arguswatch.models import (
    Detection, Finding, FindingRemediation, FindingSource, Customer, CustomerAsset,
    CustomerExposure, ThreatActor, Campaign, ActorIoc, DarkWebMention,
    Enrichment, SeverityLevel, DetectionStatus, ExposureHistory,
    FPPattern, SectorAdvisory, CollectorRun, GlobalThreatActivity,
    AssetType, CveProductMap,
)

logger = logging.getLogger("arguswatch.api.operations")


# Pydantic models for request validation
class EventIngestItem(BaseModel):
    customer_id: Optional[int] = None
    source: str = "webhook"
    event_type: str = "generic"
    hostname: Optional[str] = None
    process: Optional[str] = None
    destination_ip: Optional[str] = None
    bytes_transferred: Optional[int] = None
    raw: str = ""

class EventIngestRequest(BaseModel):
    events: list[EventIngestItem]

class ScanRequest(BaseModel):
    text: str

router = APIRouter(tags=["operations"])

_write_deps = [Depends(require_role("admin", "analyst"))]
_admin_deps = [Depends(require_role("admin"))]

@router.post("/api/collect/{collector}", dependencies=_write_deps)
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

@router.post("/api/collect-all", dependencies=_write_deps)
async def trigger_all_collectors():
    """Trigger ALL collectors via Intel Proxy, then auto-run full pipeline:
    collect -> correlate -> match all customers -> recalculate exposure scores."""
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


@router.post("/api/recon/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
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

@router.post("/api/match-intel/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def match_intel_endpoint(customer_id: int, db: AsyncSession = Depends(get_db)):
    """Manually trigger customer intel matching - searches ALL global detections
    for matches against this customer's assets."""
    from arguswatch.engine.customer_intel_matcher import match_customer_intel
    return await match_customer_intel(customer_id, db)



@router.post("/api/match-intel-all", dependencies=[Depends(require_role("admin", "analyst"))])
async def match_all_intel_endpoint(db: AsyncSession = Depends(get_db)):
    """Match ALL global detections against ALL customers' assets. No AI (fast)."""
    from arguswatch.engine.customer_intel_matcher import match_all_customers
    return await match_all_customers(db)



@router.post("/api/ingest/events", dependencies=[Depends(require_role("admin", "analyst"))])
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



@router.get("/api/collectors/status")
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


@router.post("/api/scan", dependencies=[Depends(require_role("admin", "analyst"))])
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


@router.get("/api/enterprise/status")
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
    except Exception as e:
        logger.debug(f"Suppressed: {e}")
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

@router.get("/api/debug/env-check")
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

@router.post("/api/enterprise/{source_id}/trigger", dependencies=[Depends(require_role("admin"))])
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

