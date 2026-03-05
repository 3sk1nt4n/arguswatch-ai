"""ArgusWatch AI Agent - 10 tools spec-exact.
Tools: query_database, enrich_ioc, check_breach, search_paste_sites,
       search_telegram, generate_report, update_alert_status,
       calculate_risk_score, search_github, explain_ioc
"""
import asyncio, logging, httpx
from datetime import datetime
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, Customer, CustomerAsset, RemediationAction, DetectionStatus, SeverityLevel
from arguswatch.engine.exposure_scorer import get_customer_risk_summary
from arguswatch.engine.playbooks import get_playbook, render_playbook_text
from sqlalchemy import select, func, desc, and_

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.agent.tools")

# ── Tool 1: query_database ──
async def query_database(query: str, customer_name: str = "", severity: str = "",
                          status: str = "", limit: int = 20) -> dict:
    """Search detections, assets, customers by any criteria."""
    async with async_session() as db:
        q = select(Detection).order_by(desc(Detection.created_at)).limit(limit)
        filters = []
        if customer_name:
            r = await db.execute(select(Customer).where(Customer.name.ilike(f"%{customer_name}%")))
            cust = r.scalar_one_or_none()
            if cust: filters.append(Detection.customer_id == cust.id)
        if severity:
            try: filters.append(Detection.severity == SeverityLevel(severity.upper()))
            except ValueError: pass
        if status:
            try: filters.append(Detection.status == DetectionStatus(status.upper()))
            except ValueError: pass
        if query:
            filters.append(Detection.ioc_value.ilike(f"%{query}%") |
                          Detection.raw_text.ilike(f"%{query}%"))
        if filters:
            from sqlalchemy import and_
            q = q.where(and_(*filters))
        r = await db.execute(q)
        items = r.scalars().all()
        return {
            "count": len(items),
            "results": [{
                "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value[:100],
                "severity": _sev(d.severity) or None,
                "source": d.source, "status": d.status.value if d.status else None,
                "customer_id": d.customer_id,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            } for d in items]
        }

# ── Tool 2: enrich_ioc ──
async def enrich_ioc(ioc_value: str, ioc_type: str = "") -> dict:
    """VirusTotal + AbuseIPDB + OTX enrichment for any IOC on demand."""
    results = {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        # VirusTotal
        vt_key = settings.VIRUSTOTAL_API_KEY
        if vt_key:
            try:
                endpoint = {"ipv4": f"ip_addresses/{ioc_value}",
                            "domain": f"domains/{ioc_value}",
                            "url": f"urls/{httpx.URL(ioc_value).__bytes__().hex()}",
                            "sha256": f"files/{ioc_value}"}.get(ioc_type, f"domains/{ioc_value}")
                r = await client.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                    headers={"x-apikey": vt_key})
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    results["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "total": sum(stats.values()),
                        "reputation": data.get("reputation", 0),
                    }
            except Exception as e:
                results["virustotal"] = {"error": str(e)}

        # AbuseIPDB
        abuse_key = settings.ABUSEIPDB_API_KEY
        if abuse_key and ioc_type == "ipv4":
            try:
                r = await client.get("https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ioc_value, "maxAgeInDays": 90})
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    results["abuseipdb"] = {
                        "abuse_score": d.get("abuseConfidenceScore", 0),
                        "country": d.get("countryCode",""),
                        "isp": d.get("isp",""),
                        "total_reports": d.get("totalReports", 0),
                        "is_whitelisted": d.get("isWhitelisted", False),
                    }
            except Exception as e:
                results["abuseipdb"] = {"error": str(e)}

        # OTX
        otx_key = settings.OTX_API_KEY
        if otx_key:
            try:
                section = {"ipv4": "IPv4","domain": "domain","sha256": "file","url": "url"}.get(ioc_type,"IPv4")
                r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc_value}/general",
                    headers={"X-OTX-API-KEY": otx_key})
                if r.status_code == 200:
                    d = r.json()
                    results["otx"] = {
                        "pulse_count": d.get("pulse_info",{}).get("count", 0),
                        "reputation": d.get("reputation", 0),
                        "country": d.get("country_name",""),
                    }
            except Exception as e:
                results["otx"] = {"error": str(e)}

    results["ioc"] = ioc_value
    results["type"] = ioc_type
    return results

# ── Tool 3: check_breach ──
async def check_breach(email_or_domain: str) -> dict:
    """HIBP 3 endpoints + BreachDirectory plaintext lookup."""
    results = {"hibp": {}, "breachdirectory": {}}
    hibp_key = settings.HIBP_API_KEY if hasattr(settings, "HIBP_API_KEY") else ""
    bd_key = getattr(settings, "BREACHDIRECTORY_API_KEY", "")
    headers = {"hibp-api-key": hibp_key, "User-Agent": "ArgusWatch/7.0"} if hibp_key else {}

    async with httpx.AsyncClient(timeout=15.0) as client:
        if hibp_key:
            is_email = "@" in email_or_domain
            if is_email:
                try:
                    r = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_or_domain}",
                        headers=headers)
                    if r.status_code == 200:
                        results["hibp"]["account_breaches"] = len(r.json() or [])
                except Exception: pass
                try:
                    r = await client.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{email_or_domain}",
                        headers=headers)
                    if r.status_code == 200:
                        results["hibp"]["pastes"] = len(r.json() or [])
                except Exception: pass
            else:
                try:
                    r = await client.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{email_or_domain}",
                        headers=headers)
                    if r.status_code == 200:
                        d = r.json() or {}
                        results["hibp"]["domain_accounts_breached"] = len(d)
                except Exception: pass

        if bd_key and "@" in email_or_domain:
            try:
                r = await client.get(f"https://breachdirectory.org/api/?func=auto&term={email_or_domain}",
                    headers={"Authorization": f"Token {bd_key}"})
                if r.status_code == 200:
                    d = r.json()
                    hits = d.get("result", [])
                    plaintext_count = sum(1 for h in hits if h.get("password"))
                    results["breachdirectory"] = {
                        "total_hits": len(hits),
                        "plaintext_passwords": plaintext_count,
                        "has_plaintext": plaintext_count > 0,
                    }
            except Exception: pass

    return results

# ── Tool 4: search_paste_sites ──
async def search_paste_sites(search_term: str) -> dict:
    """On-demand paste search outside normal schedule."""
    results = []
    async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ArgusWatch/7.0"}) as client:
        # Search psbdmp (public paste archive)
        try:
            r = await client.get(f"https://psbdmp.ws/api/search/{search_term}")
            if r.status_code == 200:
                data = r.json()
                pastes = data.get("data", []) if isinstance(data, dict) else []
                for p in pastes[:5]:
                    results.append({"source": "psbdmp", "title": p.get("text","")[:100],
                                   "url": p.get("url",""), "date": p.get("time","")})
        except Exception: pass
    return {"term": search_term, "results": results, "count": len(results)}

# ── Tool 5: search_telegram ──
async def search_telegram(keyword: str, channel: str = "") -> dict:
    """Query monitored channel history by keyword."""
    api_id = getattr(settings, "TELEGRAM_API_ID", "")
    api_hash = getattr(settings, "TELEGRAM_API_HASH", "")
    if not api_id or not api_hash:
        return {"skipped": "no_credentials", "note": "Add TELEGRAM_API_ID/HASH to .env"}
    try:
        from telethon import TelegramClient
        client = TelegramClient("arguswatch_search", int(api_id), api_hash)
        await client.start()
        results = []
        target = channel or "darkwebinformer"
        async for msg in client.iter_messages(target, limit=100, search=keyword):
            results.append({"text": (msg.text or "")[:200], "date": str(msg.date), "id": msg.id})
        await client.disconnect()
        return {"keyword": keyword, "channel": target, "count": len(results), "results": results[:10]}
    except Exception as e:
        return {"error": str(e)}

# ── Tool 6: generate_report ──
async def generate_report(customer_name: str, period_days: int = 30) -> dict:
    """Trigger PDF report generation for a customer."""
    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.name.ilike(f"%{customer_name}%")))
        customer = r.scalar_one_or_none()
        if not customer:
            return {"error": f"Customer '{customer_name}' not found"}
        risk = await get_customer_risk_summary(customer.id, db)
    # Trigger async report generation
    from arguswatch.services.report_generator import generate_pdf_report
    report_path = await generate_pdf_report(customer.id, period_days)
    return {"status": "generated", "customer": customer_name, "path": report_path,
            "risk_summary": risk}

# ── Tool 7: update_alert_status ──
async def update_alert_status(detection_id: int, new_status: str,
                               notes: str = "", assignee: str = "") -> dict:
    """Mark detection: reviewing / remediated / false_positive. Triggers 72h re-check if remediated."""
    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": f"Detection {detection_id} not found"}
        try:
            det.status = DetectionStatus(new_status.upper())
        except ValueError:
            return {"error": f"Invalid status: {new_status}"}
        if new_status.upper() == "REMEDIATED":
            det.resolved_at = datetime.utcnow()
            # Create playbook-based remediation action
            pb = get_playbook(det.ioc_type, det.source)
            if pb:
                action = RemediationAction(
                    detection_id=detection_id,
                    action_type="remediated",
                    description=f"Resolved: {pb.title}",
                    assigned_to=assignee or pb.assignee_role,
                    status="completed",
                )
                db.add(action)
            # Schedule 72h re-check via celery
            try:
                from arguswatch.services.recheck_scheduler import schedule_recheck
                schedule_recheck(detection_id, det.customer_id, det.ioc_type, det.ioc_value)
            except Exception: pass
        elif new_status.upper() == "FALSE_POSITIVE":
            det.resolved_at = datetime.utcnow()
        await db.commit()
        return {"detection_id": detection_id, "new_status": new_status, "recheck_scheduled": new_status.upper() == "REMEDIATED"}

# ── Tool 8: calculate_risk_score ──
async def calculate_risk_score(customer_name: str) -> dict:
    """Weighted risk score for any customer from exposure scoring engine."""
    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.name.ilike(f"%{customer_name}%")))
        customer = r.scalar_one_or_none()
        if not customer:
            return {"error": f"Customer '{customer_name}' not found"}
        return await get_customer_risk_summary(customer.id, db)

# ── Tool 9: search_github ──
async def search_github(customer_domain: str, org_name: str = "") -> dict:
    """On-demand GitHub + pattern search for customer assets."""
    token = settings.GITHUB_TOKEN if hasattr(settings, "GITHUB_TOKEN") else \
            getattr(settings, "VIRUSTOTAL_API_KEY", "")  # placeholder
    headers = {"Accept": "application/vnd.github.v3+json"}
    results = []
    queries = [customer_domain]
    if org_name: queries.append(org_name)
    async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
        for q in queries[:2]:
            try:
                r = await client.get("https://api.github.com/search/code",
                    params={"q": f"{q} extension:env OR extension:config OR extension:yml", "per_page": 10})
                if r.status_code in (403, 422): break
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        results.append({
                            "repo": item.get("repository",{}).get("full_name",""),
                            "file": item.get("name",""),
                            "url": item.get("html_url",""),
                        })
            except Exception: pass
    return {"query": customer_domain, "results": results, "count": len(results)}

# ── Tool 10: explain_ioc ──
async def explain_ioc(ioc_value: str, ioc_type: str = "", context: str = "") -> dict:
    """Plain English explanation of any IOC, detection, or finding."""
    pb = get_playbook(ioc_type)
    enrichment = await enrich_ioc(ioc_value, ioc_type)
    explanation = {
        "ioc": ioc_value,
        "type": ioc_type,
        "what_it_is": {
            "aws_access_key": "AWS API key - grants programmatic access to AWS services",
            "email_password_combo": "Credential pair - email + password found in breach data",
            "ipv4": "IP address - potentially malicious C2 or botnet node",
            "cve_id": "Known vulnerability - may be actively exploited",
            "sha256": "File hash - fingerprint of potentially malicious file",
            "domain": "Domain name - potentially phishing or malicious",
        }.get(ioc_type, f"IOC of type {ioc_type}"),
        "business_risk": pb.title if pb else "Unknown risk",
        "recommended_action": pb.technical_steps[0].step if pb and pb.technical_steps else "Investigate",
        "sla": f"{pb.sla_hours}h" if pb else "72h",
        "enrichment_summary": {
            "vt_malicious": enrichment.get("virustotal",{}).get("malicious", "N/A"),
            "abuse_score": enrichment.get("abuseipdb",{}).get("abuse_score", "N/A"),
        }
    }
    return explanation

# Tool registry for agent

# ══════════════════════════════════════════════════════════════════════
# GAP 6: ONBOARD CUSTOMER - create customer + assets in one call
# ══════════════════════════════════════════════════════════════════════

async def onboard_customer(
    name: str,
    industry: str = "",
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    emails: list[str] | None = None,
    keywords: list[str] | None = None,
    tech_stack: list[str] | None = None,
    tier: str = "standard",
) -> dict:
    """Create a new customer and register their assets in one step.
    Also triggers retroactive correlation to catch missed detections."""
    from arguswatch.database import async_session
    from arguswatch.models import Customer, CustomerAsset, AssetType
    from sqlalchemy import select

    async with async_session() as db:
        # Check if customer already exists
        r = await db.execute(select(Customer).where(Customer.name == name))
        existing = r.scalar_one_or_none()
        if existing:
            cid = existing.id
            created_customer = False
        else:
            c = Customer(name=name, industry=industry, tier=tier)
            db.add(c)
            await db.flush()
            cid = c.id
            created_customer = True

        # Add assets (skip duplicates)
        er = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == cid))
        existing_assets = {(a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type,
                           a.asset_value) for a in er.scalars().all()}
        added = 0
        asset_map = {
            "domain": domains or [],
            "ip": ips or [],
            "email": emails or [],
            "keyword": keywords or [],
            "tech_stack": tech_stack or [],
        }
        for atype, values in asset_map.items():
            for val in values:
                val = val.strip()
                if not val:
                    continue
                if (atype, val) not in existing_assets:
                    db.add(CustomerAsset(
                        customer_id=cid,
                        asset_type=AssetType(atype),
                        asset_value=val,
                        criticality="critical" if atype in ("domain", "ip") else "high",
                    ))
                    existing_assets.add((atype, val))
                    added += 1
        await db.commit()

        # Trigger retroactive correlation
        retro = 0
        try:
            from arguswatch.engine.correlation_engine import route_detection
            from arguswatch.models import Detection
            ur = await db.execute(
                select(Detection).where(Detection.customer_id == None).limit(200)
            )
            for det in ur.scalars().all():
                matched = await route_detection(det, db)
                if matched and det.customer_id == cid:
                    retro += 1
            await db.commit()
        except Exception:
            pass

        return {
            "customer_id": cid,
            "customer_created": created_customer,
            "assets_added": added,
            "retroactive_matches": retro,
            "name": name,
            "industry": industry,
        }


async def check_customer_completeness(customer_name: str = "", customer_id: int = 0) -> dict:
    """Check which asset categories are missing for a customer - reveals blind spots."""
    from arguswatch.database import async_session
    from arguswatch.models import Customer, CustomerAsset
    from sqlalchemy import select

    async with async_session() as db:
        if customer_id:
            r = await db.execute(select(Customer).where(Customer.id == customer_id))
        else:
            r = await db.execute(select(Customer).where(Customer.name.ilike(f"%{customer_name}%")).limit(1))
        c = r.scalar_one_or_none()
        if not c:
            return {"error": f"Customer not found: {customer_name or customer_id}"}

        ar = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == c.id))
        assets = ar.scalars().all()
        CATEGORIES = {
            "domain": "IOC-to-customer routing for domains/subdomains",
            "ip": "IP address exact matching",
            "email": "Credential leak and phishing detection",
            "keyword": "Brand mention monitoring across all feeds",
            "cidr": "IP range matching for cloud/office blocks",
            "org_name": "Organization name in WHOIS, certs, pastes",
            "github_org": "Code leak and exposed repo detection",
            "subdomain": "Subdomain takeover and shadow IT detection",
            "tech_stack": "CVE-to-customer routing (CRITICAL for KEV alerts)",
            "brand_name": "Typosquat domain detection",
            "exec_name": "VIP credential leak and impersonation detection",
            "cloud_asset": "Cloud bucket/resource exposure correlation",
        }
        filled = set(a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type for a in assets)
        missing = {k: v for k, v in CATEGORIES.items() if k not in filled}
        pct = round(len(filled) / len(CATEGORIES) * 100)
        return {
            "customer": c.name,
            "customer_id": c.id,
            "completeness_pct": pct,
            "total_assets": len(assets),
            "filled_categories": list(filled),
            "missing_categories": missing,
            "blind_spots": [f"⚠️ {k}: {v}" for k, v in missing.items()],
        }


async def search_related_findings(
    ioc_value: str = "",
    ioc_type: str = "",
    actor_name: str = "",
    customer_id: int = 0,
) -> dict:
    """Find historical findings related to this IOC or actor using DB retrieval."""
    try:
        from arguswatch.services.ai_rag_context import find_related_findings, get_actor_intelligence
        from arguswatch.database import async_session
        async with async_session() as db:
            related = await find_related_findings(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                customer_id=customer_id or None,
                actor_name=actor_name or None,
                finding_id=None,
                db=db,
                limit=10,
            )
            actor_intel = {}
            if actor_name:
                actor_intel = await get_actor_intelligence(actor_name, db)
        return {
            "related_findings": related,
            "related_count": len(related),
            "actor_intelligence": actor_intel,
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════
# TOOL SCHEMAS - OpenAI-compatible function definitions
# Used by agent_core.py for native tool calling on all providers.
# ══════════════════════════════════════════════════════════════════════

TOOL_REGISTRY = {
    "query_database": query_database,
    "enrich_ioc": enrich_ioc,
    "check_breach": check_breach,
    "search_paste_sites": search_paste_sites,
    "search_telegram": search_telegram,
    "generate_report": generate_report,
    "update_alert_status": update_alert_status,
    "calculate_risk_score": calculate_risk_score,
    "search_github": search_github,
    "explain_ioc": explain_ioc,
    "search_related_findings": search_related_findings,
    "onboard_customer": onboard_customer,
    "check_customer_completeness": check_customer_completeness,
}


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "Search live threat detections in the ArgusWatch database. Returns real IOCs, severities, and statuses.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term for IOC value or raw text"},
                    "customer_name": {"type": "string", "description": "Filter by customer name (partial match)"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "description": "Filter by severity"},
                    "status": {"type": "string", "enum": ["NEW", "REVIEWING", "REMEDIATED", "FALSE_POSITIVE", "VERIFIED_CLOSED"], "description": "Filter by status"},
                    "limit": {"type": "integer", "description": "Max results to return (default 20, max 100)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": "Run real-time enrichment on an IOC: VirusTotal detection count, AbuseIPDB score, OTX pulse count. Returns live data from threat intel APIs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "The IOC to enrich (IP, domain, hash, URL)"},
                    "ioc_type": {"type": "string", "enum": ["ipv4", "domain", "sha256", "md5", "url"], "description": "Type of IOC"},
                },
                "required": ["ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_breach",
            "description": "Check if an email or domain appears in known breaches via HIBP and BreachDirectory. Returns breach counts and plaintext password exposure.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email_or_domain": {"type": "string", "description": "Email address or domain to check"},
                },
                "required": ["email_or_domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_risk_score",
            "description": "Get the current exposure risk score for a customer. Returns weighted score (0-100) with factor breakdown.",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_name": {"type": "string", "description": "Customer name (partial match OK)"},
                },
                "required": ["customer_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_alert_status",
            "description": "Update the status of a detection. Use to mark detections as reviewed, remediated, or false positive.",
            "parameters": {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "integer", "description": "Detection ID to update"},
                    "new_status": {"type": "string", "enum": ["REVIEWING", "REMEDIATED", "FALSE_POSITIVE"], "description": "New status"},
                    "notes": {"type": "string", "description": "Optional analyst notes"},
                    "assignee": {"type": "string", "description": "Optional assignee name"},
                },
                "required": ["detection_id", "new_status"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate a PDF threat intelligence report for a customer covering a time period.",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_name": {"type": "string", "description": "Customer name"},
                    "period_days": {"type": "integer", "description": "Number of days to cover (default 30)"},
                },
                "required": ["customer_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_github",
            "description": "Search GitHub for exposed secrets, config files, or credentials matching a customer domain or org name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_domain": {"type": "string", "description": "Customer domain (e.g. acme.com)"},
                    "org_name": {"type": "string", "description": "Optional GitHub org name"},
                },
                "required": ["customer_domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_paste_sites",
            "description": "Search paste sites for a keyword (email, domain, company name). Returns paste matches with URLs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search_term": {"type": "string", "description": "Search term"},
                },
                "required": ["search_term"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_ioc",
            "description": "Get a plain English explanation of what an IOC means, its business risk, and recommended action.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "The IOC value"},
                    "ioc_type": {"type": "string", "description": "IOC type"},
                    "context": {"type": "string", "description": "Optional additional context"},
                },
                "required": ["ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_telegram",
            "description": "Search monitored Telegram channels for threat intel matching a keyword.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Keyword to search"},
                    "channel": {"type": "string", "description": "Optional specific channel name"},
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_related_findings",
            "description": "Find historical findings related to this IOC or actor. Returns related threats from the past 90 days with relevance scores, plus full actor intelligence (techniques, targets, MITRE ID).",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "IOC value to find related findings for"},
                    "ioc_type": {"type": "string", "description": "IOC type (ipv4, domain, sha256, etc.)"},
                    "actor_name": {"type": "string", "description": "Threat actor name for actor intelligence"},
                    "customer_id": {"type": "integer", "description": "Customer ID to scope search"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "onboard_customer",
            "description": "Create a new customer and register their assets in one step. Also triggers retroactive correlation to catch previously missed detections. Use this when the analyst says 'set up monitoring for X' or 'add customer X'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Customer name (required)"},
                    "industry": {"type": "string", "description": "Industry sector (Finance, Healthcare, Technology, etc.)"},
                    "domains": {"type": "array", "items": {"type": "string"}, "description": "Domain names to monitor (e.g. ['acme.com', 'acme.io'])"},
                    "ips": {"type": "array", "items": {"type": "string"}, "description": "IP addresses to monitor"},
                    "emails": {"type": "array", "items": {"type": "string"}, "description": "Email addresses or patterns to monitor"},
                    "keywords": {"type": "array", "items": {"type": "string"}, "description": "Keywords for brand monitoring"},
                    "tech_stack": {"type": "array", "items": {"type": "string"}, "description": "Technologies to match CVEs against (e.g. ['FortiOS 7.2', 'Apache 2.4'])"},
                    "tier": {"type": "string", "enum": ["standard", "professional", "enterprise"], "description": "Service tier"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_customer_completeness",
            "description": "Check which asset categories are missing for a customer, revealing blind spots in threat detection. Shows what types of threats will be missed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_name": {"type": "string", "description": "Customer name (partial match)"},
                    "customer_id": {"type": "integer", "description": "Customer ID"},
                },
            },
        },
    },
]
