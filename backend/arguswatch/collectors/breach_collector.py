"""Breach Collector - HIBP (3 endpoints) + BreachDirectory plaintext lookup.
HIBP costs $3.50/mo. BreachDirectory is free community tier.
Both degrade gracefully when API keys absent.
"""
import httpx, logging, asyncio
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, Customer, CustomerAsset
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.breach")

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
BREACHDIR_BASE = "https://breachdirectory.org/api"

async def check_hibp_domain(domain: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """HIBP /breacheddomain endpoint - returns all accounts breached for a domain."""
    headers = {"hibp-api-key": api_key, "User-Agent": "ArgusWatch/7.0"}
    try:
        r = await client.get(f"{HIBP_BASE}/breacheddomain/{domain}", headers=headers)
        if r.status_code == 404: return []
        if r.status_code == 401: return [{"error": "invalid_hibp_key"}]
        r.raise_for_status()
        return r.json() or []
    except Exception as e:
        logger.warning(f"HIBP domain {domain}: {e}"); return []

async def check_hibp_account(email: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """HIBP /breachedaccount endpoint - breaches for specific email."""
    headers = {"hibp-api-key": api_key, "User-Agent": "ArgusWatch/7.0"}
    try:
        r = await client.get(f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=false", headers=headers)
        if r.status_code == 404: return []
        r.raise_for_status()
        return r.json() or []
    except Exception as e:
        logger.warning(f"HIBP account {email}: {e}"); return []

async def check_hibp_paste(email: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """HIBP /pasteaccount endpoint - pastes containing email."""
    headers = {"hibp-api-key": api_key, "User-Agent": "ArgusWatch/7.0"}
    try:
        r = await client.get(f"{HIBP_BASE}/pasteaccount/{email}", headers=headers)
        if r.status_code == 404: return []
        r.raise_for_status()
        return r.json() or []
    except Exception as e:
        logger.warning(f"HIBP paste {email}: {e}"); return []

async def check_breachdirectory(term: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """BreachDirectory - plaintext password recovery, free tier."""
    if not api_key: return []
    try:
        r = await client.get(f"{BREACHDIR_BASE}/?func=auto&term={term}",
            headers={"Authorization": f"Token {api_key}", "User-Agent": "ArgusWatch/7.0"})
        if r.status_code in (401, 403): return []
        r.raise_for_status()
        data = r.json()
        return data.get("result", []) or []
    except Exception as e:
        logger.warning(f"BreachDirectory {term}: {e}"); return []

async def run_collection() -> dict:
    hibp_key = getattr(settings, "HIBP_API_KEY", "") or ""
    bd_key = getattr(settings, "BREACHDIRECTORY_API_KEY", "") or ""
    if not hibp_key and not bd_key:
        return {"skipped": "no_keys", "note": "Add HIBP_API_KEY ($3.50/mo) and/or BREACHDIRECTORY_API_KEY to .env"}

    stats = {"domains_checked": 0, "emails_checked": 0, "new": 0, "skipped": 0,
             "hibp_breaches": 0, "hibp_pastes": 0, "breachdirectory_hits": 0}

    async with async_session() as db:
        # Get all customer email and domain assets
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["email", "domain"])))
        assets = r.scalars().all()
        r2 = await db.execute(select(Customer).where(Customer.active == True))
        customers = {c.id: c for c in r2.scalars().all()}

        async with httpx.AsyncClient(timeout=20.0) as client:
            for asset in assets:
                val = asset.asset_value
                cust = customers.get(asset.customer_id)

                if asset.asset_type == "domain" and hibp_key:
                    stats["domains_checked"] += 1
                    breaches = await check_hibp_domain(val, hibp_key, client)
                    if breaches and not isinstance(breaches[0], dict) or (breaches and "error" not in str(breaches[0])):
                        for acct, breach_names in (breaches.items() if isinstance(breaches, dict) else []):
                            ioc_val = f"{acct}@{val}"
                            r3 = await db.execute(select(Detection).where(
                                Detection.ioc_value == ioc_val, Detection.source == "hibp_domain"))
                            if r3.scalar_one_or_none():
                                stats["skipped"] += 1; continue
                            stats["hibp_breaches"] += 1
                            db.add(Detection(
                                source="hibp_domain", ioc_type="email_password_combo",
                                ioc_value=ioc_val, customer_id=asset.customer_id,
                                matched_asset=val,
                                raw_text=f"HIBP domain breach: {acct}@{val} in {len(breach_names) if isinstance(breach_names, list) else 1} breaches",
                                severity=SeverityLevel.HIGH, sla_hours=8,
                                status=DetectionStatus.NEW, confidence=0.95,
                                metadata_={"breaches": breach_names if isinstance(breach_names, list) else [breach_names],
                                           "endpoint": "breacheddomain"},
                            ))
                            stats["new"] += 1

                elif asset.asset_type == "email" and hibp_key:
                    stats["emails_checked"] += 1
                    # Check account breaches
                    acct_breaches = await check_hibp_account(val, hibp_key, client)
                    for breach in acct_breaches:
                        ioc_val = f"{val}|hibp|{breach.get('Name','')}"
                        r3 = await db.execute(select(Detection).where(
                            Detection.ioc_value == ioc_val, Detection.source == "hibp_account"))
                        if r3.scalar_one_or_none():
                            stats["skipped"] += 1; continue
                        stats["hibp_breaches"] += 1
                        db.add(Detection(
                            source="hibp_account", ioc_type="email_password_combo",
                            ioc_value=val, customer_id=asset.customer_id,
                            matched_asset=val,
                            raw_text=f"HIBP account breach: {val} in {breach.get('Name','')}",
                            severity=SeverityLevel.HIGH, sla_hours=8,
                            status=DetectionStatus.NEW, confidence=0.9,
                            metadata_={"breach_name": breach.get("Name",""), "breach_date": breach.get("BreachDate",""),
                                       "data_classes": breach.get("DataClasses",[]), "is_verified": breach.get("IsVerified",False)},
                        ))
                        stats["new"] += 1
                    # Check pastes
                    pastes = await check_hibp_paste(val, hibp_key, client)
                    for paste in pastes[:5]:
                        stats["hibp_pastes"] += 1
                        paste_id = paste.get("Id","")
                        ioc_val = f"{val}|paste|{paste_id}"
                        r3 = await db.execute(select(Detection).where(
                            Detection.ioc_value == ioc_val, Detection.source == "hibp_paste"))
                        if r3.scalar_one_or_none():
                            stats["skipped"] += 1; continue
                        db.add(Detection(
                            source="hibp_paste", ioc_type="email",
                            ioc_value=val, customer_id=asset.customer_id,
                            matched_asset=val,
                            raw_text=f"HIBP paste: {val} found in paste {paste.get('Source','')}",
                            severity=SeverityLevel.HIGH, sla_hours=12,
                            status=DetectionStatus.NEW, confidence=0.85,
                            metadata_={"paste_id": paste_id, "source": paste.get("Source",""),
                                       "title": paste.get("Title",""), "date": paste.get("Date","")},
                        ))
                        stats["new"] += 1

                # BreachDirectory check for email assets
                if asset.asset_type == "email" and bd_key:
                    bd_results = await check_breachdirectory(val, bd_key, client)
                    for hit in bd_results[:10]:
                        password = hit.get("password", hit.get("hash",""))
                        ioc_val = f"{val}:{password}"
                        r3 = await db.execute(select(Detection).where(
                            Detection.ioc_value == ioc_val[:200], Detection.source == "breachdirectory"))
                        if r3.scalar_one_or_none():
                            stats["skipped"] += 1; continue
                        is_plaintext = bool(hit.get("password"))
                        stats["breachdirectory_hits"] += 1
                        db.add(Detection(
                            source="breachdirectory", ioc_type="breachdirectory_combo",
                            ioc_value=ioc_val[:200], customer_id=asset.customer_id,
                            matched_asset=val,
                            raw_text=f"BreachDirectory: {val} with {'plaintext' if is_plaintext else 'hash'} password",
                            severity=SeverityLevel.CRITICAL if is_plaintext else SeverityLevel.HIGH,
                            sla_hours=4 if is_plaintext else 8,
                            status=DetectionStatus.NEW,
                            confidence=0.95 if is_plaintext else 0.80,
                            metadata_={"has_plaintext": is_plaintext, "source_name": hit.get("sources",""),
                                       "hash_type": hit.get("hash_type",""), "sha1": hit.get("sha1","")},
                        ))
                        stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"Breach ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.breach_collector.collect_breach")
def collect_breach():
    async def _wrapped():
        async with record_collector_run("breach") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
