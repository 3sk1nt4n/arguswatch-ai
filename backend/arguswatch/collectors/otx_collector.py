"""AlienVault OTX Collector - public pulses, no API key for basic feed.

V11: Also writes actor IOCs to actor_iocs table.
OTX pulses include:
 - adversary: the threat actor attributed to this pulse
 - indicators: the actual IOCs
When a pulse has adversary set, every indicator becomes an actor_ioc row.
This is the primary source for populating actor_iocs (MITRE ATT&CK Enterprise
JSON doesn't include STIX indicator objects in the public feed).
"""
import httpx, logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, ActorIoc, ThreatActor
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.otx")

OTX_BASE = "https://otx.alienvault.com"

# OTX indicator type -> our ioc_type
OTX_TYPE_MAP = {
    "ipv4":            "ipv4",
    "ipv6":            "ipv6",
    "domain":          "domain",
    "hostname":        "fqdn",
    "url":             "url",
    "fileHash-md5":    "md5",
    "fileHash-sha256": "sha256",
    "fileHash-sha1":   "sha1",
    "email":           "email",
    "cidr":            "cidr",
}

# IOC type -> inferred role in a campaign
IOC_ROLE_MAP = {
    "ipv4": "c2", "ipv6": "c2", "cidr": "c2",
    "domain": "c2", "fqdn": "c2", "url": "dropper",
    "md5": "dropper", "sha256": "dropper", "sha1": "dropper",
    "email": "phishing",
}


async def _get_or_create_actor(actor_name: str, db) -> int | None:
    """Get actor_id for an actor name, creating a stub ThreatActor if needed."""
    if not actor_name or len(actor_name.strip()) < 3:
        return None
    name = actor_name.strip()
    r = await db.execute(select(ThreatActor).where(ThreatActor.name == name))
    actor = r.scalar_one_or_none()
    if actor:
        return actor.id
    # Create stub - MITRE collector will fill details later if it finds a match
    actor = ThreatActor(name=name, source="otx", description=f"Actor stub from OTX pulse attribution")
    db.add(actor)
    await db.flush()
    return actor.id


async def run_collection() -> dict:
    headers = {}
    if settings.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = settings.OTX_API_KEY
    since = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    url = f"{OTX_BASE}/api/v1/pulses/subscribed?modified_since={since}&limit=50"
    stats = {
        "pulses": 0, "iocs": 0, "new": 0, "skipped": 0,
        "actor_iocs_added": 0, "actor_iocs_skipped": 0, "actors_seen": set(),
    }
    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            resp = await client.get(url)
            if resp.status_code == 401:
                logger.info("OTX: no API key - skipping")
                return {"skipped": "no_api_key"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"OTX fetch error: {e}")
        return {"error": str(e)}

    async with async_session() as db:
        for pulse in data.get("results", []):
            stats["pulses"] += 1
            pulse_id = pulse.get("id", "")
            pulse_name = pulse.get("name", "")
            tags = pulse.get("tags", [])
            tlp = pulse.get("tlp", "white")
            adversary = (pulse.get("adversary") or "").strip()

            # ── Actor IOC extraction ──────────────────────────────────────
            actor_id = None
            if adversary:
                actor_id = await _get_or_create_actor(adversary, db)
                if actor_id:
                    stats["actors_seen"].add(adversary)

            # ── Detection ingest + actor_iocs population ──────────────────
            for ind in pulse.get("indicators", []):
                ioc_val = ind.get("indicator", "")
                otx_type = ind.get("type", "")
                ioc_type = OTX_TYPE_MAP.get(otx_type, otx_type.lower().replace(" ", "_"))
                if not ioc_val:
                    continue
                stats["iocs"] += 1

                # Standard detection row
                r = await db.execute(
                    select(Detection).where(
                        Detection.ioc_value == ioc_val,
                        Detection.source == "otx",
                    )
                )
                if not r.scalar_one_or_none():
                    db.add(Detection(
                        source="otx", ioc_type=ioc_type, ioc_value=ioc_val,
                        raw_text=pulse_name,
                        severity=SeverityLevel.MEDIUM, sla_hours=48,
                        status=DetectionStatus.NEW, confidence=0.75,
                        metadata_={
                            "pulse_id": pulse_id, "pulse_name": pulse_name,
                            "adversary": adversary or None,
                            "tags": tags, "tlp": tlp,
                        },
                    ))
                    stats["new"] += 1
                else:
                    stats["skipped"] += 1

                # actor_iocs row - only when adversary is attributed
                if actor_id and adversary:
                    r2 = await db.execute(
                        select(ActorIoc).where(
                            ActorIoc.actor_id == actor_id,
                            ActorIoc.ioc_value == ioc_val,
                        ).limit(1)
                    )
                    if r2.scalar_one_or_none():
                        stats["actor_iocs_skipped"] += 1
                    else:
                        role = IOC_ROLE_MAP.get(ioc_type, "infrastructure")
                        db.add(ActorIoc(
                            actor_id=actor_id,
                            actor_name=adversary,
                            ioc_type=ioc_type,
                            ioc_value=ioc_val,
                            ioc_role=role,
                            confidence=0.75,
                            source="otx",
                        ))
                        stats["actor_iocs_added"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)

    # Convert set to list for JSON serialisation
    stats["actors_seen"] = list(stats["actors_seen"])
    logger.info(f"OTX ingest: {stats}")
    return stats


@celery_app.task(name="arguswatch.collectors.otx_collector.collect_otx")
def collect_otx():
    import asyncio
    async def _wrapped():
        async with record_collector_run("otx") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
