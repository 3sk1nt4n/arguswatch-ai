"""MITRE ATT&CK Collector - 138+ threat actor groups with techniques and IOCs.

V11: Also populates actor_iocs table from group external references.
MITRE ATT&CK groups include known C2 domains, IPs, and malware hashes
in their external references and indicator relationships.
"""
import httpx, logging, re
from functools import lru_cache
from sqlalchemy import select, create_engine
from sqlalchemy.orm import sessionmaker
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import ThreatActor, ActorIoc
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import record_collector_run

logger = logging.getLogger("arguswatch.collectors.mitre")

# ── Description parsers for enriching actor metadata ──
_COUNTRY_MAP = {
    "china": "China", "chinese": "China", "prc": "China",
    "russia": "Russia", "russian": "Russia",
    "iran": "Iran", "iranian": "Iran",
    "north korea": "North Korea", "dprk": "North Korea", "north korean": "North Korea",
    "south korea": "South Korea",
    "vietnam": "Vietnam", "vietnamese": "Vietnam",
    "pakistan": "Pakistan", "pakistani": "Pakistan",
    "india": "India", "indian": "India",
    "turkey": "Turkey", "turkish": "Turkey",
    "israel": "Israel", "israeli": "Israel",
    "lebanon": "Lebanon", "lebanese": "Lebanon",
    "nigeria": "Nigeria", "nigerian": "Nigeria",
    "ukraine": "Ukraine", "ukrainian": "Ukraine",
    "gaza": "Palestine", "palestinian": "Palestine",
}
_COUNTRY_FLAGS = {
    "China": "🇨🇳", "Russia": "🇷🇺", "Iran": "🇮🇷", "North Korea": "🇰🇵",
    "South Korea": "🇰🇷", "Vietnam": "🇻🇳", "Pakistan": "🇵🇰", "India": "🇮🇳",
    "Turkey": "🇹🇷", "Israel": "🇮🇱", "Lebanon": "🇱🇧", "Nigeria": "🇳🇬",
    "Ukraine": "🇺🇦", "Palestine": "🇵🇸",
}

def _guess_country(desc: str) -> str:
    if not desc: return None
    dl = desc.lower()[:500]
    for key, country in _COUNTRY_MAP.items():
        if key in dl:
            return country
    return None

def _guess_motivation(desc: str) -> str:
    if not desc: return None
    dl = desc.lower()[:500]
    if any(w in dl for w in ["espionage", "intelligence", "spy"]): return "espionage"
    if any(w in dl for w in ["financial", "ransomware", "extortion", "profit"]): return "financial"
    if any(w in dl for w in ["destructive", "sabotage", "wiper"]): return "sabotage"
    if any(w in dl for w in ["hacktivist", "activist", "political"]): return "hacktivism"
    return None

def _guess_sectors(desc: str) -> list:
    if not desc: return []
    dl = desc.lower()[:800]
    sectors = []
    sector_map = {"government": "Government", "financial": "Financial", "energy": "Energy",
                  "defense": "Defense", "healthcare": "Healthcare", "technology": "Technology",
                  "telecom": "Telecom", "media": "Media", "education": "Education",
                  "aerospace": "Aerospace", "manufacturing": "Manufacturing", "retail": "Retail"}
    for key, label in sector_map.items():
        if key in dl: sectors.append(label)
    return sectors[:5]

def _country_flag(country: str) -> str:
    return _COUNTRY_FLAGS.get(country, "🎭")

MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

@lru_cache(maxsize=1)
def _sync_engine():
    return create_engine(settings.SYNC_DATABASE_URL, pool_pre_ping=True, pool_size=3)

@lru_cache(maxsize=1)
def _sync_session_factory():
    return sessionmaker(bind=_sync_engine())


def _ioc_type_from_url(url: str) -> str | None:
    """Classify a URL from external references as an IOC type."""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url):
        return "ipv4"
    if re.match(r"^[a-f0-9]{64}$", url, re.I):
        return "sha256"
    if re.match(r"^[a-f0-9]{32}$", url, re.I):
        return "md5"
    if re.match(r"^https?://", url):
        # Extract domain from URL
        domain = url.split("/")[2].split(":")[0]
        if domain and "." in domain:
            return "domain"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$", url):
        return "domain"
    return None


def _extract_ioc_value(url: str, ioc_type: str) -> str:
    """Extract clean IOC value from a URL or string."""
    if ioc_type == "domain" and url.startswith("http"):
        return url.split("/")[2].split(":")[0].lower()
    if ioc_type in ("ipv4", "sha256", "md5"):
        return url.lower()
    return url.lower()


def _parse_actors(bundle: dict) -> tuple[list[dict], list[dict]]:
    """Parse MITRE bundle into actors and actor_iocs.
    
    Returns (actors, ioc_rows) where ioc_rows are ready for ActorIoc table.
    """
    objects = bundle.get("objects", [])
    groups = {o["id"]: o for o in objects if o.get("type") == "intrusion-set"}
    relationships = [o for o in objects if o.get("type") == "relationship"]
    techniques = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    indicators = {o["id"]: o for o in objects if o.get("type") == "indicator"}
    malwares = {o["id"]: o for o in objects if o.get("type") in ("malware", "tool")}

    # Build actor→techniques map
    actor_techniques: dict[str, list] = {}
    # Build actor→indicators map (known IOCs)
    actor_indicators: dict[str, list] = {}

    for rel in relationships:
        rel_type = rel.get("relationship_type", "")
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")

        if rel_type == "uses" and src in groups:
            if tgt in techniques:
                t = techniques[tgt]
                ext = t.get("external_references", [{}])
                tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), "")
                actor_techniques.setdefault(src, []).append({"id": tid, "name": t.get("name", "")})

        if rel_type == "indicates" and tgt in groups:
            # indicator → group relationship
            if src in indicators:
                actor_indicators.setdefault(tgt, []).append(indicators[src])
        if rel_type == "uses" and src in groups and tgt in malwares:
            # group uses malware - tag malware name to actor
            actor_indicators.setdefault(src, [])

    actors = []
    ioc_rows = []  # (actor_name, mitre_id, ioc_type, ioc_value, ioc_role, confidence)

    for gid, g in groups.items():
        ext = g.get("external_references", [{}])
        mitre_id = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), "")
        aliases = g.get("aliases", [])
        actor_name = g.get("name", "")
        if not actor_name:
            continue

        actors.append({
            "name": actor_name,
            "mitre_id": mitre_id,
            "aliases": aliases,
            "description": g.get("description", ""),
            "techniques": actor_techniques.get(gid, []),
            "references": [r.get("url", "") for r in ext if r.get("url")],
            "active_since": (g.get("created", "") or "")[:10] or None,
            "last_seen": (g.get("modified", "") or "")[:10] or None,
            "origin_country": _guess_country(g.get("description", "")),
            "motivation": _guess_motivation(g.get("description", "")),
            "target_sectors": _guess_sectors(g.get("description", "")),
        })

        # Extract IOCs from external references (domains, IPs in URLs)
        for ref in ext:
            url = ref.get("url", "")
            desc = ref.get("description", "")
            # Skip MITRE ATT&CK URLs themselves
            if "mitre.org" in url or "attack.mitre" in url:
                continue
            # Look for IP/hash/domain in description or URL
            for candidate in [url] + desc.split():
                ioc_type = _ioc_type_from_url(candidate)
                if ioc_type:
                    val = _extract_ioc_value(candidate, ioc_type)
                    if len(val) > 4:  # Skip noise
                        ioc_rows.append({
                            "actor_name": actor_name,
                            "ioc_type": ioc_type,
                            "ioc_value": val,
                            "ioc_role": "c2" if ioc_type in ("ipv4", "domain") else "infrastructure",
                            "confidence": 0.7,
                        })

        # Extract IOCs from STIX indicators linked to this group
        SKIP_OBJ_TYPES = {"process", "windows-registry-key", "user-account",
                          "network-traffic", "artifact"}
        STIX_TYPE_MAP = {
            "domain-name": "domain",
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "url": "url",
        }
        for ind in actor_indicators.get(gid, []):
            pattern = ind.get("pattern", "")
            if not pattern:
                continue

            # Simple value patterns: [domain-name:value = 'evil.com']
            for match in re.finditer(
                r"\[(\w[\w\-]+):value\s*=\s*'([^']+)'\]", pattern
            ):
                obj_type, val = match.group(1), match.group(2)
                if obj_type in SKIP_OBJ_TYPES:
                    continue
                ioc_type = STIX_TYPE_MAP.get(obj_type)
                if ioc_type and val and len(val) > 4:
                    ioc_rows.append({
                        "actor_name": actor_name,
                        "ioc_type": ioc_type,
                        "ioc_value": val.lower(),
                        "ioc_role": "indicator",
                        "confidence": 0.85,
                    })

            # Hash patterns: [file:hashes.'SHA-256' = 'abc...']
            # Handles both quoted and unquoted property names
            for match in re.finditer(
                r"file:hashes[.\[']*(?:SHA-256|SHA256|MD5|SHA-1|SHA1)[.'\"]*\s*=\s*'([a-fA-F0-9]{32,64})'",
                pattern, re.IGNORECASE
            ):
                val = match.group(1)
                hash_type = "sha256" if len(val) == 64 else ("sha1" if len(val) == 40 else "md5")
                ioc_rows.append({
                    "actor_name": actor_name,
                    "ioc_type": hash_type,
                    "ioc_value": val.lower(),
                    "ioc_role": "malware",
                    "confidence": 0.9,
                })

    return actors, ioc_rows


async def run_collection() -> dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(MITRE_ENTERPRISE_URL)
        resp.raise_for_status()
        bundle = resp.json()

    actors, ioc_rows = _parse_actors(bundle)
    stats = {"total_actors": len(actors), "new": 0, "updated": 0,
             "iocs_added": 0, "iocs_skipped": 0}

    async with async_session() as db:
        # Upsert threat actors
        actor_id_map: dict[str, int] = {}
        for a in actors:
            if not a["name"]:
                continue
            r = await db.execute(select(ThreatActor).where(ThreatActor.name == a["name"]))
            existing = r.scalar_one_or_none()
            if existing:
                existing.mitre_id = a["mitre_id"]
                existing.aliases = a["aliases"] or existing.aliases
                existing.techniques = a["techniques"] or existing.techniques
                existing.references = a["references"] or existing.references
                if a["description"]:
                    existing.description = a["description"]
                if a.get("origin_country"):
                    existing.origin_country = a["origin_country"]
                if a.get("motivation"):
                    existing.motivation = a["motivation"]
                if a.get("target_sectors"):
                    existing.target_sectors = a["target_sectors"]
                if a.get("active_since"):
                    existing.active_since = a["active_since"]
                if a.get("last_seen"):
                    existing.last_seen = a["last_seen"]
                actor_id_map[a["name"]] = existing.id
                stats["updated"] += 1
            else:
                actor = ThreatActor(
                    name=a["name"], mitre_id=a["mitre_id"], aliases=a["aliases"],
                    description=a["description"], techniques=a["techniques"],
                    references=a["references"], source="mitre",
                    origin_country=a.get("origin_country"),
                    motivation=a.get("motivation"),
                    target_sectors=a.get("target_sectors", []),
                    active_since=a.get("active_since"),
                    last_seen=a.get("last_seen"),
                )
                db.add(actor)
                await db.flush()
                actor_id_map[a["name"]] = actor.id
                stats["new"] += 1

        await db.flush()

        # Insert actor IOCs (skip duplicates)
        for ioc in ioc_rows:
            actor_name = ioc["actor_name"]
            actor_id = actor_id_map.get(actor_name)
            if not actor_id:
                continue
            # Check for existing
            r = await db.execute(
                select(ActorIoc).where(
                    ActorIoc.actor_id == actor_id,
                    ActorIoc.ioc_value == ioc["ioc_value"],
                ).limit(1)
            )
            if r.scalar_one_or_none():
                stats["iocs_skipped"] += 1
                continue
            db.add(ActorIoc(
                actor_id=actor_id,
                actor_name=actor_name,
                ioc_type=ioc["ioc_type"],
                ioc_value=ioc["ioc_value"],
                ioc_role=ioc["ioc_role"],
                confidence=ioc["confidence"],
                source="mitre",
            ))
            stats["iocs_added"] += 1

        await db.commit()

    logger.info(f"MITRE ingest: {stats}")
    return stats


@celery_app.task(name="arguswatch.collectors.mitre_collector.collect_mitre")
def collect_mitre():
    import asyncio
    async def _wrapped():
        async with record_collector_run("mitre") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
