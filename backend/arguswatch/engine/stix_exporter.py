"""STIX 2.1 Export - converts detections to valid STIX bundles.
Every detection can be exported as STIX 2.1 for SIEM compatibility.
"""
import json, uuid, logging
from datetime import datetime
from pathlib import Path
from arguswatch.config import settings

logger = logging.getLogger("arguswatch.engine.stix")

STIX_OUTPUT_DIR = Path(getattr(settings, "STIX_OUTPUT_DIR", "/tmp/stix_out"))

def _indicator_type(ioc_type: str) -> str:
    mapping = {
        "ipv4": "network-traffic", "ipv6": "network-traffic",
        "domain": "domain-name", "url": "url",
        "sha256": "file", "md5": "file", "sha1": "file",
        "email": "email-addr",
        "aws_access_key": "artifact", "github_pat_classic": "artifact",
    }
    return mapping.get(ioc_type, "indicator")

def _stix_pattern(ioc_type: str, ioc_value: str) -> str:
    patterns = {
        "ipv4": f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "md5": f"[file:hashes.'MD5' = '{ioc_value}']",
        "email": f"[email-addr:value = '{ioc_value}']",
    }
    return patterns.get(ioc_type, f"[artifact:payload_bin = '{ioc_value[:100]}']")

def export_detection_to_stix(detection) -> dict:
    """Export a single detection as STIX 2.1 bundle dict."""
    ts = (detection.created_at or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator_id = f"indicator--{uuid.uuid4()}"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": ts,
                "modified": ts,
                "name": f"ArgusWatch: {detection.ioc_type} - {detection.ioc_value[:60]}",
                "description": (detection.raw_text or "")[:500],
                "pattern": _stix_pattern(detection.ioc_type, detection.ioc_value),
                "pattern_type": "stix",
                "valid_from": ts,
                "indicator_types": [_indicator_type(detection.ioc_type)],
                "confidence": int((detection.confidence or 0.5) * 100),
                "labels": [detection.source, detection.ioc_type],
                "custom_properties": {
                    "x_arguswatch_severity": _sev(detection.severity) or "MEDIUM",
                    "x_arguswatch_source": detection.source,
                    "x_arguswatch_sla_hours": detection.sla_hours,
                    "x_arguswatch_customer_id": detection.customer_id,
                }
            }
        ]
    }
    return bundle

async def export_all_to_stix(limit: int = 500) -> dict:
    """Export recent detections to STIX JSON files."""
    from arguswatch.database import async_session
    from arguswatch.models import Detection
    from sqlalchemy import select, desc
    STIX_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    async with async_session() as db:
        r = await db.execute(select(Detection).order_by(desc(Detection.created_at)).limit(limit))
        detections = r.scalars().all()
    bundles = []
    for det in detections:
        bundle = export_detection_to_stix(det)
        path = STIX_OUTPUT_DIR / f"detection_{det.id}.json"
        path.write_text(json.dumps(bundle, indent=2))
        bundles.append(str(path))
    return {"exported": len(bundles), "output_dir": str(STIX_OUTPUT_DIR)}


def bundle_to_json(det_dict: dict) -> str:
    """Convert a detection dict to STIX 2.1 JSON string.
    Used by api/enrichments.py export endpoint which passes plain dicts.
    """
    from types import SimpleNamespace
    ns = SimpleNamespace(**det_dict)
    sev = det_dict.get("severity", "MEDIUM")
    ns.severity = SimpleNamespace(value=sev) if isinstance(sev, str) else sev
    ns.created_at = None
    return json.dumps(export_detection_to_stix(ns), indent=2)


from arguswatch.celery_app import celery_app as _celery_app

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


@_celery_app.task(name="arguswatch.engine.stix_exporter.run_stix_export_task")
def run_stix_export_task():
    import asyncio
    return asyncio.run(export_all_to_stix())
