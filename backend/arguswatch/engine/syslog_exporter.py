"""Syslog / CEF Output - forward detections to any SIEM.
Splunk, Elastic, Microsoft Sentinel - standard CEF/Syslog format.
"""
import socket, logging
from datetime import datetime, timezone
from arguswatch.config import settings

logger = logging.getLogger("arguswatch.engine.syslog")

SYSLOG_HOST = getattr(settings, "SYSLOG_HOST", "") or ""
SYSLOG_PORT = int(getattr(settings, "SYSLOG_PORT", 514) or 514)

SEV_TO_CEF = {"CRITICAL": "10", "HIGH": "8", "MEDIUM": "5", "LOW": "3", "INFO": "1"}

def format_cef(detection) -> str:
    """Format detection as CEF (Common Event Format) for SIEM ingestion."""
    sev = _sev(detection.severity) or "MEDIUM"
    cef_sev = SEV_TO_CEF.get(sev, "5")
    ts = (detection.created_at or datetime.utcnow()).strftime("%b %d %H:%M:%S")
    # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    cef = (
        f"CEF:0|SolventCyberSecurity|ArgusWatch|7.0|{detection.ioc_type}|"
        f"ArgusWatch Detection: {detection.ioc_type}|{cef_sev}|"
        f"src={detection.ioc_value[:100]} "
        f"cs1={detection.source} cs1Label=Source "
        f"cs2={sev} cs2Label=Severity "
        f"cs3={detection.status.value if detection.status else 'NEW'} cs3Label=Status "
        f"cn1={detection.sla_hours or 72} cn1Label=SLA_Hours "
        f"msg={ts} {(detection.raw_text or '')[:100]}"
    )
    return cef

def send_to_siem(detection) -> bool:
    """Send a single detection as CEF/Syslog to configured SIEM endpoint."""
    if not SYSLOG_HOST:
        return False
    try:
        cef_msg = format_cef(detection)
        msg_bytes = cef_msg.encode("utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(msg_bytes, (SYSLOG_HOST, SYSLOG_PORT))
        logger.debug(f"CEF sent to {SYSLOG_HOST}:{SYSLOG_PORT}")
        return True
    except Exception as e:
        logger.warning(f"Syslog send error: {e}")
        return False

async def send_recent_to_siem(limit: int = 100) -> dict:
    """Batch forward recent detections to SIEM."""
    if not SYSLOG_HOST:
        return {"skipped": "SYSLOG_HOST not configured", "note": "Add SYSLOG_HOST + SYSLOG_PORT to .env"}
    from arguswatch.database import async_session
    from arguswatch.models import Detection
    from sqlalchemy import select, desc
    async with async_session() as db:
        r = await db.execute(select(Detection).order_by(desc(Detection.created_at)).limit(limit))
        detections = r.scalars().all()
    sent, failed = 0, 0
    for det in detections:
        if send_to_siem(det): sent += 1
        else: failed += 1
    return {"sent": sent, "failed": failed, "siem": f"{SYSLOG_HOST}:{SYSLOG_PORT}"}


def send_cef(det_dict: dict) -> bool:
    """Send a detection dict as CEF to SIEM.
    Used by api/enrichments.py CEF push endpoint which passes plain dicts.
    """
    from types import SimpleNamespace
    ns = SimpleNamespace(**det_dict)
    sev = det_dict.get("severity", "MEDIUM")
    ns.severity = SimpleNamespace(value=sev) if isinstance(sev, str) else sev
    ns.status = SimpleNamespace(value=det_dict.get("status", "NEW"))
    ns.created_at = None
    ns.raw_text = det_dict.get("raw_text", "")
    return send_to_siem(ns)


from arguswatch.celery_app import celery_app as _celery_app

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


@_celery_app.task(name="arguswatch.engine.syslog_exporter.run_syslog_task")
def run_syslog_task():
    import asyncio
    return asyncio.run(send_recent_to_siem())
