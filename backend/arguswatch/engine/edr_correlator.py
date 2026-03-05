"""
EDR Telemetry API - Hash Correlation
======================================
THE FIX FOR: "hash_sha256 from MalwareBazaar/ThreatFox sits unused"

WITHOUT EDR: Hashes cannot match customers (no endpoint visibility)
WITH EDR:    Customer endpoints report file hashes → we match against threat intel

INGESTION:
  POST /api/edr/telemetry - accepts batch of file observations from EDR/SIEM
  {
    "customer_id": 5,
    "observations": [
      {"hostname": "WORKSTATION-01", "hash_sha256": "abc123...", "file_path": "C:\\Users\\...\\mal.exe", "process_name": "mal.exe"},
      {"hostname": "SERVER-DB", "hash_sha256": "def456...", "file_path": "/tmp/suspicious.bin"}
    ]
  }

CORRELATION:
  POST /api/edr/correlate/{customer_id} - matches customer's EDR hashes against threat intel
  Joins edr_telemetry.hash_sha256 = detections.ioc_value WHERE ioc_type = 'hash_sha256'
  Creates findings for matches.
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text

from arguswatch.models import Detection, Finding, Customer, SeverityLevel, DetectionStatus

logger = logging.getLogger("arguswatch.edr")


async def ingest_edr_telemetry(customer_id: int, observations: list[dict], db: AsyncSession) -> dict:
    """Ingest file hash observations from EDR agent or SIEM.
    
    Each observation: {hostname, hash_sha256, hash_md5?, file_path?, process_name?, seen_at?}
    """
    stats = {"inserted": 0, "duplicates": 0, "invalid": 0}
    
    for obs in observations:
        sha256 = obs.get("hash_sha256", "").strip().lower()
        md5 = obs.get("hash_md5", "").strip().lower()
        
        if not sha256 and not md5:
            stats["invalid"] += 1
            continue
        
        # Check for duplicate
        check_hash = sha256 or md5
        existing = await db.execute(text(
            "SELECT id FROM edr_telemetry WHERE customer_id = :cid AND (hash_sha256 = :h OR hash_md5 = :h) LIMIT 1"
        ), {"cid": customer_id, "h": check_hash})
        if existing.first():
            stats["duplicates"] += 1
            continue
        
        await db.execute(text("""
            INSERT INTO edr_telemetry (customer_id, hostname, file_path, hash_sha256, hash_md5,
                process_name, seen_at, source)
            VALUES (:cid, :host, :path, :sha, :md5, :proc, :seen, 'edr_agent')
        """), {
            "cid": customer_id,
            "host": obs.get("hostname", ""),
            "path": obs.get("file_path", ""),
            "sha": sha256 or None,
            "md5": md5 or None,
            "proc": obs.get("process_name", ""),
            "seen": obs.get("seen_at", datetime.utcnow()),
        })
        stats["inserted"] += 1
    
    await db.commit()
    logger.info(f"EDR ingest [{customer_id}]: {stats}")
    return stats


async def correlate_edr_hashes(customer_id: int, db: AsyncSession) -> dict:
    """Correlate customer's EDR hash observations against threat intel detections.
    
    Joins:
      edr_telemetry.hash_sha256 = detections.ioc_value WHERE ioc_type IN ('hash_sha256', 'hash_md5')
    
    Creates findings for confirmed malware on customer endpoints.
    """
    stats = {"checked": 0, "matched": 0, "findings_created": 0}
    
    # Load customer EDR hashes from last 30 days
    edr_r = await db.execute(text("""
        SELECT DISTINCT hash_sha256, hash_md5, hostname, file_path, process_name
        FROM edr_telemetry
        WHERE customer_id = :cid AND seen_at > :cutoff
    """), {"cid": customer_id, "cutoff": datetime.utcnow() - timedelta(days=30)})
    edr_rows = edr_r.all()
    
    if not edr_rows:
        return {**stats, "note": "No EDR telemetry data - ingest via POST /api/edr/telemetry"}
    
    stats["checked"] = len(edr_rows)
    
    for row in edr_rows:
        sha256, md5, hostname, file_path, process_name = row
        
        # Look for this hash in threat intel
        match_hash = sha256 or md5
        if not match_hash:
            continue
        
        det_r = await db.execute(
            select(Detection).where(
                Detection.ioc_type.in_(["hash_sha256", "hash_md5"]),
                func.lower(Detection.ioc_value) == match_hash.lower(),
            ).limit(1)
        )
        det = det_r.scalar_one_or_none()
        
        if det:
            stats["matched"] += 1
            
            # Assign to customer
            det.customer_id = customer_id
            det.matched_asset = f"{hostname}:{file_path}"
            det.correlation_type = "edr_hash"
            det.match_proof = {
                "method": "edr_hash_correlation",
                "edr_hostname": hostname,
                "edr_file_path": file_path,
                "edr_process": process_name,
                "threat_source": det.source,
                "malware_info": det.raw_text[:200] if det.raw_text else "",
            }
            
            # Create finding
            existing_finding = await db.execute(
                select(Finding).where(
                    Finding.customer_id == customer_id,
                    Finding.ioc_value == det.ioc_value,
                ).limit(1)
            )
            if not existing_finding.scalar_one_or_none():
                finding = Finding(
                    customer_id=customer_id,
                    ioc_type=det.ioc_type,
                    ioc_value=det.ioc_value,
                    severity=SeverityLevel.CRITICAL,  # Malware confirmed on endpoint = always CRITICAL
                    status=DetectionStatus.NEW,
                    confidence=0.95,
                    source_count=1,
                    matched_asset=f"{hostname}:{file_path}",
                    correlation_type="edr_hash",
                    sla_hours=4,
                    sla_deadline=datetime.utcnow() + timedelta(hours=4),
                    all_sources=[det.source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    match_proof=det.match_proof,
                    enrichment_narrative=(
                        f"CONFIRMED MALWARE: {det.source} identified hash {match_hash[:16]}... "
                        f"as malicious. Found on {hostname} at {file_path}. "
                        f"Process: {process_name or 'unknown'}. "
                        f"Threat info: {det.raw_text[:100] if det.raw_text else 'N/A'}"
                    ),
                )
                db.add(finding)
                stats["findings_created"] += 1
                
                logger.warning(
                    f"EDR MATCH [{customer_id}]: {match_hash[:16]}... "
                    f"on {hostname} - {det.source}: {det.raw_text[:60] if det.raw_text else 'malware'}"
                )
    
    await db.commit()
    logger.info(f"EDR correlate [{customer_id}]: {stats}")
    return stats
