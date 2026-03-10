"""SpyCloud Enterprise - live stealer log ingestion, active_session:true confirmation. SPYCLOUD_API_KEY required."""
import logging
from arguswatch.config import settings
logger = logging.getLogger("arguswatch.collectors.enterprise.spycloud")

async def run_collection() -> dict:
    if not settings.SPYCLOUD_API_KEY:
        return {"status": "inactive", "reason": "SPYCLOUD_API_KEY not set - add key to .env to activate"}
    import httpx
    headers = {"X-API-Key": settings.SPYCLOUD_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            resp = await client.get("https://api.spycloud.io/enterprise-v2/breach/data/emails", params={"severity": 25, "limit": 100})
            resp.raise_for_status()
            data = resp.json()
        results = data.get("results", [])
        from arguswatch.database import async_session
        from arguswatch.models import Detection, SeverityLevel, DetectionStatus
        from sqlalchemy import select
        new_count = 0
        async with async_session() as db:
            for item in results:
                email = item.get("email", "")
                if not email: continue
                r = await db.execute(select(Detection).where(Detection.ioc_value == email, Detection.source == "spycloud"))
                if r.scalar_one_or_none(): continue
                active_session = item.get("active_session", False)
                db.add(Detection(
                    source="spycloud", ioc_type="email_password_combo", ioc_value=email,
                    raw_text=item.get("password", "")[:200],
                    severity=SeverityLevel.CRITICAL, sla_hours=1 if active_session else 4,
                    status=DetectionStatus.NEW, confidence=0.98 if active_session else 0.90,
                    metadata_={"active_session": active_session, "document_id": item.get("document_id"),
                               "breach_date": item.get("breach_date"), "spycloud_publish_date": item.get("spycloud_publish_date")},
                ))
                new_count += 1
            await db.commit()
            # Fire pipeline for new detections
            if new_count > 0:
                from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new
                await trigger_pipeline_for_new(db)
        return {"status": "active", "new": new_count, "total_fetched": len(results)}
    except Exception as e:
        logger.error(f"SpyCloud error: {e}")
        return {"status": "error", "error": str(e)}
