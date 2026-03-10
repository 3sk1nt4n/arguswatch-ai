"""Cybersixgill - invite-only dark web forums. CYBERSIXGILL_CLIENT_ID + CYBERSIXGILL_SECRET required."""
import logging
from arguswatch.config import settings
logger = logging.getLogger("arguswatch.collectors.enterprise.cybersixgill")

async def run_collection() -> dict:
    if not settings.CYBERSIXGILL_CLIENT_ID or not settings.CYBERSIXGILL_SECRET:
        return {"status": "inactive", "reason": "CYBERSIXGILL_CLIENT_ID + CYBERSIXGILL_SECRET not set"}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get token
            token_r = await client.post("https://api.cybersixgill.com/auth/token",
                data={"client_id": settings.CYBERSIXGILL_CLIENT_ID, "client_secret": settings.CYBERSIXGILL_SECRET, "grant_type": "client_credentials"})
            token_r.raise_for_status()
            token = token_r.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.get("https://api.cybersixgill.com/intel/posts", headers=headers, params={"limit": 50, "positive_status": 1})
            resp.raise_for_status()
            data = resp.json()
        posts = data.get("posts", [])
        from arguswatch.database import async_session
        from arguswatch.models import DarkWebMention, SeverityLevel
        from sqlalchemy import select
        new_count = 0
        async with async_session() as db:
            for post in posts:
                url = post.get("url", "")
                r = await db.execute(select(DarkWebMention).where(DarkWebMention.url == url, DarkWebMention.source == "cybersixgill"))
                if r.scalar_one_or_none(): continue
                db.add(DarkWebMention(
                    source="cybersixgill", mention_type="darkweb_forum",
                    title=post.get("title", "")[:499], url=url,
                    threat_actor=post.get("actor", ""),
                    content_snippet=post.get("content", "")[:1000],
                    severity=SeverityLevel.HIGH,
                    metadata_={"channel": post.get("channel", ""), "site": post.get("site", "")},
                ))
                new_count += 1
            await db.commit()
        return {"status": "active", "new": new_count}
    except Exception as e:
        logger.error(f"Cybersixgill error: {e}")
        return {"status": "error", "error": str(e)}
