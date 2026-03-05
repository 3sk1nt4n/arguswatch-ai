"""Seed service - loads sample customers + assets from CSV."""
import csv, asyncio, logging, traceback
from pathlib import Path
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Customer, CustomerAsset

logger = logging.getLogger("arguswatch.services.seed")

# Resolve CSV path - works both in Docker (/app/data/) and local dev
_candidates = [
    Path(__file__).parent.parent.parent / "data" / "sample_customers.csv",  # local dev
    Path("/app/data/sample_customers.csv"),                                  # Docker mount
]
SAMPLE_CSV = next((p for p in _candidates if p.exists()), _candidates[0])

async def seed_from_csv(csv_path: Path = SAMPLE_CSV) -> dict:
    stats = {"customers_created": 0, "assets_created": 0, "skipped": 0, "errors": []}
    if not csv_path.exists():
        logger.warning(f"CSV not found at {csv_path} - skipping seed")
        stats["errors"].append(f"CSV not found: {csv_path}")
        return stats

    # ── STEP 1: Create all customers first (separate transaction) ──
    customer_map = {}  # name -> id
    try:
        rows = list(csv.DictReader(open(csv_path)))
        customer_names = sorted(set(r.get("customer_name","").strip() for r in rows if r.get("customer_name","").strip()))
        
        async with async_session() as db:
            for name in customer_names:
                try:
                    r = await db.execute(select(Customer).where(Customer.name == name))
                    existing = r.scalar_one_or_none()
                    if existing:
                        customer_map[name] = existing.id
                    else:
                        row = next(r for r in rows if r.get("customer_name","").strip() == name)
                        c = Customer(
                            name=name,
                            industry=row.get("industry",""),
                            tier=row.get("tier","standard"),
                            email=row.get("contact_email",""),
                            onboarding_state="monitoring",
                            active=True,
                        )
                        db.add(c)
                        await db.flush()
                        customer_map[name] = c.id
                        stats["customers_created"] += 1
                        logger.info(f"  Created customer: {name} (id={c.id})")
                except Exception as e:
                    logger.warning(f"  Customer '{name}' failed: {e}")
                    stats["errors"].append(f"customer:{name}:{e}")
            await db.commit()
            logger.info(f"  Customers committed: {stats['customers_created']} created, {len(customer_map)} total")
    except Exception as e:
        logger.error(f"  Customer creation failed: {e}\n{traceback.format_exc()}")
        stats["errors"].append(f"customers_batch:{e}")
        return stats

    # ── STEP 2: Add assets per-customer (separate transactions) ──
    for name, cid in customer_map.items():
        try:
            async with async_session() as db:
                customer_rows = [r for r in rows if r.get("customer_name","").strip() == name]
                for row in customer_rows:
                    at = row.get("asset_type","").strip()
                    av = row.get("asset_value","").strip()
                    if not at or not av:
                        continue
                    # Check duplicate
                    try:
                        r = await db.execute(
                            select(CustomerAsset).where(
                                CustomerAsset.customer_id == cid,
                                CustomerAsset.asset_value == av
                            )
                        )
                        if r.scalar_one_or_none():
                            stats["skipped"] += 1
                            continue
                    except Exception:
                        pass
                    # Try to insert asset
                    try:
                        db.add(CustomerAsset(
                            customer_id=cid,
                            asset_type=at,
                            asset_value=av,
                            criticality=row.get("criticality","medium"),
                        ))
                        stats["assets_created"] += 1
                    except Exception as e1:
                        # Fallback: if enum value fails, use keyword
                        try:
                            await db.rollback()
                            db.add(CustomerAsset(
                                customer_id=cid,
                                asset_type="keyword",
                                asset_value=av,
                                criticality=row.get("criticality","medium"),
                            ))
                            stats["assets_created"] += 1
                            logger.debug(f"  Asset fallback to keyword: {at}={av}")
                        except Exception as e2:
                            stats["skipped"] += 1
                            stats["errors"].append(f"asset:{name}:{at}={av}:{e2}")
                await db.commit()
        except Exception as e:
            logger.warning(f"  Assets for '{name}' failed: {e}")
            stats["errors"].append(f"assets_batch:{name}:{e}")

    logger.info(f"  Seed complete: {stats['customers_created']} customers, {stats['assets_created']} assets, {stats['skipped']} skipped")
    if stats["errors"]:
        logger.warning(f"  Seed errors: {stats['errors'][:5]}")
    return stats
