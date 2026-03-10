"""
ArgusWatch Celery Tasks - v14
==============================
REAL tasks that form the automated pipeline:

collect_via_intel_proxy  -> calls intel-proxy HTTP to fetch real IOCs
match_all_customers_task -> runs 5-strategy customer matching (Fix #1)
correlate_detections_task -> routes unmatched detections to customers
check_sla_and_alert_task -> scans for SLA breaches, dispatches Slack/email (Fix #3)
exposure_recalc_task     -> recalculates exposure with real CVSS/EPSS data (Fix #4)
"""

import os
import asyncio
import logging
import httpx
from datetime import datetime, timezone, timedelta

from arguswatch.celery_app import celery_app

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.tasks")


def _run_async(coro):
    """Helper to run async code from sync Celery tasks."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════════
# TASK 1: Intel Collection via Intel Proxy
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.collect_via_intel_proxy", bind=True, max_retries=2)
def collect_via_intel_proxy(self, endpoint="all"):
    """Call intel-proxy HTTP API to trigger real threat intel collection.
    
    The intel-proxy container has internet access and writes directly to PostgreSQL.
    This is the ONLY real collection path in v13+.
    """
    proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
    
    async def _collect():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                if endpoint == "all":
                    resp = await client.post(f"{proxy_url}/collect/all")
                else:
                    resp = await client.post(f"{proxy_url}/collect/{endpoint}")
                
                if resp.status_code == 200:
                    data = resp.json()
                    total_new = 0
                    if isinstance(data, dict):
                        for source, stats in data.items():
                            if isinstance(stats, dict) and "new" in stats:
                                total_new += stats["new"]
                    logger.info(f"Intel-proxy collection complete: {total_new} new IOCs from {endpoint}")
                    return {"status": "ok", "new_iocs": total_new, "endpoint": endpoint}
                else:
                    logger.warning(f"Intel-proxy returned {resp.status_code}: {resp.text[:200]}")
                    return {"status": "error", "code": resp.status_code}
        except Exception as e:
            logger.error(f"Intel-proxy collection failed: {e}")
            raise self.retry(exc=e, countdown=60)
    
    return _run_async(_collect())


# ═══════════════════════════════════════════════════════════════════════
# TASK 2: Customer Intel Matching
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.match_all_customers_task")
def match_all_customers_task():
    """Run the 5-strategy customer intel matcher against ALL customers.
    
    This is the CRITICAL task that bridges global intel to customer-specific findings.
    Matching creates findings and dispatches alerts for CRITICAL/HIGH matches.
    V16.4.7: Now auto-generates remediations for new findings after matching.
    """
    from arguswatch.database import async_session
    from arguswatch.engine.customer_intel_matcher import match_all_customers
    
    async def _match():
        async with async_session() as db:
            result = await match_all_customers(db)
            total = result.get('total_matches', 0)
            logger.info(
                f"Customer matching complete: {total} matches "
                f"across {result.get('customers_processed', 0)} customers"
            )
            
            # V16.4.7: Auto-generate remediations for new findings
            if total > 0:
                try:
                    from arguswatch.engine.action_generator import generate_action
                    from arguswatch.models import Finding, FindingRemediation
                    from sqlalchemy import select
                    # Find findings without remediations
                    subq = select(FindingRemediation.finding_id).distinct()
                    new_f = await db.execute(
                        select(Finding.id).where(
                            Finding.id.notin_(subq),
                            Finding.severity.in_(["CRITICAL", "HIGH", "MEDIUM"]),
                        ).limit(50)
                    )
                    remed_count = 0
                    for row in new_f.all():
                        try:
                            r = await generate_action(row[0], db)
                            if r: remed_count += 1
                        except Exception:
                            pass
                    if remed_count:
                        await db.commit()
                        logger.info(f"Auto-generated {remed_count} remediations for new findings")
                    result["remediations_auto_generated"] = remed_count
                except Exception as e:
                    logger.warning(f"Auto-remediation failed (non-blocking): {e}")
            
            return result
    
    return _run_async(_match())


# ═══════════════════════════════════════════════════════════════════════
# TASK 3: Correlation Engine
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.correlate_detections_task")
def correlate_detections_task():
    """Route unmatched detections to customers using correlation engine."""
    from arguswatch.database import async_session
    from arguswatch.engine.correlation_engine import correlate_new_detections
    
    async def _correlate():
        async with async_session() as db:
            result = await correlate_new_detections(db, limit=500)
            await db.commit()
            logger.info(f"Correlation: {result}")
            return result
    
    return _run_async(_correlate())


# ═══════════════════════════════════════════════════════════════════════
# TASK 4: SLA Check + Alert Dispatch (Fix #3)
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.check_sla_and_alert_task")
def check_sla_and_alert_task():
    """Scan for:
    1. New CRITICAL/HIGH findings that haven't been alerted yet
    2. SLA breaches - findings past their deadline
    3. Dispatch Slack/email alerts for both cases
    
    THIS IS FIX #3: event-driven alerting that was previously never triggered.
    """
    from arguswatch.database import async_session
    from sqlalchemy import select, and_
    from arguswatch.models import Finding, Customer, DetectionStatus, SeverityLevel
    from arguswatch.engine.alert_dispatcher import dispatch_finding_alert, send_slack, send_email
    
    async def _check():
        async with async_session() as db:
            stats = {"new_alerts": 0, "sla_breaches": 0, "errors": 0}
            now = datetime.utcnow()
            
            # ── 1. New CRITICAL/HIGH findings not yet alerted ──
            r = await db.execute(
                select(Finding).where(
                    Finding.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH]),
                    Finding.status == DetectionStatus.NEW,
                    Finding.customer_id.isnot(None),
                    # Only findings created in last 2 hours (avoid re-alerting old ones)
                    Finding.created_at >= now - timedelta(hours=2),
                ).limit(50)
            )
            new_findings = r.scalars().all()
            
            for finding in new_findings:
                try:
                    # Load customer
                    cr = await db.execute(
                        select(Customer).where(Customer.id == finding.customer_id)
                    )
                    customer = cr.scalar_one_or_none()
                    if not customer:
                        continue
                    
                    result = await dispatch_finding_alert(finding, customer)
                    if result.get("slack") or result.get("email"):
                        # Mark as ALERTED so we don't re-alert
                        finding.status = DetectionStatus.ALERTED
                        stats["new_alerts"] += 1
                        logger.info(
                            f"Alert sent: Finding #{finding.id} "
                            f"{_sev(finding.severity)} {finding.ioc_value[:40]} "
                            f"-> {customer.name}"
                        )
                except Exception as e:
                    logger.warning(f"Alert failed for finding #{finding.id}: {e}")
                    stats["errors"] += 1
            
            # ── 2. SLA breach check ──
            r = await db.execute(
                select(Finding).where(
                    Finding.status.in_([DetectionStatus.NEW, DetectionStatus.ENRICHED]),
                    Finding.sla_deadline.isnot(None),
                    Finding.sla_deadline < now,
                    Finding.customer_id.isnot(None),
                ).limit(50)
            )
            breached = r.scalars().all()
            
            for finding in breached:
                try:
                    cr = await db.execute(
                        select(Customer).where(Customer.id == finding.customer_id)
                    )
                    customer = cr.scalar_one_or_none()
                    if not customer:
                        continue
                    
                    hours_over = (now - finding.sla_deadline).total_seconds() / 3600
                    sev_val = _sev(finding.severity) or "HIGH"
                    
                    # SLA breach Slack message
                    breach_msg = (
                        f"⏰ *SLA BREACH - {customer.name}*\n"
                        f"*Finding:* #{finding.id} - `{finding.ioc_value[:60]}`\n"
                        f"*Severity:* {sev_val}\n"
                        f"*Over SLA by:* {hours_over:.1f} hours\n"
                        f"*Status:* {finding.status.value if finding.status else 'NEW'}\n"
                        f"*Action required:* Escalate or resolve immediately"
                    )
                    
                    slack_url = customer.slack_channel or os.environ.get("SLACK_WEBHOOK_URL", "")
                    if slack_url:
                        await send_slack(breach_msg, slack_url)
                    
                    # Email alert
                    alert_email = customer.email or os.environ.get("ALERT_EMAIL", "")
                    if alert_email:
                        send_email(
                            subject=f"[ArgusWatch SLA BREACH] {sev_val}: {customer.name}",
                            body=breach_msg.replace("*", "").replace("`", ""),
                            to_email=alert_email,
                        )
                    
                    stats["sla_breaches"] += 1
                except Exception as e:
                    logger.warning(f"SLA breach alert failed: {e}")
                    stats["errors"] += 1
            
            await db.commit()
            logger.info(f"Alert check: {stats}")
            return stats
    
    return _run_async(_check())


# ═══════════════════════════════════════════════════════════════════════
# TASK 5: Exposure Scoring with CVSS/EPSS (Fix #4)
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# TASK 5: Exposure Scoring with CVSS/EPSS (Fix #4)
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.threat_pressure_task")
def threat_pressure_task():
    """Calculate global threat pressure from unmatched IOCs.
    
    Converts Class 2/3 IOCs into sector-level environmental risk signals.
    Feodo C2 IPs -> banking malware pressure.
    LockBit victims -> healthcare ransomware pressure.
    """
    from arguswatch.database import async_session
    from arguswatch.engine.threat_pressure import calculate_threat_pressure
    
    async def _calc():
        async with async_session() as db:
            result = await calculate_threat_pressure(db, window_hours=48)
            logger.info(f"Threat pressure: {result}")
            return result
    
    return _run_async(_calc())


@celery_app.task(name="arguswatch.tasks.exposure_recalc_task")
def exposure_recalc_task():
    """Recalculate exposure scores using real CVSS/EPSS data from NVD.
    
    This wraps the exposure scorer and ensures it uses actual CVSS scores
    stored in detection metadata and CveProductMap.
    """
    from arguswatch.database import async_session
    from arguswatch.engine.exposure_scorer import recalculate_all_exposures
    
    async def _recalc():
        async with async_session() as db:
            result = await recalculate_all_exposures(db)
            await db.commit()
            logger.info(f"Exposure recalc: {result}")
            # V16.4: Generate AI narratives for all customers after scoring
            try:
                from arguswatch.engine.exposure_narrative import generate_all_narratives
                narr_result = await generate_all_narratives(db)
                await db.commit()
                logger.info(f"Exposure narratives: {narr_result}")
            except Exception as _ne:
                logger.debug(f"Narrative generation failed (non-fatal): {_ne}")
            return result
    
    return _run_async(_recalc())

@celery_app.task(name="arguswatch.tasks.snapshot_exposure_history")
def snapshot_exposure_history():
    """Daily snapshot of exposure scores for trend charts.
    Stores overall + D1-D5 scores per customer in exposure_history table."""
    from arguswatch.database import async_session
    
    async def _snapshot():
        from arguswatch.models import Customer, Detection, ExposureHistory
        from arguswatch.services.exposure_scorer import calculate_customer_exposure
        from sqlalchemy import select, func
        from datetime import datetime, timezone
        
        async with async_session() as db:
            # Get all active customers
            r = await db.execute(select(Customer).where(Customer.active == True))
            customers = r.scalars().all()
            
            snapshot_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            count = 0
            
            for cust in customers:
                try:
                    # Calculate current exposure
                    exp = await calculate_customer_exposure(cust.id, db)
                    
                    # Count detections
                    det_r = await db.execute(
                        select(func.count(Detection.id)).where(Detection.customer_id == cust.id)
                    )
                    total_dets = det_r.scalar() or 0
                    
                    crit_r = await db.execute(
                        select(func.count(Detection.id)).where(
                            Detection.customer_id == cust.id,
                            Detection.severity == "CRITICAL",
                        )
                    )
                    crit_count = crit_r.scalar() or 0
                    
                    # Check if snapshot already exists for today
                    existing = await db.execute(
                        select(ExposureHistory).where(
                            ExposureHistory.customer_id == cust.id,
                            ExposureHistory.snapshot_date == snapshot_date,
                        )
                    )
                    if existing.scalar_one_or_none():
                        continue  # Already snapshotted today
                    
                    db.add(ExposureHistory(
                        customer_id=cust.id,
                        snapshot_date=snapshot_date,
                        overall_score=exp.get("overall_score", 0),
                        d1_score=exp.get("d1", {}).get("score", 0) if isinstance(exp.get("d1"), dict) else exp.get("d1_score", 0),
                        d2_score=exp.get("d2", {}).get("score", 0) if isinstance(exp.get("d2"), dict) else exp.get("d2_score", 0),
                        d3_score=exp.get("d3", {}).get("score", 0) if isinstance(exp.get("d3"), dict) else exp.get("d3_score", 0),
                        d4_score=exp.get("d4", {}).get("score", 0) if isinstance(exp.get("d4"), dict) else exp.get("d4_score", 0),
                        d5_score=exp.get("d5", {}).get("score", 0) if isinstance(exp.get("d5"), dict) else exp.get("d5_score", 0),
                        total_detections=total_dets,
                        critical_count=crit_count,
                    ))
                    count += 1
                except Exception as e:
                    logger.warning(f"Exposure snapshot failed for {cust.name}: {e}")
            
            await db.commit()
            logger.info(f"Exposure snapshot: {count} customers recorded")
            return {"snapshots": count}
    
    return _run_async(_snapshot())


@celery_app.task(name="arguswatch.tasks.retry_recon", bind=True, max_retries=3)
def retry_recon(self, customer_id, domain):
    """Retry recon for customers where initial recon failed at onboarding.
    Retries 3 times with exponential backoff (2min, 4min, 8min)."""
    logger.info(f"Retrying recon for customer {customer_id}, domain {domain}")
    
    async def _retry():
        from arguswatch.database import async_session
        from arguswatch.models import Customer
        from sqlalchemy import select
        
        recon_url = os.environ.get("RECON_ENGINE_URL", "http://recon-engine:9001")
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{recon_url}/recon/{customer_id}",
                                          params={"domain": domain})
                result = resp.json()
            
            # Update customer recon status
            async with async_session() as db:
                r = await db.execute(select(Customer).where(Customer.id == customer_id))
                cust = r.scalar_one_or_none()
                if cust:
                    cust.recon_status = "success"
                    cust.recon_error = None
                    await db.commit()
            
            assets_found = result.get("assets_created", 0)
            logger.info(f"Recon retry SUCCESS for customer {customer_id}: {assets_found} assets discovered")
            
            # Run intel matching on newly discovered assets
            try:
                from arguswatch.engine.customer_intel_matcher import match_customer_intel
                async with async_session() as db:
                    await match_customer_intel(customer_id, db)
            except Exception as me:
                logger.warning(f"Post-recon matching failed for {customer_id}: {me}")
            
            return {"status": "success", "assets": assets_found}
            
        except Exception as e:
            logger.warning(f"Recon retry {self.request.retries + 1}/3 failed for customer {customer_id}: {e}")
            # Update status to retrying
            try:
                async with async_session() as db:
                    r = await db.execute(select(Customer).where(Customer.id == customer_id))
                    cust = r.scalar_one_or_none()
                    if cust:
                        cust.recon_status = "retrying" if self.request.retries < 2 else "failed"
                        cust.recon_error = str(e)[:200]
                        await db.commit()
            except Exception:
                pass
            raise e
    
    try:
        return _run_async(_retry())
    except Exception as e:
        try:
            self.retry(countdown=120 * (2 ** self.request.retries))  # 2min, 4min, 8min
        except self.MaxRetriesExceededError:
            logger.error(f"Recon permanently failed for customer {customer_id} after 3 retries")
            return {"status": "failed", "error": str(e)[:200]}


# ══════════════════════════════════════════════════════════════════════
# V16.4: AGENTIC AI TASKS
# ══════════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.darkweb_triage_task")
def darkweb_triage_task():
    """Triage all untriaged dark web mentions with customer_id.
    Runs every 30 min via Celery beat.
    AI classifies each mention and auto-creates CRITICAL findings for real threats.
    """
    from arguswatch.database import async_session

    async def _triage():
        from arguswatch.engine.darkweb_triage import triage_untriaged_mentions
        async with async_session() as db:
            result = await triage_untriaged_mentions(db, limit=50)
            await db.commit()
            logger.info(f"Dark web triage: {result}")
            return result

    return _run_async(_triage())


@celery_app.task(name="arguswatch.tasks.sector_campaign_detection_task")
def sector_campaign_detection_task():
    """Detect cross-customer IOC patterns - MSSP differentiator.
    Runs every 6 hours via Celery beat.
    Finds IOCs hitting 2+ customers in 48 hours and generates sector advisories.
    """
    from arguswatch.database import async_session

    async def _detect():
        from arguswatch.engine.sector_detection import detect_sector_campaigns
        async with async_session() as db:
            result = await detect_sector_campaigns(db, hours=48)
            await db.commit()
            logger.info(f"Sector detection: {result}")
            return result

    return _run_async(_detect())


# ══════════════════════════════════════════════════════════════════
# DATA RETENTION / CLEANUP -  Prevent unbounded DB growth
# ══════════════════════════════════════════════════════════════════

@celery_app.task(name="arguswatch.tasks.data_cleanup")
def data_cleanup_task():
    """Nightly data cleanup to prevent unbounded PostgreSQL growth.

    Configurable via environment variables:
      RETENTION_DETECTIONS_DAYS=90    -  Delete raw detections older than N days
      RETENTION_COLLECTOR_RUNS_DAYS=30 -  Delete collector run logs older than N days
      RETENTION_ENRICHMENTS_DAYS=60   -  Delete enrichment records older than N days

    Safe: Only deletes processed/old records. Active findings are NEVER deleted.
    """
    from arguswatch.database import async_session

    det_days = int(os.environ.get("RETENTION_DETECTIONS_DAYS", "90"))
    run_days = int(os.environ.get("RETENTION_COLLECTOR_RUNS_DAYS", "30"))
    enr_days = int(os.environ.get("RETENTION_ENRICHMENTS_DAYS", "60"))

    async def _cleanup():
        from sqlalchemy import delete, and_
        from arguswatch.models import Detection, CollectorRun, Enrichment, DetectionStatus

        stats = {"detections": 0, "collector_runs": 0, "enrichments": 0}

        async with async_session() as db:
            # 1. Old detections (already matched or closed)
            det_cutoff = datetime.utcnow() - timedelta(days=det_days)
            r = await db.execute(
                delete(Detection).where(and_(
                    Detection.created_at < det_cutoff,
                    Detection.status.in_([
                        DetectionStatus.REMEDIATED,
                        DetectionStatus.FALSE_POSITIVE,
                        DetectionStatus.CLOSED,
                        DetectionStatus.VERIFIED_CLOSED,
                    ]),
                ))
            )
            stats["detections"] = r.rowcount

            # 2. Old collector run logs
            run_cutoff = datetime.utcnow() - timedelta(days=run_days)
            r = await db.execute(
                delete(CollectorRun).where(CollectorRun.started_at < run_cutoff)
            )
            stats["collector_runs"] = r.rowcount

            # 3. Old enrichment records
            enr_cutoff = datetime.utcnow() - timedelta(days=enr_days)
            r = await db.execute(
                delete(Enrichment).where(Enrichment.created_at < enr_cutoff)
            )
            stats["enrichments"] = r.rowcount

            await db.commit()

            # 4. VACUUM ANALYZE to reclaim space
            from sqlalchemy import text
            async with async_session() as vacuum_db:
                await vacuum_db.execute(text("VACUUM ANALYZE detections"))
                await vacuum_db.execute(text("VACUUM ANALYZE collector_runs"))
                await vacuum_db.execute(text("VACUUM ANALYZE enrichments"))

            logger.info(
                f"[cleanup] Deleted: {stats['detections']} detections (>{det_days}d), "
                f"{stats['collector_runs']} collector_runs (>{run_days}d), "
                f"{stats['enrichments']} enrichments (>{enr_days}d)"
            )
            return stats

    return _run_async(_cleanup())


@celery_app.task(name="arguswatch.tasks.mitre_sync_task", bind=True, max_retries=1)
def mitre_sync_task(self):
    """Weekly MITRE ATT&CK sync -  pulls latest techniques, flags deprecated mappings."""
    import asyncio
    async def _run():
        from arguswatch.database import async_session
        from arguswatch.engine.ai_prompt_manager import sync_mitre_attack
        async with async_session() as db:
            result = await sync_mitre_attack(db)
            deprecated = len(result.get("deprecated_in_registry", []))
            logger.info(f"MITRE sync: v{result.get('version')}, {deprecated} deprecated techniques flagged")
            return result
    return asyncio.run(_run())
