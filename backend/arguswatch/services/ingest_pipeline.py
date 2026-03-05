"""
Ingest Pipeline V11 - the complete flow from raw detection to actionable finding.

FLOW:
  detection saved → [Celery task]
    1. NORMALIZE          - lowercase ioc_value, strip whitespace
    2. FIND OR CREATE     - merge into existing finding or create new one
    3. CUSTOMER ROUTING   - match to customer via 12 asset types, set correlation_type
    4. ENRICHMENT         - VT, AbuseIPDB, OTX (rate-limited)
    5. ENRICHMENT FEEDBACK- malware_family→actor, VT score→severity, CPE→tech_stack
    6. ATTRIBUTION        - IOC/CVE/sector → actor via DB tables (not hardcoded dicts)
    7. CAMPAIGN CHECK     - same customer+actor+14d window → campaign declared?
    8. EXPOSURE RECALC    - 10 factors + recency multiplier, factor_breakdown persisted
    9. ACTION GENERATION  - instantiate playbook with real values → FindingRemediation
   10. DISPATCH           - CRITICAL: Slack+email+STIX | HIGH: Slack+email | MEDIUM: digest

  NO MATCH → finding.customer_id = None → stored in findings table, searchable by agent
  72h RECHECK → Celery beat task re-queries source, checks remediation, VERIFIED_CLOSED or REOPENED
"""
import logging
from arguswatch.celery_app import celery_app

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.ingest_pipeline")


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════

@celery_app.task(
    name="arguswatch.services.ingest_pipeline.process_detection",
    bind=True, max_retries=2, default_retry_delay=10
)
def process_detection(self, detection_id: int):
    """Full post-ingest pipeline for a single detection. Fire-and-forget from collectors."""
    import asyncio
    return asyncio.run(_async_pipeline(detection_id))


def fire_pipeline(detection_id: int):
    """Fire-and-forget: queue pipeline task after db.commit() in any collector."""
    try:
        process_detection.delay(detection_id)
    except Exception as e:
        logger.warning(f"[pipeline] Could not queue detection {detection_id}: {e}")


@celery_app.task(name="arguswatch.services.ingest_pipeline.process_new_detections_batch")
def process_new_detections_batch():
    """Batch pipeline: runs every 5 minutes via Celery beat for any missed detections."""
    import asyncio
    return asyncio.run(_async_batch_pipeline())


@celery_app.task(name="arguswatch.services.ingest_pipeline.recheck_open_findings")
def recheck_open_findings():
    """72h recheck: re-evaluate open findings, verify remediations, close or reopen."""
    import asyncio
    return asyncio.run(_async_recheck())


# ═══════════════════════════════════════════════════════════════════════
# SINGLE DETECTION PIPELINE
# ═══════════════════════════════════════════════════════════════════════

async def _async_pipeline(detection_id: int) -> dict:
    from arguswatch.database import async_session
    from arguswatch.models import Detection, Customer, SeverityLevel
    from sqlalchemy import select

    results = {"detection_id": detection_id, "steps": []}

    try:
        # ── Step 0: AI Orchestration (Anthropic/OpenAI only - fast providers) ──
        # LLM decides which steps to run and makes decisions directly.
        # If orchestration succeeds, skip the linear steps it already handled.
        _orchestration_result = None
        _orchestration_handled_severity = False
        _orchestration_handled_attribution = False
        try:
            from arguswatch.services.ai_pipeline_orchestrator import ai_orchestrate_detection
            _orchestration_result = await ai_orchestrate_detection(detection_id)
            if _orchestration_result:
                results["steps"].append(
                    f"AI orchestration: {_orchestration_result.get('iterations',0)} iterations, "
                    f"tools={_orchestration_result.get('tools_called',[])}"
                )
                _tc = _orchestration_result.get("tools_called", [])
                _orchestration_handled_severity = "pipeline_set_severity" in _tc
                _orchestration_handled_attribution = "pipeline_set_actor" in _tc
        except Exception as _e0:
            logger.debug(f"[pipeline] AI orchestration failed (linear pipeline continues): {_e0}")

        # ── Step 1: Load + normalize ──────────────────────────────────────────
        async with async_session() as db:
            r = await db.execute(select(Detection).where(Detection.id == detection_id))
            det = r.scalar_one_or_none()
            if not det:
                return {"error": "detection not found"}

            _normalize_detection(det)
            await db.commit()

        # ── Step 2: Customer routing ──────────────────────────────────────────
        async with async_session() as db:
            r = await db.execute(select(Detection).where(Detection.id == detection_id))
            det = r.scalar_one_or_none()

            if not det.customer_id:
                from arguswatch.engine.correlation_engine import route_detection
                matched = await route_detection(det, db)
                await db.commit()
                if matched:
                    results["steps"].append(f"routed → customers {matched} via {det.correlation_type}")
                else:
                    results["steps"].append("routing: no customer match")
            else:
                results["steps"].append(f"routing: already customer_id={det.customer_id}")

        # ── Step 3: Finding merge or create ───────────────────────────────────
        finding_id = None
        is_new_finding = False
        async with async_session() as db:
            from arguswatch.engine.finding_manager import get_or_create_finding
            r = await db.execute(select(Detection).where(Detection.id == detection_id))
            det = r.scalar_one_or_none()
            finding, is_new_finding = await get_or_create_finding(det, db)
            finding_id = finding.id
            await db.commit()
            results["steps"].append(
                f"finding {'created' if is_new_finding else 'merged'} → {finding_id} "
                f"({finding.source_count} sources)"
            )

        if not finding_id:
            return results

        # ── Step 4: Enrichment (rate-limited - VT 500/day free tier) ─────────
        # Enrich on: new finding, or source_count hit 2 or 4 (multi-source confirmation)
        should_enrich = is_new_finding
        if not should_enrich:
            async with async_session() as db:
                from arguswatch.models import Finding
                rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                f = rf.scalar_one_or_none()
                should_enrich = f and f.source_count in (2, 4)

        if should_enrich and not _orchestration_handled_severity:
            try:
                from arguswatch.services.enrichment_pipeline import enrich_detection
                enrich_result = await enrich_detection(detection_id)
                results["steps"].append(f"enriched: {enrich_result.get('enrichments', [])}")
            except Exception as e:
                logger.warning(f"[pipeline] Enrichment failed for {detection_id}: {e}")
                results["steps"].append(f"enrichment error: {e}")

            # ── Steps 5a-5d: AI-FIRST enrichment (AI decides, rules are fallback) ─
            try:
                async with async_session() as db:
                    from arguswatch.models import Finding as _F5, Customer as _C5, SeverityLevel as _SL5
                    from arguswatch.services.ai_pipeline_hooks import (
                        hook_ai_triage, hook_false_positive_check,
                        hook_investigation_narrative,
                    )
                    rf5 = await db.execute(select(_F5).where(_F5.id == finding_id))
                    _f5 = rf5.scalar_one_or_none()
                    if _f5:
                        # Build customer context
                        _cctx5 = {}
                        if _f5.customer_id:
                            _rc5 = await db.execute(select(_C5).where(_C5.id == _f5.customer_id))
                            _cust5 = _rc5.scalar_one_or_none()
                            if _cust5:
                                _cctx5 = {
                                    "industry": getattr(_cust5, "industry", ""),
                                    "name": _cust5.name,
                                    "matched_asset": _f5.matched_asset or "",
                                    "asset_type": _f5.correlation_type or "",
                                }

                        # Run rule-based feedback first to get enrichment numbers
                        from arguswatch.engine.enrichment_feedback import process_enrichment_feedback
                        changes = await process_enrichment_feedback(finding_id, db)
                        _enrich_data = {
                            "vt_malicious": changes.get("vt_malicious", 0),
                            "abuse_score": changes.get("abuse_confidence", 0),
                            "otx_pulses": changes.get("otx_pulses", 0),
                        }

                        # ── Step 5a-pre: FP Memory check - before AI call ──
                        _fp_auto_closed = False
                        try:
                            from arguswatch.engine.fp_memory import check_fp_history
                            if _f5.customer_id:
                                _fp_check = await check_fp_history(
                                    customer_id=_f5.customer_id,
                                    ioc_type=_f5.ioc_type or "",
                                    ioc_value=_f5.ioc_value or "",
                                    source=(_f5.all_sources or ["unknown"])[0],
                                    db=db,
                                )
                                if _fp_check and _fp_check.get("auto_close"):
                                    _f5.ai_false_positive_flag = True
                                    _f5.ai_false_positive_reason = (
                                        f"FP Memory auto-close: {_fp_check.get('reason', '')} "
                                        f"(confirmed {_fp_check.get('hit_count', 0)}x, "
                                        f"conf={_fp_check.get('confidence', 0):.2f})"
                                    )
                                    from arguswatch.models import DetectionStatus as _DS_FP
                                    _f5.status = _DS_FP.FALSE_POSITIVE
                                    _fp_auto_closed = True
                                    results["steps"].append(
                                        f"FP Memory auto-close: {_fp_check.get('reason','')[:60]} "
                                        f"(hits={_fp_check.get('hit_count',0)})"
                                    )
                                elif _fp_check and not _fp_check.get("auto_close"):
                                    # Low-confidence FP match - pass context to AI triage
                                    _enrich_data["fp_memory_match"] = True
                                    _enrich_data["fp_memory_reason"] = _fp_check.get("reason", "")
                                    _enrich_data["fp_memory_confidence"] = _fp_check.get("confidence", 0)
                        except Exception as _efp:
                            logger.debug(f"[pipeline] FP memory check failed (non-fatal): {_efp}")

                        # ── Step 4.5: FP MEMORY CHECK - check before AI triage ──
                        _fp_memory_hit = None
                        if _f5.customer_id:
                            try:
                                from arguswatch.engine.fp_memory import check_fp_history
                                _fp_memory_hit = await check_fp_history(
                                    customer_id=_f5.customer_id,
                                    ioc_type=_f5.ioc_type or "",
                                    ioc_value=_f5.ioc_value or "",
                                    source=(_f5.all_sources or ["unknown"])[0],
                                    db=db,
                                )
                                if _fp_memory_hit and _fp_memory_hit.get("auto_close"):
                                    _f5.ai_false_positive_flag = True
                                    _f5.ai_false_positive_reason = (
                                        f"FP Memory auto-close: {_fp_memory_hit.get('reason', '')[:200]} "
                                        f"(confirmed {_fp_memory_hit.get('hit_count', 0)}x, "
                                        f"conf={_fp_memory_hit.get('confidence', 0):.2f})"
                                    )
                                    from arguswatch.models import DetectionStatus as _DS_fp
                                    _f5.status = _DS_fp.FALSE_POSITIVE
                                    results["steps"].append(
                                        f"FP Memory auto-close: pattern#{_fp_memory_hit.get('pattern_id')} "
                                        f"hits={_fp_memory_hit.get('hit_count')} "
                                        f"conf={_fp_memory_hit.get('confidence', 0):.2f}"
                                    )
                                    await db.flush()
                                    # Skip AI triage entirely - known FP
                                    results["steps"].append("Skipped AI triage (known FP pattern)")
                                    return results
                            except Exception as _efp:
                                logger.debug(f"[pipeline] FP memory check failed (non-fatal): {_efp}")

                        # ── Step 5a: AI TRIAGE - AI sets severity (overrides rules) ──
                        _ai_triage_ok = False
                        # Fetch raw_text from underlying Detection for richer AI context
                        _raw_text_5a = ""
                        try:
                            from arguswatch.models import Detection as _Det5a
                            _det5a_r = await db.execute(
                                select(_Det5a.raw_text).where(
                                    _Det5a.finding_id == finding_id,
                                ).order_by(_Det5a.created_at.desc()).limit(1)
                            )
                            _raw_text_5a = (_det5a_r.scalar() or "")[:1500]
                        except Exception:
                            pass
                        try:
                            _ai_triage = await hook_ai_triage(
                                ioc_type=_f5.ioc_type or "",
                                ioc_value=_f5.ioc_value or "",
                                source=(_f5.all_sources or ["unknown"])[0],
                                enrichment_data=_enrich_data,
                                customer_context=_cctx5,
                                raw_text=_raw_text_5a,
                            )
                            if _ai_triage and "severity" in _ai_triage:
                                _f5.severity = _SL5(_ai_triage["severity"])
                                _f5.confidence = float(_ai_triage.get("confidence", _f5.confidence or 0.5))
                                _f5.ai_severity_decision = _ai_triage["severity"]
                                _f5.ai_severity_reasoning = _ai_triage.get("reasoning", "")
                                _f5.ai_severity_confidence = float(_ai_triage.get("confidence", 0))
                                _f5.ai_provider = _ai_triage.get("provider", "")
                                _ai_triage_ok = True
                                results["steps"].append(
                                    f"AI triage: {_ai_triage['severity']} "
                                    f"conf={_ai_triage.get('confidence',0):.2f} | "
                                    f"{_ai_triage.get('reasoning','')[:60]}"
                                )
                        except Exception as _e5a:
                            logger.debug(f"[pipeline] AI triage failed (rule fallback): {_e5a}")
                        if not _ai_triage_ok:
                            results["steps"].append(f"enrichment feedback (rules): {changes}")

                        # ── Step 5b: AI false positive check ──────────────
                        try:
                            _ai_fp = await hook_false_positive_check(
                                ioc_type=_f5.ioc_type or "",
                                ioc_value=_f5.ioc_value or "",
                                source=(_f5.all_sources or ["unknown"])[0],
                                enrichment_data=_enrich_data,
                                customer_context=_cctx5,
                            )
                            if _ai_fp and _ai_fp.get("is_fp") and _ai_fp.get("confidence", 0) > 0.75:
                                _f5.ai_false_positive_flag = True
                                _f5.ai_false_positive_reason = _ai_fp.get("reason", "")
                                from arguswatch.config import settings as _s5b
                                if getattr(_s5b, "AI_AUTONOMOUS", False):
                                    # AUTONOMOUS: auto-close the finding
                                    from arguswatch.models import DetectionStatus as _DS5
                                    _f5.status = _DS5.FALSE_POSITIVE
                                    results["steps"].append(
                                        f"AI FP auto-close: {_ai_fp.get('reason','')[:60]} "
                                        f"conf={_ai_fp.get('confidence',0):.2f}"
                                    )
                                else:
                                    # SAFE MODE: flag only, analyst reviews
                                    results["steps"].append(
                                        f"AI FP flagged (safe mode, not closed): "
                                        f"{_ai_fp.get('reason','')[:60]} "
                                        f"conf={_ai_fp.get('confidence',0):.2f}"
                                    )
                        except Exception as _e5b:
                            logger.debug(f"[pipeline] AI FP check failed: {_e5b}")

                        # ── Step 5c: AI investigation narrative ────────────
                        try:
                            _narr = await hook_investigation_narrative(
                                finding_id=finding_id,
                                ioc_value=_f5.ioc_value or "",
                                ioc_type=_f5.ioc_type or "",
                                enrichment_summary=_enrich_data,
                                actor_name=_f5.actor_name,
                                customer_name=_cctx5.get("name"),
                                severity=_sev(_f5.severity) or None,
                            )
                            if _narr:
                                _f5.ai_narrative = _narr
                                import datetime as _dt5
                                _f5.ai_enriched_at = _dt5.datetime.utcnow()
                                results["steps"].append(f"AI narrative ({len(_narr)} chars)")
                        except Exception as _e5c:
                            logger.debug(f"[pipeline] AI narrative failed: {_e5c}")

                        await db.commit()

            except Exception as e:
                logger.warning(f"[pipeline] AI enrichment step failed: {e}")

        # ── Step 6: Attribution - AI picks from candidates, SQL provides them ──
        try:
            async with async_session() as db:
                from arguswatch.models import Finding, ThreatActor, Customer as _C6
                from arguswatch.engine.attribution_engine import (
                    attribute_finding, get_candidate_actors, update_customer_exposure
                )
                from arguswatch.services.ai_pipeline_hooks import hook_attribution_assist
                rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                finding = rf.scalar_one_or_none()
                # Skip if orchestrator already attributed
                if _orchestration_handled_attribution and finding and finding.actor_name:
                    results["steps"].append(f"attribution: orchestrator set → {finding.actor_name}")
                elif finding and not finding.actor_id:

                    # Get full-metadata candidates from DB (IOC match + CVE + sector)
                    _candidates6 = await get_candidate_actors(finding, db)

                    # Build customer context for AI
                    _cctx6 = {}
                    if finding.customer_id:
                        _rc6 = await db.execute(select(_C6).where(_C6.id == finding.customer_id))
                        _cust6 = _rc6.scalar_one_or_none()
                        if _cust6:
                            _cctx6 = {
                                "industry": getattr(_cust6, "industry", ""),
                                "name": _cust6.name,
                                "country": getattr(_cust6, "country", ""),
                                "asset_type": finding.correlation_type or "",
                            }

                    actors = []
                    _ai_attr_result = None

                    if _candidates6:
                        # AI picks the best candidate with full metadata
                        try:
                            _ai_attr_result = await hook_attribution_assist(
                                finding_id=finding_id,
                                ioc_value=finding.ioc_value or "",
                                ioc_type=finding.ioc_type or "",
                                candidate_actors=_candidates6,
                                finding_context=_cctx6,
                            )
                        except Exception as _e6ai:
                            logger.debug(f"[pipeline] AI attribution failed: {_e6ai}")

                        if _ai_attr_result and _ai_attr_result.get("actor_name") and _ai_attr_result.get("confidence", 0) > 0.55:
                            # AI made a confident pick - use it
                            actors = [_ai_attr_result["actor_name"]]
                            # Find actor_id from DB
                            _ra6 = await db.execute(
                                select(ThreatActor).where(ThreatActor.name == _ai_attr_result["actor_name"]).limit(1)
                            )
                            _actor6 = _ra6.scalar_one_or_none()
                            if _actor6:
                                finding.actor_id = _actor6.id
                                finding.actor_name = _actor6.name
                            else:
                                finding.actor_name = _ai_attr_result["actor_name"]
                            finding.ai_attribution_reasoning = _ai_attr_result.get("narrative", "")
                            finding.ai_provider = finding.ai_provider or _ai_attr_result.get("provider", "")
                            results["steps"].append(
                                f"AI attribution: {_ai_attr_result['actor_name']} "
                                f"conf={_ai_attr_result.get('confidence',0):.2f} | "
                                f"{(_ai_attr_result.get('narrative',''))[:60]}"
                            )
                        else:
                            # AI not confident or unavailable - fall back to rule-based
                            actors = await attribute_finding(finding, db)
                            if actors:
                                results["steps"].append(f"rule attribution (AI low-conf): {actors}")

                    if actors:
                        if finding.customer_id:
                            for actor_name in actors:
                                await update_customer_exposure(
                                    finding.customer_id, actor_name, db, new_detection=True
                                )
                        await db.commit()
                        results["steps"].append(f"attributed → {actors[0]}")
                    else:
                        results["steps"].append("attribution: no match")
        except Exception as e:
            logger.warning(f"[pipeline] Attribution failed: {e}")

        # ── Step 6.5: AI severity re-score (post-attribution) ────────────────
        # Runs AFTER attribution - now AI knows BOTH enrichment data AND actor identity.
        # BUG 6 FIX: Skip if triage already ran with high confidence AND no actor
        # was found (meaning Step 6 didn't add new context worth re-evaluating).
        # BUG 5 FIX: Writes to ai_rescore_* columns, never overwrites triage columns.
        try:
            async with async_session() as db:
                from arguswatch.models import Finding, Customer as _C65, CveProductMap as _CPM65
                from arguswatch.services.ai_pipeline_hooks import hook_rescore_severity
                from arguswatch.config import settings as _s65
                rf65 = await db.execute(select(Finding).where(Finding.id == finding_id))
                _f65 = rf65.scalar_one_or_none()
                if _f65 and not _orchestration_handled_severity:

                    # BUG 6: Skip rescore if triage was high-confidence and no actor added new context
                    _triage_confident = (
                        getattr(_f65, "ai_severity_confidence", None) is not None
                        and float(getattr(_f65, "ai_severity_confidence", 0)) >= 0.75
                    )
                    _actor_added_context = bool(_f65.actor_name)
                    if _triage_confident and not _actor_added_context:
                        results["steps"].append(
                            f"rescore: SKIPPED (triage conf={_f65.ai_severity_confidence:.2f}, "
                            f"no actor - no new context to justify re-scoring)"
                        )
                    else:
                        _cctx65 = {"customer_id": _f65.customer_id}
                        if _f65.customer_id:
                            _rc65 = await db.execute(select(_C65).where(_C65.id == _f65.customer_id))
                            _cust65 = _rc65.scalar_one_or_none()
                            if _cust65:
                                _cctx65.update({"industry": getattr(_cust65, "industry", ""),
                                               "name": _cust65.name})

                        # Check CISA KEV status for CVE findings
                        _kev65 = False
                        if _f65.ioc_type == "cve_id":
                            _rkev = await db.execute(
                                select(_CPM65).where(_CPM65.cve_id == _f65.ioc_value.upper()).limit(1)
                            )
                            _cpm65 = _rkev.scalar_one_or_none()
                            _kev65 = bool(_cpm65 and _cpm65.actively_exploited)

                        # Get latest enrichment numbers
                        from arguswatch.models import Enrichment as _E65, Detection as _D65
                        _er65 = await db.execute(
                            select(_E65).join(_D65, _E65.detection_id == _D65.id)
                            .where(_D65.finding_id == finding_id)
                        )
                        _enrich65 = _er65.scalars().all()
                        _vt65 = next((e.data.get("malicious", 0) for e in _enrich65 if e.provider == "virustotal" and e.data), 0)
                        _ab65 = next((e.data.get("abuse_confidence", 0) for e in _enrich65 if e.provider == "abuseipdb" and e.data), 0)
                        _otx65 = next((e.data.get("pulse_count", 0) for e in _enrich65 if e.provider == "otx" and e.data), 0)

                        _rescore = await hook_rescore_severity(
                            finding_id=finding_id,
                            ioc_value=_f65.ioc_value or "",
                            ioc_type=_f65.ioc_type or "",
                            current_severity=_sev(_f65.severity) or "MEDIUM",
                            enrichment_data={"vt_malicious": _vt65, "abuse_score": _ab65, "otx_pulses": _otx65},
                            actor_name=_f65.actor_name,
                            customer_context=_cctx65,
                            cisa_kev=_kev65,
                            autonomous=getattr(_s65, "AI_AUTONOMOUS", False),
                        )

                        if _rescore and _rescore.get("severity"):
                            from arguswatch.models import SeverityLevel as _SL65
                            try:
                                _f65.severity = _SL65(_rescore["severity"])
                                # BUG 5 FIX: Write to rescore columns, not triage columns
                                _f65.ai_rescore_decision = _rescore["severity"]
                                _f65.ai_rescore_reasoning = _rescore.get("reasoning", "")
                                _f65.ai_rescore_confidence = float(_rescore.get("confidence", 0))
                                _f65.ai_provider = _rescore.get("provider", _f65.ai_provider or "")
                                if _rescore.get("sla_hours"):
                                    _f65.sla_hours = int(_rescore["sla_hours"])
                                await db.commit()
                                _mode_tag = "autonomous" if getattr(_s65, "AI_AUTONOMOUS", False) else "safe"
                                results["steps"].append(
                                    f"rescore[{_mode_tag}]: {_rescore['severity']} "
                                    f"conf={_rescore.get('confidence',0):.2f} "
                                    f"changed={_rescore.get('changed', False)} | "
                                    f"{_rescore.get('reasoning','')[:60]}"
                                )
                            except (ValueError, TypeError):
                                pass
        except Exception as e:
            logger.warning(f"[pipeline] Step 6.5 rescore failed: {e}")

        # ── Step 7: Campaign check ─────────────────────────────────────────────
        try:
            async with async_session() as db:
                from arguswatch.models import Finding
                from arguswatch.engine.campaign_detector import check_and_create_campaign
                rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                finding = rf.scalar_one_or_none()
                if finding and finding.actor_id:
                    campaign = await check_and_create_campaign(finding, db)
                    await db.commit()
                    if campaign:
                        results["steps"].append(
                            f"campaign: {campaign.name} stage={campaign.kill_chain_stage} "
                            f"findings={campaign.finding_count}"
                        )
                        # Step 7a: AI campaign narrative
                        try:
                            from arguswatch.services.ai_pipeline_hooks import hook_campaign_narrative
                            # Get customer name
                            cust_name = None
                            if finding.customer_id:
                                rc = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
                                cust = rc.scalar_one_or_none()
                                cust_name = cust.name if cust else None
                            narrative = await hook_campaign_narrative(
                                campaign_id=campaign.id,
                                actor_name=campaign.actor_name or "Unknown",
                                kill_chain_stage=campaign.kill_chain_stage or "unknown",
                                finding_count=campaign.finding_count or 1,
                                ioc_types=[finding.ioc_type or "unknown"],
                                customer_name=cust_name,
                            )
                            if narrative and hasattr(campaign, "ai_narrative"):
                                campaign.ai_narrative = narrative
                                await db.commit()
                                results["steps"].append(f"AI campaign narrative: {narrative[:60]}...")
                        except Exception as e:
                            logger.debug(f"[pipeline] AI campaign narrative failed (non-fatal): {e}")
        except Exception as e:
            logger.warning(f"[pipeline] Campaign check failed: {e}")

        # ── Step 8: Exposure recalculation (CRITICAL/HIGH only, rate-limited) ─
        try:
            async with async_session() as db:
                from arguswatch.models import Finding
                rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                finding = rf.scalar_one_or_none()
                if finding and finding.customer_id and finding.actor_id:
                    sev_val = _sev(finding.severity) or "LOW"
                    if sev_val in ("CRITICAL", "HIGH"):
                        from arguswatch.services.exposure_scorer import score_customer_actor
                        from arguswatch.models import CustomerExposure, Customer as Cust, ThreatActor
                        rc = await db.execute(select(Cust).where(Cust.id == finding.customer_id))
                        ra = await db.execute(select(ThreatActor).where(ThreatActor.id == finding.actor_id))
                        customer = rc.scalar_one_or_none()
                        actor = ra.scalar_one_or_none()
                        if customer and actor:
                            score, factors = await score_customer_actor(customer, actor, db)
                            from sqlalchemy import and_
                            re = await db.execute(select(CustomerExposure).where(
                                and_(CustomerExposure.customer_id == customer.id,
                                     CustomerExposure.actor_id == actor.id)))
                            exp = re.scalar_one_or_none()
                            from datetime import datetime
                            if exp:
                                exp.exposure_score = score
                                exp.factor_breakdown = factors
                                exp.recency_multiplier = factors.get("recency_multiplier", {}).get("value", 1.0)
                                exp.last_calculated = datetime.utcnow()
                            else:
                                from arguswatch.models import CustomerExposure as CE
                                db.add(CE(customer_id=customer.id, actor_id=actor.id,
                                          exposure_score=score, factor_breakdown=factors,
                                          recency_multiplier=factors.get("recency_multiplier", {}).get("value", 1.0),
                                          last_calculated=datetime.utcnow()))
                            await db.commit()
                            results["steps"].append(f"exposure recalculated: {score:.1f}")
        except Exception as e:
            logger.warning(f"[pipeline] Exposure recalc failed: {e}")

        # ── Step 9: Action generation (new findings only, MEDIUM+) ────────────
        if is_new_finding:
            try:
                async with async_session() as db:
                    from arguswatch.models import Finding
                    rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                    finding = rf.scalar_one_or_none()
                    sev_val = _sev(finding.severity) if finding and finding.severity else "LOW"
                    if finding and sev_val in ("CRITICAL", "HIGH", "MEDIUM"):
                        from arguswatch.engine.action_generator import generate_action
                        action = await generate_action(finding_id, db)
                        await db.commit()
                        if action:
                            results["steps"].append(
                                f"action created: {action.playbook_key} deadline={action.deadline}"
                            )
            except Exception as e:
                logger.warning(f"[pipeline] Action generation failed: {e}")

        # ── Step 10: Dispatch ──────────────────────────────────────────────────
        try:
            async with async_session() as db:
                from arguswatch.models import Finding, Customer
                from arguswatch.engine.alert_dispatcher import dispatch_detection_alert
                rf = await db.execute(select(Finding).where(Finding.id == finding_id))
                finding = rf.scalar_one_or_none()
                sev_val = _sev(finding.severity) if finding and finding.severity else "LOW"
                if finding and sev_val in ("CRITICAL", "HIGH"):
                    customer = None
                    if finding.customer_id:
                        rc = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
                        customer = rc.scalar_one_or_none()
                    # Reuse alert dispatcher - pass finding as a Detection-compatible object
                    # alert_dispatcher accepts any object with .ioc_value, .severity, .source, etc.
                    from arguswatch.engine.alert_dispatcher import dispatch_finding_alert
                    alert_result = await dispatch_finding_alert(finding, customer)
                    results["steps"].append(f"dispatched: {alert_result}")
        except Exception as e:
            logger.warning(f"[pipeline] Dispatch failed: {e}")

    except Exception as e:
        logger.error(f"[pipeline] Fatal error for detection {detection_id}: {e}")
        results["error"] = str(e)

    return results


# ═══════════════════════════════════════════════════════════════════════
# NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════

def _normalize_detection(det) -> None:
    """Normalize IOC value in-place. Mutates detection object (not committed yet)."""
    if not det.ioc_value:
        return
    val = det.ioc_value.strip()
    # Lowercase everything except hashes (case-sensitive) and API keys
    if det.ioc_type not in ("sha256", "md5", "sha1", "aws_access_key", "github_pat"):
        val = val.lower()
    # Strip common URL wrappers
    if val.startswith("hxxp"):
        val = "http" + val[4:]
    if val.startswith("hxxps"):
        val = "https" + val[5:]
    # Strip defanging
    val = val.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    det.ioc_value = val


# ═══════════════════════════════════════════════════════════════════════
# BATCH PIPELINE (Celery beat every 5 min)
# ═══════════════════════════════════════════════════════════════════════

async def _async_batch_pipeline() -> dict:
    """Process any NEW detections that missed the real-time pipeline."""
    from arguswatch.database import async_session
    from arguswatch.models import Detection, DetectionStatus
    from sqlalchemy import select, and_

    stats = {"queued": 0, "errors": 0}
    async with async_session() as db:
        r = await db.execute(
            select(Detection.id)
            .where(and_(
                Detection.status == DetectionStatus.NEW,
                Detection.finding_id == None,
            ))
            .order_by(Detection.id.desc())
            .limit(200)
        )
        ids = [row[0] for row in r.all()]

    for det_id in ids:
        try:
            fire_pipeline(det_id)
            stats["queued"] += 1
        except Exception as e:
            logger.debug(f"Batch queue error {det_id}: {e}")
            stats["errors"] += 1

    logger.info(f"[batch pipeline] {stats}")
    return stats


# ═══════════════════════════════════════════════════════════════════════
# 72h RECHECK (Celery beat every hour - checks findings past SLA)
# ═══════════════════════════════════════════════════════════════════════

async def _async_recheck() -> dict:
    """Re-evaluate findings that are still open past their SLA deadline or 72h old."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding, FindingRemediation, DetectionStatus, SeverityLevel
    from sqlalchemy import select, and_
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    recheck_cutoff = now - timedelta(hours=72)
    stats = {"rechecked": 0, "closed": 0, "overdue": 0, "errors": 0}

    async with async_session() as db:
        # Open findings older than 72h
        r = await db.execute(
            select(Finding).where(
                and_(
                    Finding.status.notin_([
                        DetectionStatus.VERIFIED_CLOSED,
                        DetectionStatus.FALSE_POSITIVE,
                        DetectionStatus.CLOSED,
                    ]),
                    Finding.created_at <= recheck_cutoff,
                )
            ).limit(50)
        )
        findings = r.scalars().all()

        for finding in findings:
            try:
                stats["rechecked"] += 1

                # Check if all remediations are completed
                rem_r = await db.execute(
                    select(FindingRemediation).where(
                        FindingRemediation.finding_id == finding.id
                    )
                )
                remediations = rem_r.scalars().all()
                all_done = remediations and all(
                    r.status in ("completed", "false_positive") for r in remediations
                )

                # Overdue check
                if finding.sla_deadline and now > finding.sla_deadline:
                    if finding.status not in [
                        DetectionStatus.VERIFIED_CLOSED,
                        DetectionStatus.ESCALATION,
                    ]:
                        finding.status = DetectionStatus.ESCALATION
                        stats["overdue"] += 1
                        logger.warning(
                            f"Finding {finding.id} SLA BREACHED - "
                            f"deadline was {finding.sla_deadline}, escalating"
                        )

                # Auto-close if all remediations done
                if all_done:
                    finding.status = DetectionStatus.VERIFIED_CLOSED
                    finding.resolved_at = now
                    stats["closed"] += 1
                    logger.info(f"Finding {finding.id} auto-closed - all remediations complete")

            except Exception as e:
                logger.debug(f"Recheck error finding {finding.id}: {e}")
                stats["errors"] += 1

        await db.commit()

    # REOPEN: closed findings that got new detections
    reopen = await _reopen_recurrent_findings()
    stats["reopened"] = reopen.get("reopened", 0)

    logger.info(f"[recheck] {stats}")
    return stats


async def _reopen_recurrent_findings() -> dict:
    """Reopen findings closed but with new detections since closure."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding, Detection, DetectionStatus
    from sqlalchemy import select, and_
    from datetime import datetime

    stats = {"checked": 0, "reopened": 0}

    async with async_session() as db:
        r = await db.execute(
            select(Finding).where(
                Finding.status.in_([
                    DetectionStatus.VERIFIED_CLOSED,
                    DetectionStatus.CLOSED,
                ]),
                Finding.resolved_at != None,
            ).limit(200)
        )
        closed_findings = r.scalars().all()

        for finding in closed_findings:
            stats["checked"] += 1
            if not finding.customer_id:
                continue
            # Any detection for same IOC+customer created AFTER this finding was closed?
            new_det_r = await db.execute(
                select(Detection).where(
                    and_(
                        Detection.ioc_value == finding.ioc_value,
                        Detection.customer_id == finding.customer_id,
                        Detection.created_at > finding.resolved_at,
                    )
                ).limit(1)
            )
            new_det = new_det_r.scalar_one_or_none()
            if new_det:
                finding.status = DetectionStatus.NEW
                finding.resolved_at = None
                finding.last_seen = datetime.utcnow()
                finding.source_count = (finding.source_count or 1) + 1
                new_det.finding_id = finding.id
                stats["reopened"] += 1
                logger.warning(
                    f"Finding {finding.id} REOPENED - new detection "
                    f"for {finding.ioc_value[:50]} after prior closure"
                )

        await db.commit()

    return stats
