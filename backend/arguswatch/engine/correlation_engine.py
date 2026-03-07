"""Correlation Engine - wires customer_router.py into every detection.

V10 changes:
- Sets detection.correlation_type from the best match's correlation_type
- Calls find_cross_source_signals() after routing and writes source_count to detection
- Deduplication: if same ioc_value already exists for a customer, bump source_count
  and last_seen rather than creating a duplicate row
"""
import logging
import re
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from arguswatch.models import Detection, CustomerAsset, DetectionStatus
from arguswatch.engine.customer_router import CustomerAssetRecord, route_to_customers
from arguswatch.models import CveProductMap

logger = logging.getLogger("arguswatch.engine.correlation")



def _version_in_range(version_str: str, version_range: str) -> bool:
    """Check if a version string falls within a CVE's affected version range.

    version_range from cve_product_map is formatted like: "< 7.4.3" or ">= 7.0, < 7.2.5"
    Returns True (vulnerable) if version is in range, False (patched/unaffected) if not.
    Returns True when range can't be parsed (conservative - flag it rather than miss it).
    """
    if not version_range or not version_str:
        return True  # No range data - conservatively flag as potentially vulnerable

    def _parse_ver(s: str):
        """Parse "7.2.1" → (7, 2, 1) tuple for comparison."""
        try:
            return tuple(int(x) for x in re.split(r"[.\-]", s.strip())[:4])
        except ValueError:
            return None

    try:
        asset_ver = _parse_ver(version_str)
        if not asset_ver:
            return True  # Can't parse asset version - flag conservatively

        # Parse each condition in the range (comma-separated)
        conditions = [c.strip() for c in version_range.split(",")]
        for condition in conditions:
            condition = condition.strip()
            if condition.startswith("<= "):
                bound = _parse_ver(condition[3:])
                if bound and asset_ver > bound:
                    return False  # Asset version is newer - not vulnerable
            elif condition.startswith("< "):
                bound = _parse_ver(condition[2:])
                if bound and asset_ver >= bound:
                    return False  # Asset version meets or exceeds fix version
            elif condition.startswith(">= "):
                bound = _parse_ver(condition[3:])
                if bound and asset_ver < bound:
                    return False  # Asset version is older than range start
        return True  # All conditions passed - in range (vulnerable)
    except Exception:
        return True  # Parse error - flag conservatively


async def route_detection(detection: Detection, db: AsyncSession) -> list[int]:
    """Match a detection against all customer assets.

    V10: Also sets correlation_type and source_count on the detection.
    Returns list of matched customer_ids.
    """
    r = await db.execute(select(CustomerAsset))
    assets = r.scalars().all()
    records = [CustomerAssetRecord(
        customer_id=a.customer_id,
        customer_name="",
        asset_type=a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
        asset_value=a.asset_value,
        criticality=a.criticality or "medium",
    ) for a in assets
        # V16.4.6: Skip unconfirmed industry defaults — they generate false CVE matches.
        # Visible in UI but don't route until analyst confirms (changes discovery_source).
        if not (
            (a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type)) == "tech_stack"
            and getattr(a, "discovery_source", None) == "industry_default"
        )
    ]

    matches = route_to_customers(detection.ioc_value, detection.ioc_type, records)
    # V16.4.5: ONLY use raw_text fallback for IOCs that don't carry domain info.
    RAW_TEXT_SAFE_TYPES = {
        "cve_id", "advisory", "sha256", "sha1", "md5", "sha512",
        "malware_hash", "apt_group", "ransomware_group", "campaign",
    }
    if not matches and detection.raw_text and detection.ioc_type in RAW_TEXT_SAFE_TYPES:
        matches = route_to_customers(detection.raw_text, detection.ioc_type, records)

    # V16.4.6: Self-referential exclusion — don't route IOCs found ON a platform
    # back TO that platform as a victim. Example: github_gist collector finds a URL
    # on gist.github.com → don't create a finding for GitHub-the-customer.
    _COLLECTOR_PLATFORMS = {
        "github_gist":  {"github.com", "gist.github.com", "githubusercontent.com"},
        "grep_app":     {"github.com", "gist.github.com", "githubusercontent.com"},
        "paste":        {"pastebin.com", "dpaste.org", "rentry.co"},
    }
    if matches and detection.ioc_type in ("url", "uri", "domain", "fqdn", "hostname"):
        src_platforms = _COLLECTOR_PLATFORMS.get(detection.source, set())
        if src_platforms:
            _url_m = re.search(r'https?://([^/?\s:]+)', detection.ioc_value.lower())
            _ioc_dom = _url_m.group(1) if _url_m else detection.ioc_value.lower()
            _on_platform = any(_ioc_dom == p or _ioc_dom.endswith("." + p) for p in src_platforms)
            if _on_platform:
                matches = [m for m in matches if not any(
                    p == d or p.endswith("." + d)
                    for p in src_platforms
                    for d in [r.asset_value.lower() for r in records
                              if r.customer_id == m.customer_id and r.asset_type == "domain"]
                )]

    # ── CVE → cve_product_map → tech_stack routing ───────────────────────────
    # If a CVE ID arrives and no asset matched via text, look up the affected
    # products in cve_product_map, then check if any customer has that product
    # in their tech_stack assets. This is the CRITICAL path for KEV→customer routing.
    if not matches and detection.ioc_type == "cve_id":
        from arguswatch.engine.customer_router import RoutedDetection
        cve_upper = detection.ioc_value.upper()
        cpm_r = await db.execute(
            select(CveProductMap).where(CveProductMap.cve_id == cve_upper)
        )
        cpe_products = cpm_r.scalars().all()
        if cpe_products:
            product_names = [p.product_name.lower() for p in cpe_products]
            tech_assets = [r for r in records if r.asset_type == "tech_stack"]
            for asset in tech_assets:
                av_lower = asset.asset_value.lower()
                # Extract product name and version from "FortiOS 7.2"
                # product_clean = "fortios", asset_version = "7.2"
                version_match = re.search(r"(\d[\d.]+)", av_lower)
                asset_version = version_match.group(1) if version_match else None
                product_clean = re.split(r"\s+\d", av_lower)[0].strip()
                product_nospace = re.sub(r"\s+", "", product_clean)

                for cpe_row in cpe_products:
                    pname_nospace = re.sub(r"\s+", "", cpe_row.product_name.lower())
                    if not (len(product_nospace) >= 4 and
                            (product_nospace in pname_nospace or
                             pname_nospace in product_nospace)):
                        continue

                    # Product name matched - now version check
                    # If we have both a version range and an asset version, check it
                    version_range = cpe_row.version_range or ""
                    version_ok = True
                    if asset_version and version_range:
                        version_ok = _version_in_range(asset_version, version_range)

                    if not version_ok:
                        logger.debug(
                            f"CVE routing: {cve_upper} product match '{cpe_row.product_name}' "
                            f"BUT customer version {asset_version} outside range '{version_range}' "
                            f"- skipping customer {asset.customer_id}"
                        )
                        continue

                    matches.append(RoutedDetection(
                        customer_id=asset.customer_id,
                        customer_name=asset.customer_name,
                        matched_asset_type="tech_stack",
                        matched_asset_value=asset.asset_value,
                        ioc_value=detection.ioc_value,
                        criticality=asset.criticality,
                        correlation_type="tech_stack",
                    ))
                    logger.info(
                        f"CVE routing: {cve_upper} → product '{cpe_row.product_name}' "
                        f"(range: '{version_range}') → customer {asset.customer_id} "
                        f"via tech_stack '{asset.asset_value}'"
                    )
                    break

    if matches:
        # Pick best match: prioritise criticality, then most specific corr_type
        CORR_SPECIFICITY = {
            "exact_domain": 10, "exact_ip": 10, "exact_email": 10,
            "subdomain": 8, "ip_range": 8, "email_pattern": 8,
            "tech_stack": 7, "typosquat": 7, "exec_name": 7,
            "cloud_asset": 6, "code_repo": 6,
            "keyword": 3,
        }
        CRIT_SCORE = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        best = max(matches, key=lambda m: (
            CRIT_SCORE.get(m.criticality, 0),
            CORR_SPECIFICITY.get(m.correlation_type, 0),
        ))
        detection.customer_id = best.customer_id
        detection.matched_asset = best.matched_asset_value
        detection.correlation_type = best.correlation_type  # V10

        # V13: Update matched asset's hit count and last_seen
        try:
            from datetime import datetime as _dt_corr
            matched_assets = await db.execute(
                select(CustomerAsset).where(
                    CustomerAsset.customer_id == best.customer_id,
                    CustomerAsset.asset_value == best.matched_asset_value,
                )
            )
            for ma in matched_assets.scalars().all():
                ma.ioc_hit_count = (ma.ioc_hit_count or 0) + 1
                ma.last_seen_in_ioc = _dt_corr.utcnow()
                # Append correlation source if not already tracked
                sources = ma.confidence_sources or []
                src_tag = f"collector:{detection.source}" if detection.source else "collector"
                if src_tag not in sources:
                    ma.confidence_sources = sources + [src_tag]
        except Exception as _e_hit:
            logger.debug(f"Asset hit count update failed: {_e_hit}")

        # V10: cross-source signal count
        cross = await find_cross_source_signals(db, detection.ioc_value)
        detection.source_count = cross["source_count"]
        # Boost severity if multi-source confirmed
        if cross["cross_source_confirmed"] and detection.severity:
            from arguswatch.models import SeverityLevel
            sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current = _sev(detection.severity) if hasattr(detection.severity, "value") else str(detection.severity)
            idx = sev_order.index(current) if current in sev_order else 2
            if idx < len(sev_order) - 1:
                detection.severity = SeverityLevel(sev_order[idx + 1])
                logger.info(
                    f"Upgraded severity of {detection.ioc_value[:50]} to "
                    f"{detection.severity} - {cross['source_count']} sources"
                )

        logger.info(
            f"Routed {detection.ioc_value[:50]} → customer {best.customer_id} "
            f"via {best.correlation_type} ({cross['source_count']} sources)"
        )
        return [m.customer_id for m in matches]
    return []


async def correlate_new_detections(db: AsyncSession, limit: int = 100, ai_triage: bool = False) -> dict:
    """Route all unrouted detections to customers AND promote to findings.
    
    V16.4.5: Now also:
    - Populates match_proof JSON on findings
    - Creates remediations via action_generator
    - Generates enrichment_narrative for CVE findings
    V16.4.6: ai_triage=True enables Ollama AI hooks (slow — only for targeted runs)
    """
    r = await db.execute(
        select(Detection).where(
            Detection.customer_id == None,
            Detection.status == DetectionStatus.NEW,
        ).limit(limit)
    )
    unrouted = r.scalars().all()
    stats = {"processed": len(unrouted), "routed": 0, "unrouted": 0,
             "findings_created": 0, "remediations_created": 0, "proofs_added": 0}
    for det in unrouted:
        matched = await route_detection(det, db)
        if matched:
            stats["routed"] += 1
            # ── Finding Promotion: create Finding for every routed detection ──
            try:
                from arguswatch.engine.finding_manager import get_or_create_finding
                f, is_new = await get_or_create_finding(det, db)
                if is_new:
                    stats["findings_created"] += 1

                    # ── V16.4.5: Populate match_proof ──────────────────────
                    try:
                        proof = {
                            "correlation_type": det.correlation_type,
                            "matched_asset": det.matched_asset,
                            "ioc_value": det.ioc_value[:200],
                            "ioc_type": det.ioc_type,
                            "source": det.source,
                            "confidence": det.confidence,
                        }
                        f.match_proof = proof
                        stats["proofs_added"] += 1
                    except Exception as e_proof:
                        logger.debug(f"Match proof failed for finding {f.id}: {e_proof}")

                    # ── V16.4.5: Generate remediation ──────────────────────
                    try:
                        from arguswatch.engine.action_generator import generate_action
                        rem = await generate_action(f.id, db)
                        if rem:
                            stats["remediations_created"] += 1
                    except Exception as e_rem:
                        logger.debug(f"Remediation failed for finding {f.id}: {e_rem}")

                    # ── V16.4.5: Enrichment narrative for CVE findings ─────
                    try:
                        if det.ioc_type == "cve_id" and not f.enrichment_narrative:
                            f.enrichment_narrative = (
                                f"CVE matched via {det.correlation_type} against "
                                f"customer asset '{det.matched_asset}'. "
                                f"Source: {det.source}. "
                                f"Confidence: {det.confidence:.0%}."
                            )
                    except Exception as e_enrich:
                        logger.debug(f"Enrichment narrative failed: {e_enrich}")

                    # ── V16.4.5: Template ai_narrative (LLM-free fallback) ──
                    try:
                        if not f.ai_narrative:
                            sev_str = _sev(f.severity) or "MEDIUM"
                            src = det.source or "unknown"
                            _NARR_TEMPLATES = {
                                "cve_id": f"{src}: {det.ioc_value} affects {det.matched_asset or 'customer infrastructure'} — patch immediately if in-scope",
                                "email_password_combo": f"{src}: Credential for {det.ioc_value.split(':')[0] if ':' in det.ioc_value else det.ioc_value[:30]} exposed — force password reset and enable MFA",
                                "username_password_combo": f"{src}: Credential pair exposed — force password reset and audit login history",
                                "breachdirectory_combo": f"{src}: Breach credential found — check for password reuse across corporate systems",
                                "url": f"{src}: Suspicious URL {det.ioc_value[:50]} detected targeting customer domain",
                                "domain": f"{src}: Suspicious domain {det.ioc_value} — possible phishing or typosquat",
                                "email": f"{src}: Email address {det.ioc_value} found in threat feed — monitor for targeted attacks",
                                "exposed_secret": f"{src}: Exposed secret/key found — rotate immediately",
                                "privileged_credential": f"{src}: Privileged credential exposed — rotate and audit access logs",
                                "malicious_url_path": f"{src}: Malicious URL path detected — block in WAF/proxy",
                            }
                            f.ai_narrative = _NARR_TEMPLATES.get(
                                det.ioc_type,
                                f"{src}: {sev_str} {det.ioc_type} finding — {det.ioc_value[:50]} matched via {det.correlation_type}"
                            )
                    except Exception as e_narr:
                        logger.debug(f"AI narrative template failed: {e_narr}")

                    # ── V16.4.6: AI TRIAGE via Ollama/Cloud (overrides template) ──
                    # Only runs when ai_triage=True (not during bulk match-intel-all)
                    if ai_triage:
                      try:
                        from arguswatch.services.ai_pipeline_hooks import (
                            hook_ai_triage, hook_false_positive_check,
                            hook_investigation_narrative, _pipeline_ai_available,
                        )
                        if _pipeline_ai_available():
                            from arguswatch.models import Customer as _CustAI, SeverityLevel as _SevAI
                            _cctx = {"matched_asset": det.matched_asset or ""}
                            if det.customer_id:
                                _cr_ai = await db.execute(
                                    select(_CustAI).where(_CustAI.id == det.customer_id))
                                _c_ai = _cr_ai.scalar_one_or_none()
                                if _c_ai:
                                    _cctx.update({"industry": _c_ai.industry or "",
                                                  "name": _c_ai.name, "customer_id": _c_ai.id})
                            _enrich = {"vt_malicious": 0, "abuse_score": 0, "otx_pulses": 0}

                            # AI severity triage
                            _ai_t = await hook_ai_triage(
                                ioc_type=det.ioc_type or "", ioc_value=det.ioc_value or "",
                                source=det.source or "unknown", enrichment_data=_enrich,
                                customer_context=_cctx, raw_text=(det.raw_text or "")[:800],
                            )
                            if _ai_t and "severity" in _ai_t:
                                f.severity = _SevAI(_ai_t["severity"])
                                f.confidence = float(_ai_t.get("confidence", f.confidence or 0.5))
                                f.ai_severity_decision = _ai_t["severity"]
                                f.ai_severity_reasoning = _ai_t.get("reasoning", "")
                                f.ai_provider = _ai_t.get("provider", "")
                                stats["ai_triaged"] = stats.get("ai_triaged", 0) + 1
                                logger.info(f"AI triage: {det.ioc_value[:40]} → {_ai_t['severity']}")

                            # AI false positive check
                            _ai_fp = await hook_false_positive_check(
                                ioc_type=det.ioc_type or "", ioc_value=det.ioc_value or "",
                                source=det.source or "unknown", enrichment_data=_enrich,
                                customer_context=_cctx,
                            )
                            if _ai_fp and _ai_fp.get("is_fp") and _ai_fp.get("confidence", 0) > 0.75:
                                f.ai_false_positive_flag = True
                                f.ai_false_positive_reason = _ai_fp.get("reason", "")
                                logger.info(f"AI FP flag: {det.ioc_value[:40]} — {_ai_fp.get('reason','')[:60]}")

                            # AI narrative (replaces template if better)
                            try:
                                _ai_narr = await hook_investigation_narrative(
                                    ioc_type=det.ioc_type or "", ioc_value=det.ioc_value or "",
                                    source=det.source or "unknown", enrichment_data=_enrich,
                                    customer_context=_cctx,
                                )
                                if _ai_narr and _ai_narr.get("narrative"):
                                    f.ai_narrative = _ai_narr["narrative"]
                            except Exception:
                                pass  # Keep template narrative
                      except Exception as e_ai:
                        logger.debug(f"AI triage hooks failed (template retained): {e_ai}")

            except Exception as e:
                logger.warning(f"Finding promotion failed for det {det.id}: {e}")
        else:
            stats["unrouted"] += 1
    await db.flush()
    return stats


async def find_cross_source_signals(db: AsyncSession, ioc_value: str) -> dict:
    """Find how many sources have seen the same IOC - higher count = stronger signal."""
    r = await db.execute(
        select(Detection.source, Detection.severity, Detection.confidence)
        .where(Detection.ioc_value == ioc_value)
    )
    rows = r.all()
    sources = list({row.source for row in rows})
    SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_sev = max(
        (_sev(row.severity) or "LOW" for row in rows),
        key=lambda s: SEV_RANK.get(s, 0),
        default="LOW",
    )
    avg_conf = sum(row.confidence or 0 for row in rows) / len(rows) if rows else 0
    return {
        "source_count": len(sources) if sources else 1,
        "sources": sources,
        "max_severity": max_sev,
        "avg_confidence": round(avg_conf, 2),
        "cross_source_confirmed": len(sources) >= 2,
    }


from arguswatch.celery_app import celery_app as _celery_app

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)



@_celery_app.task(name="arguswatch.engine.correlation_engine.run_correlation_task")
def run_correlation_task():
    import asyncio
    from arguswatch.database import async_session
    async def _run():
        async with async_session() as db:
            return await correlate_new_detections(db)
    return asyncio.run(_run())


async def backfill_findings(db: AsyncSession) -> dict:
    """V16.4.5: Backfill match_proof, remediations, and enrichment_narrative
    for existing findings that are missing them."""
    from arguswatch.models import Finding, FindingRemediation
    stats = {"proofs_added": 0, "remediations_created": 0, "narratives_added": 0}

    r = await db.execute(select(Finding))
    findings = r.scalars().all()

    for f in findings:
        # ── match_proof ───────────────────────────────────────────────
        if not f.match_proof or f.match_proof == {}:
            f.match_proof = {
                "correlation_type": f.correlation_type,
                "matched_asset": f.matched_asset,
                "ioc_value": f.ioc_value[:200] if f.ioc_value else "",
                "ioc_type": f.ioc_type,
                "sources": f.all_sources or [],
                "confidence": f.confidence,
            }
            stats["proofs_added"] += 1

        # ── enrichment_narrative for CVEs ─────────────────────────────
        if f.ioc_type == "cve_id" and not f.enrichment_narrative:
            f.enrichment_narrative = (
                f"CVE matched via {f.correlation_type} against "
                f"customer asset '{f.matched_asset}'. "
                f"Sources: {', '.join(f.all_sources or ['unknown'])}. "
                f"Confidence: {f.confidence:.0%}."
            )
            stats["narratives_added"] += 1

        # ── remediations ──────────────────────────────────────────────
        existing_rem = await db.execute(
            select(FindingRemediation).where(
                FindingRemediation.finding_id == f.id
            ).limit(1)
        )
        if not existing_rem.scalar_one_or_none():
            try:
                from arguswatch.engine.action_generator import generate_action
                rem = await generate_action(f.id, db)
                if rem:
                    stats["remediations_created"] += 1
            except Exception as e:
                logger.debug(f"Backfill remediation failed for finding {f.id}: {e}")

    await db.flush()
    return stats
