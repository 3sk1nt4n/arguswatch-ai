"""
ArgusWatch AI Routes -  Extracted from main.py
All AI-related endpoints: triage, chat, investigate, match confidence, etc.
"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel

from arguswatch.database import get_db
from arguswatch.auth import require_role
from arguswatch.config import settings
from arguswatch.models import (
    Detection, Finding, FindingRemediation, Customer, CustomerAsset,
    ThreatActor, SeverityLevel, DetectionStatus, ExposureHistory,
)

logger = logging.getLogger("arguswatch.api.ai")

router = APIRouter(tags=["ai"])

# ── ai-triage ──
@router.post("/api/ai-triage", dependencies=[Depends(require_role("admin", "analyst"))])
async def ai_triage_endpoint(limit: int = 5, db: AsyncSession = Depends(get_db)):
    """Run AI triage on findings that haven't been triaged yet.
    Default: 5 findings at a time (~2-3 min with Ollama qwen3:8b).
    Call repeatedly to process more.
    """
    from arguswatch.services.ai_pipeline_hooks import (
        hook_ai_triage, hook_false_positive_check,
        hook_investigation_narrative, _pipeline_ai_available, _provider,
    )
    from arguswatch.models import Finding, Customer, SeverityLevel

    if not _pipeline_ai_available():
        return {"error": "No AI provider available. Check Ollama or set ANTHROPIC_API_KEY."}

    # Find findings without AI triage
    r = await db.execute(
        select(Finding).where(
            Finding.ai_provider == None,
            Finding.status.notin_(["FALSE_POSITIVE", "VERIFIED_CLOSED"]),
        ).order_by(Finding.created_at.desc()).limit(min(limit, 20))
    )
    findings = r.scalars().all()
    if not findings:
        return {"message": "All findings already triaged", "triaged": 0, "provider": _provider()}

    stats = {"triaged": 0, "fp_flagged": 0, "narratives": 0, "errors": 0, "provider": _provider(), "details": []}

    for f in findings:
        try:
            # Build customer context
            cctx = {"matched_asset": f.matched_asset or ""}
            if f.customer_id:
                cr = await db.execute(select(Customer).where(Customer.id == f.customer_id))
                cust = cr.scalar_one_or_none()
                if cust:
                    cctx.update({"industry": cust.industry or "", "name": cust.name, "customer_id": cust.id})

            enrich = {"vt_malicious": 0, "abuse_score": 0, "otx_pulses": 0}

            # 1. AI severity triage
            ai_t = await hook_ai_triage(
                ioc_type=f.ioc_type or "", ioc_value=f.ioc_value or "",
                source=(f.all_sources or ["unknown"])[0] if isinstance(f.all_sources, list) else "unknown",
                enrichment_data=enrich, customer_context=cctx,
                raw_text="",
            )
            if ai_t and "severity" in ai_t:
                f.severity = SeverityLevel(ai_t["severity"])
                f.confidence = float(ai_t.get("confidence", f.confidence or 0.5))
                f.ai_severity_decision = ai_t["severity"]
                f.ai_severity_reasoning = ai_t.get("reasoning", "")
                f.ai_provider = ai_t.get("provider", "")
                stats["triaged"] += 1
                stats["details"].append({"ioc": (f.ioc_value or "")[:40], "severity": ai_t["severity"]})
            else:
                stats["errors"] += 1
                stats["details"].append({"ioc": (f.ioc_value or "")[:40], "error": "AI returned empty/invalid response"})

            # 2. AI false positive check
            ai_fp = await hook_false_positive_check(
                ioc_type=f.ioc_type or "", ioc_value=f.ioc_value or "",
                source=(f.all_sources or ["unknown"])[0] if isinstance(f.all_sources, list) else "unknown",
                enrichment_data=enrich, customer_context=cctx,
            )
            if ai_fp and ai_fp.get("is_fp") and ai_fp.get("confidence", 0) > 0.75:
                f.ai_false_positive_flag = True
                f.ai_false_positive_reason = ai_fp.get("reason", "")
                stats["fp_flagged"] += 1

            # 3. AI narrative
            try:
                ai_narr = await hook_investigation_narrative(
                    ioc_type=f.ioc_type or "", ioc_value=f.ioc_value or "",
                    source=(f.all_sources or ["unknown"])[0] if isinstance(f.all_sources, list) else "unknown",
                    enrichment_data=enrich, customer_context=cctx,
                )
                if ai_narr and ai_narr.get("narrative"):
                    f.ai_narrative = ai_narr["narrative"]
                    stats["narratives"] += 1
            except Exception as e:
                logger.debug(f"Suppressed: {e}")
        except Exception as e:
            stats["errors"] += 1
            stats["details"].append({"ioc": (f.ioc_value or "")[:40], "exception": str(e)[:100]})

    await db.commit()
    stats["remaining"] = await db.scalar(
        select(func.count(Finding.id)).where(Finding.ai_provider == None,
            Finding.status.notin_(["FALSE_POSITIVE", "VERIFIED_CLOSED"]))
    ) or 0
    stats["details"] = stats["details"][:10]  # Limit to 10 for readability
    return stats

# ── pipeline-fixup ──
@router.post("/api/pipeline-fixup", dependencies=[Depends(require_role("admin", "analyst"))])
async def pipeline_fixup_endpoint(db: AsyncSession = Depends(get_db)):
    """V16.4.5: Fix-up pipeline for existing findings.
    
    Backfills: match_proof, enrichment_narrative, remediations.
    No AI API key required - uses rule-based logic only.
    
    Steps:
    1. Promote matched detections without findings -> create findings
    2. Generate match_proof for findings without it
    3. Generate enrichment_narrative from existing data
    4. Generate remediations via action_generator
    """
    from arguswatch.engine.finding_manager import get_or_create_finding
    from arguswatch.engine.action_generator import generate_action
    from arguswatch.models import Finding, Detection, Customer, FindingRemediation
    from sqlalchemy import select, and_
    import json
    
    stats = {
        "findings_promoted": 0,
        "match_proof_set": 0,
        "narratives_set": 0,
        "remediations_created": 0,
        "errors": 0,
    }
    
    # Step 1: Promote matched-but-no-finding detections
    orphan_r = await db.execute(
        select(Detection).where(
            and_(
                Detection.customer_id.isnot(None),
                Detection.finding_id.is_(None),
            )
        ).limit(500)
    )
    for det in orphan_r.scalars().all():
        try:
            f, is_new = await get_or_create_finding(det, db)
            if is_new:
                stats["findings_promoted"] += 1
        except Exception as e:
            stats["errors"] += 1
    await db.flush()
    
    # Step 2+3: Backfill match_proof and enrichment_narrative
    all_findings_r = await db.execute(select(Finding).limit(2000))
    for finding in all_findings_r.scalars().all():
        # match_proof
        if not finding.match_proof or finding.match_proof == {} or finding.match_proof is None:
            proof = {
                "correlation_type": finding.correlation_type or "unknown",
                "matched_asset": finding.matched_asset or "none",
                "ioc_type": finding.ioc_type,
                "ioc_value_preview": (finding.ioc_value or "")[:100],
                "confidence": finding.confidence or 0,
                "source_count": finding.source_count or 1,
                "all_sources": list(finding.all_sources or []),
            }
            finding.match_proof = proof
            stats["match_proof_set"] += 1
        
        # enrichment_narrative
        if not finding.enrichment_narrative:
            customer_name = ""
            if finding.customer_id:
                cr = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
                cust = cr.scalar_one_or_none()
                customer_name = cust.name if cust else ""
            
            parts = []
            parts.append(f"{finding.ioc_type} detection for {customer_name}.")
            if finding.correlation_type:
                parts.append(f"Matched via {finding.correlation_type} against asset '{finding.matched_asset or 'unknown'}'.")
            if finding.source_count and finding.source_count > 1:
                parts.append(f"Confirmed by {finding.source_count} independent sources ({', '.join(finding.all_sources or [])}).")
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity or 'MEDIUM')
            parts.append(f"Severity: {sev}. Confidence: {finding.confidence or 0:.0%}.")
            
            finding.enrichment_narrative = " ".join(parts)
            stats["narratives_set"] += 1
    
    await db.flush()
    
    # Step 4: Generate remediations
    all_f_r = await db.execute(select(Finding.id).limit(2000))
    for row in all_f_r.all():
        try:
            rem = await generate_action(row[0], db)
            if rem:
                stats["remediations_created"] += 1
        except Exception as e:
            stats["errors"] += 1
    
    await db.commit()
    return stats



# ── ai-remediation-regen ──
@router.post("/api/ai-remediation-regen", dependencies=[Depends(require_role("admin", "analyst"))])
async def ai_remediation_regen(limit: int = 5, db: AsyncSession = Depends(get_db)):
    """Regenerate remediations using AI for findings that have template-based remediations.
    Deletes old template remediations and creates new AI-customized ones.
    Default: 5 at a time (~30-60s each with Ollama).
    """
    from arguswatch.engine.action_generator import generate_action

    # Find findings that have template remediations (playbook_key NOT ending in _ai)
    r = await db.execute(
        select(FindingRemediation.finding_id).where(
            ~FindingRemediation.playbook_key.like("%_ai"),
            FindingRemediation.status == "pending",
        ).distinct().limit(min(limit, 20))
    )
    finding_ids = [row[0] for row in r.all()]

    if not finding_ids:
        return {"message": "All remediations already AI-customized or none pending", "regenerated": 0}

    stats = {"regenerated": 0, "errors": 0, "details": []}
    for fid in finding_ids:
        try:
            # Delete old template remediation
            await db.execute(
                FindingRemediation.__table__.delete().where(
                    FindingRemediation.finding_id == fid,
                    ~FindingRemediation.playbook_key.like("%_ai"),
                    FindingRemediation.status == "pending",
                )
            )
            # Generate new AI-customized one
            rem = await generate_action(fid, db)
            if rem and "_ai" in (rem.playbook_key or ""):
                stats["regenerated"] += 1
                stats["details"].append({"finding_id": fid, "title": rem.title[:60], "ai": True})
            elif rem:
                stats["details"].append({"finding_id": fid, "title": rem.title[:60], "ai": False, "note": "AI unavailable, template used"})
            else:
                stats["details"].append({"finding_id": fid, "error": "No remediation generated"})
        except Exception as e:
            stats["errors"] += 1
            stats["details"].append({"finding_id": fid, "error": str(e)[:80]})

    await db.commit()
    stats["details"] = stats["details"][:10]
    return stats


# ── AIQuery class ──
# ── AI Query ──
class AIQuery(BaseModel):
    question: Optional[str] = None
    query: Optional[str] = None
    provider: str = "auto"
    customer_id: Optional[int] = None  # Optional: scope to specific customer
    conversation_history: list = []  # Multi-turn conversation

    @property
    def text(self):
        return self.question or self.query or ""


# ── ai/query ──
@router.post("/api/ai/query", dependencies=[Depends(require_role("admin", "analyst"))])
async def ai_query(req: AIQuery, db: AsyncSession = Depends(get_db)):
    """AI query with FULL platform context - customer-specific when customer_id provided."""
    if not req.text:
        raise HTTPException(422, "Either 'question' or 'query' field required")
    
    # ── Build rich context ──
    stats = {}
    try:
        r = await db.execute(select(func.count(Detection.id)))
        stats["total_detections"] = r.scalar() or 0
        r = await db.execute(select(func.count(Detection.id)).where(Detection.severity == SeverityLevel.CRITICAL))
        stats["critical"] = r.scalar() or 0
        r = await db.execute(select(func.count(Customer.id)).where(Customer.active == True))
        stats["active_customers"] = r.scalar() or 0
    except Exception as e: pass

    # Always load customer summary for general questions
    customers_summary = ""
    try:
        cr = await db.execute(select(Customer.id, Customer.name, Customer.industry).where(Customer.active == True).limit(20))
        custs = cr.all()
        if custs:
            lines = []
            for c in custs:
                # Count findings per customer
                fr = await db.execute(select(func.count(Finding.id)).where(Finding.customer_id == c[0]))
                fc = fr.scalar() or 0
                lines.append(f" - {c[1]} (ID:{c[0]}, industry:{c[2]}, findings:{fc})")
            customers_summary = "CUSTOMERS:\n" + "\n".join(lines)
    except Exception as e: pass

    # Load top findings for context
    findings_summary = ""
    try:
        fr = await db.execute(
            select(Finding.ioc_value, Finding.ioc_type, Finding.severity, Finding.customer_id)
            .order_by(Finding.severity.desc(), Finding.created_at.desc()).limit(15)
        )
        top_f = fr.all()
        if top_f:
            findings_summary = "TOP FINDINGS:\n" + "\n".join(
                f" - [{f[2]}] {f[1]}: {str(f[0])[:60]} (customer_id:{f[3]})" for f in top_f
            )
    except Exception as e: pass

    # Load actors that have IOCs linked to customers
    actors_summary = ""
    try:
        from arguswatch.models import ThreatActor
        ar = await db.execute(
            select(ThreatActor.name, ThreatActor.origin_country, ThreatActor.target_sectors, ThreatActor.sophistication)
            .limit(20)
        )
        actors = ar.all()
        if actors:
            actors_summary = "THREAT ACTORS:\n" + "\n".join(
                f" - {a[0]} ({a[1] or '?'}, sophistication:{a[3] or '?'}, targets:{str(a[2])[:80]})" for a in actors
            )
    except Exception as e: pass

    # Customer-specific context
    customer_context = ""
    if req.customer_id:
        try:
            cr = await db.execute(select(Customer).where(Customer.id == req.customer_id))
            cust = cr.scalar_one_or_none()
            if cust:
                # Detection summary - full values + raw_text for AI analysis
                det_r = await db.execute(
                    select(Detection.ioc_type, Detection.severity, Detection.source,
                           Detection.ioc_value, Detection.raw_text, Detection.created_at)
                    .where(Detection.customer_id == req.customer_id)
                    .order_by(Detection.created_at.desc()).limit(20)
                )
                recent_dets = [{"type": r[0], "severity": r[1].value if hasattr(r[1], 'value') else str(r[1]),
                                "source": r[2], "value": r[3],
                                "raw_text": (r[4] or "")[:300],
                                "detected": r[5].isoformat() if r[5] else None} for r in det_r.all()]
                
                # Exposure score - use ExposureHistory (has overall_score + d1-d5)
                from arguswatch.models import ExposureHistory
                exp_r = await db.execute(
                    select(ExposureHistory).where(ExposureHistory.customer_id == req.customer_id)
                    .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
                )
                exp = exp_r.scalar_one_or_none()
                exp_data = {}
                if exp:
                    exp_data = {"score": exp.overall_score, "d1": exp.d1_score,
                                "d2": exp.d2_score, "d3": exp.d3_score,
                                "d4": exp.d4_score, "d5": exp.d5_score}
                
                # Asset count
                ar = await db.execute(
                    select(CustomerAsset.asset_type, func.count(CustomerAsset.id))
                    .where(CustomerAsset.customer_id == req.customer_id)
                    .group_by(CustomerAsset.asset_type)
                )
                asset_summary = dict(ar.all())
                
                customer_context = f"""
CUSTOMER CONTEXT for {cust.name}:
  Industry: {cust.industry or 'unknown'}
  Tier: {cust.tier}
  Onboarding state: {cust.onboarding_state}
  Assets registered: {dict(asset_summary)}
  Exposure score: {exp_data}
  Recent detections (last 20): {recent_dets}
"""
                # Load coverage gaps for recommendation capability
                try:
                    from arguswatch.models import CustomerAsset as CA2
                    ca_r = await db.execute(select(CA2.asset_type).where(CA2.customer_id == req.customer_id))
                    reg_types = {r[0] for r in ca_r.all()}
                    gaps = []
                    if "github_org" not in reg_types:
                        gaps.append("Register github_org to enable API key and code leak scanning (Cat 2, 7, 11)")
                    if "aws_account" not in reg_types:
                        gaps.append("Register aws_account to enable S3 bucket attribution (Cat 12)")
                    if "tech_stack" not in reg_types:
                        gaps.append("Register tech_stack to enable CVE matching (Cat 16)")
                    if "ip" not in reg_types:
                        gaps.append("Register IPs to enable network IOC matching (Cat 3)")
                    if "internal_domain" not in reg_types:
                        gaps.append("Register internal_domain to enable internal hostname matching (Cat 7)")
                    if gaps:
                        customer_context += f"  Coverage gaps (RECOMMEND these to the operator): {gaps}\n"
                except Exception as e:
                    logger.debug(f"Suppressed: {e}")
        except Exception as e:
            customer_context = f"\n(Customer context error: {e})\n"
    
    # Check for natural language onboarding commands
    q_lower = req.text.lower()
    if any(phrase in q_lower for phrase in ["add customer", "onboard", "start monitoring", "register customer"]):
        # Try to parse: "add customer Acme Corp domain acme.com industry financial"
        import re as _re
        # Extract domain (anything.tld pattern)
        domain_m = _re.search(r'(?:domain\s+)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,})', q_lower)
        # Extract industry
        ind_m = _re.search(r'industry\s+(\w+)', q_lower)
        # Extract name - text after "customer" or "onboard" keyword, before "domain"/"industry"
        name_m = _re.search(r'(?:add customer|onboard|register customer|start monitoring)\s+(.+?)(?:\s+(?:domain|industry|$))', q_lower)
        
        parsed_domain = domain_m.group(1) if domain_m else None
        parsed_industry = ind_m.group(1) if ind_m else None
        parsed_name = name_m.group(1).strip().title() if name_m else None
        
        if parsed_domain and parsed_name:
            # Actually onboard the customer
            try:
                existing = await db.execute(select(Customer).where(Customer.name == parsed_name))
                if existing.scalar_one_or_none():
                    return {"answer": f"Customer '{parsed_name}' already exists. Use the customer selector to view their profile.",
                            "model": "system", "provider": "builtin"}
                
                if not parsed_industry:
                    return {"answer": f"I can create '{parsed_name}' with domain {parsed_domain}, but I need an industry. "
                                      f"Try: 'add customer {parsed_name} domain {parsed_domain} industry financial' "
                                      f"(options: {', '.join(sorted(VALID_INDUSTRIES))})",
                            "model": "system", "provider": "builtin"}
                
                if parsed_industry not in VALID_INDUSTRIES:
                    return {"answer": f"Industry '{parsed_industry}' isn't recognized. Valid options: {', '.join(sorted(VALID_INDUSTRIES))}",
                            "model": "system", "provider": "builtin"}
                
                # Create customer + assets
                customer = Customer(name=parsed_name, industry=parsed_industry, tier="standard",
                                    onboarding_state="assets_added")
                db.add(customer)
                await db.flush()
                await db.refresh(customer)
                cid = customer.id
                
                for atype, aval in [("domain", parsed_domain), ("email_domain", parsed_domain),
                                     ("brand_name", parsed_name)]:
                    db.add(CustomerAsset(customer_id=cid, asset_type=atype, asset_value=aval,
                                         criticality="high", discovery_source="ai_onboarding"))
                
                brand_short = parsed_name.split()[0]
                if len(brand_short) >= 4 and brand_short.lower() != "the":
                    db.add(CustomerAsset(customer_id=cid, asset_type="keyword",
                                         asset_value=brand_short.lower(), criticality="high",
                                         discovery_source="ai_onboarding"))
                
                # Run matching + exposure
                match_info = ""
                try:
                    from arguswatch.engine.customer_intel_matcher import match_customer_intel
                    mr = await match_customer_intel(cid, db)
                    total = mr.get("total_matches", 0)
                    match_info = f" Found {total} threat intel matches." if total > 0 else " No matching threats found yet in current intel feeds."
                except Exception as e:
                    logger.debug(f"Suppressed: {e}")
                
                exp_info = ""
                try:
                    from arguswatch.services.exposure_scorer import calculate_customer_exposure
                    exp = await calculate_customer_exposure(cid, db)
                    score = exp.get("overall_score", exp.get("score", 0))
                    exp_info = f" Initial exposure score: {round(score)}/100."
                    # Seed exposure history for day-1 trend
                    from arguswatch.models import ExposureHistory
                    db.add(ExposureHistory(customer_id=cid, snapshot_date=datetime.utcnow(),
                                           overall_score=score,
                                           d1_score=exp.get("d1", 0), d2_score=exp.get("d2", 0),
                                           d3_score=exp.get("d3", 0), d4_score=exp.get("d4", 0),
                                           d5_score=exp.get("d5", 0)))
                except Exception as e:
                    logger.debug(f"Suppressed: {e}")
                
                customer.onboarding_state = "monitoring"
                customer.onboarding_updated_at = datetime.utcnow()
                await db.commit()
                
                return {
                    "answer": f"✅ Customer '{parsed_name}' created and onboarded!\n\n"
                              f"• Domain: {parsed_domain}\n"
                              f"• Industry: {parsed_industry}\n"
                              f"• Assets auto-registered: domain, email_domain, brand_name, keyword\n"
                              f"• State: monitoring\n"
                              f"{match_info}{exp_info}\n\n"
                              f"Next steps: Register github_org, IPs, and tech_stack to expand coverage. "
                              f"Select '{parsed_name}' from the customer dropdown to see the full dashboard.",
                    "model": "system", "provider": "builtin",
                    "customer_created": cid,
                }
            except Exception as e:
                return {"answer": f"Onboarding failed: {str(e)[:200]}. Use the '+ Add Customer' button instead.",
                        "model": "system", "provider": "builtin"}
        else:
            missing = []
            if not parsed_name: missing.append("customer name")
            if not parsed_domain: missing.append("domain")
            return {
                "answer": f"I need {' and '.join(missing)} to onboard. Try:\n\n"
                          f"'add customer Acme Corp domain acme.com industry financial'\n\n"
                          f"Or use the '+ Add Customer' button in the Customers tab.",
                "model": "system", "provider": "builtin",
            }

    context = f"""You are ArgusWatch AI, a cybersecurity threat intelligence analyst for an MSSP platform.
Platform stats: {stats}
{customers_summary}
{findings_summary}
{actors_summary}
{customer_context}
INSTRUCTIONS:
- Answer concisely using the data above. Reference specific customers, findings, and actors by name.
- If asked about actors targeting customers, match actor target_sectors to customer industries.
- If asked about a specific customer and no customer_id was provided, use the customer list above.
- Keep answers under 300 words. Use bullet points for lists."""

    prompt = req.text
    
    # Build conversation history for multi-turn
    conv_msgs = []
    for msg in (req.conversation_history or [])[-10:]:  # Last 10 turns
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role in ("user", "assistant") and content:
            conv_msgs.append({"role": role, "content": content[:500]})

    # Auto-detect provider: Ollama+Qwen is the DEFAULT (always-on, local)
    # Other providers (Claude, OpenAI, Gemini) are used ONLY when explicitly selected
    provider = req.provider
    if provider == "auto":
        provider = "ollama"  # Ollama+Qwen is always the default

    if provider == "ollama":
        try:
            import httpx
            history_text = "\n".join(f"{m['role'].title()}: {m['content']}" for m in conv_msgs)
            full_prompt = f"{context}\n\n{history_text}\nUser: {prompt}\nAssistant:" if history_text else f"{context}\n\nUser: {prompt}\nAssistant:"
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{settings.OLLAMA_URL}/api/generate",
                    json={"model": settings.OLLAMA_MODEL, "prompt": full_prompt, "stream": False})
                data = resp.json()
                if "error" in data:
                    return {"answer": f"Ollama error: {data['error']}", "model": "error", "provider": "ollama"}
                return {"answer": data.get("response", "No response"), "model": settings.OLLAMA_MODEL, "provider": "ollama"}
        except httpx.TimeoutException:
            return {"answer": "Ollama is processing your query (qwen3:8b can take 15-60s for complex questions). Please try again -  the model is warmed up now.", "model": "slow", "provider": "ollama"}
        except Exception as e:
            return {"answer": f"Ollama connection error: {str(e)[:150]}. Check: docker logs arguswatch-ollama", "model": "offline", "provider": "ollama"}

    elif provider == "anthropic" and settings.ANTHROPIC_API_KEY:
        try:
            import httpx
            messages = conv_msgs + [{"role": "user", "content": prompt}]
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 2048,
                          "system": context, "messages": messages})
                data = resp.json()
                if "error" in data:
                    return {"answer": f"Claude API error: {data['error'].get('message', data['error'])}", "model": "error", "provider": "anthropic"}
                if "content" in data and len(data["content"]) > 0:
                    text = data["content"][0].get("text", "")
                    return {"answer": text, "model": settings.ANTHROPIC_MODEL, "provider": "anthropic"}
                return {"answer": f"Claude returned empty response: {str(data)[:200]}", "model": "error", "provider": "anthropic"}
        except Exception as e:
            return {"answer": f"Claude API error: {e}", "model": "error"}

    elif provider == "openai" and settings.OPENAI_API_KEY:
        try:
            import httpx
            messages = [{"role": "system", "content": context}] + conv_msgs + [{"role": "user", "content": prompt}]
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post("https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={"model": settings.OPENAI_MODEL, "max_tokens": 1024, "messages": messages})
                data = resp.json()
                return {"answer": data["choices"][0]["message"]["content"], "model": settings.OPENAI_MODEL, "provider": "openai"}
        except Exception as e:
            return {"answer": f"OpenAI error: {e}", "model": "error"}

    elif provider == "google" and getattr(settings, "GOOGLE_AI_API_KEY", ""):
        try:
            import httpx
            model = getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro")
            # Gemini uses a different message format than OpenAI/Anthropic
            gemini_contents = []
            # System instruction goes in systemInstruction field
            for msg in conv_msgs:
                role = "user" if msg["role"] == "user" else "model"
                gemini_contents.append({"role": role, "parts": [{"text": msg["content"]}]})
            gemini_contents.append({"role": "user", "parts": [{"text": prompt}]})
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                    f"?key={settings.GOOGLE_AI_API_KEY}",
                    json={
                        "systemInstruction": {"parts": [{"text": context}]},
                        "contents": gemini_contents,
                        "generationConfig": {"maxOutputTokens": 1024},
                    })
                data = resp.json()
                candidates = data.get("candidates", [{}])
                parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
                text = " ".join(p.get("text", "") for p in parts)
                if not text:
                    error = data.get("error", {}).get("message", "Empty response")
                    return {"answer": f"Gemini returned no content: {error}", "model": model, "provider": "google"}
                return {"answer": text, "model": model, "provider": "google"}
        except Exception as e:
            return {"answer": f"Gemini API error: {e}", "model": "error"}

    return {"answer": f"No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_AI_API_KEY, or start Ollama locally.", "model": "none"}


# ══════════════════════════════════════════════════════════════════════════
# #2 AGENTIC CHAT AGENT (v16.4.7) -  Tool-using chat with 6 query tools
# AI autonomously decides which tools to call to answer the question
# ══════════════════════════════════════════════════════════════════════════


# ── ai/agent-query ──
@router.post("/api/ai/agent-query", dependencies=[Depends(require_role("admin", "analyst"))])
async def agentic_chat_query(req: AIQuery, db: AsyncSession = Depends(get_db)):
    """Tool-using agentic chat. AI picks from 6 tools to answer analyst questions.
    Returns answer + tools_used + iterations for full transparency.
    """
    if not req.text:
        raise HTTPException(422, "query required")

    from arguswatch.agent.chat_tools import CHAT_TOOLS, CHAT_TOOL_SCHEMAS, set_db
    from arguswatch.services.ai_pipeline_hooks import _provider, _pipeline_ai_available
    import json as _json

    if not _pipeline_ai_available():
        return {"answer": "No AI provider available.", "tools_used": [], "iterations": 0}

    set_db(db)
    prov = _provider()
    max_iter = 3 if prov == "ollama" else 6

    # Build system prompt
    system = """You are ArgusWatch AI, a cybersecurity threat intelligence analyst with access to the platform database.
You MUST use the available tools to look up real data before answering. DO NOT guess or make up data.

Available tools:
- search_customers: Find customers by name/industry, see finding counts
- search_findings: Find threat findings by customer/severity/IOC type
- check_exposure: Get D1-D5 exposure score breakdown for a customer
- search_actors: Find threat actors by name/sector/country
- search_darkweb: Search dark web mentions (ransomware, pastes, leaks)
- search_remediations: Search remediation tasks by status

ALWAYS call at least one tool before answering. Reference specific data from tool results.
Keep answers concise (under 250 words). Use the exact numbers and names from tool results."""

    messages = [{"role": "system", "content": system}, {"role": "user", "content": req.text}]
    tools_used = []
    tool_results_log = []

    # Import the right LLM caller
    if prov == "anthropic":
        from arguswatch.agent.agent_core import _call_anthropic as _call_llm_fn
    elif prov == "openai":
        from arguswatch.agent.agent_core import _call_openai as _call_llm_fn
    elif prov == "google":
        from arguswatch.agent.agent_core import _call_google as _call_llm_fn
    else:
        from arguswatch.agent.agent_core import _call_ollama as _call_llm_fn

    for iteration in range(max_iter):
        try:
            response = await _call_llm_fn(messages, CHAT_TOOL_SCHEMAS)
        except Exception as e:
            return {"answer": f"AI call failed: {str(e)[:150]}", "tools_used": tools_used, "iterations": iteration, "provider": prov}

        # If no tool calls, we have the final answer
        if not response.get("tool_calls"):
            return {
                "answer": response.get("text", "No response"),
                "tools_used": tools_used,
                "tool_results": tool_results_log,
                "iterations": iteration + 1,
                "provider": prov,
                "model": getattr(settings, "OLLAMA_MODEL", "") if prov == "ollama" else prov,
                "agentic": True,
            }

        # Process tool calls
        assistant_msg = {"role": "assistant", "content": response.get("text", "") or ""}
        if response["tool_calls"]:
            assistant_msg["tool_calls"] = [{
                "id": tc["id"], "type": "function",
                "function": {"name": tc["name"], "arguments": _json.dumps(tc["args"])}
            } for tc in response["tool_calls"]]
        messages.append(assistant_msg)

        for tc in response["tool_calls"]:
            tool_name = tc["name"]
            tool_args = tc["args"]
            tools_used.append(tool_name)

            if tool_name in CHAT_TOOLS:
                try:
                    result = await CHAT_TOOLS[tool_name](**tool_args)
                    result_str = _json.dumps(result, default=str)[:2000]
                except Exception as e:
                    result_str = _json.dumps({"error": str(e)[:100]})
            else:
                result_str = _json.dumps({"error": f"Unknown tool: {tool_name}"})

            tool_results_log.append({"tool": tool_name, "args": tool_args, "result_preview": result_str[:200]})

            if prov == "anthropic":
                messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": tc["id"], "content": result_str}]})
            else:
                messages.append({"role": "tool", "tool_call_id": tc["id"], "name": tool_name, "content": result_str})

    # Max iterations reached
    return {
        "answer": response.get("text", "Analysis incomplete -  reached iteration limit."),
        "tools_used": tools_used, "tool_results": tool_results_log,
        "iterations": max_iter, "provider": prov, "agentic": True,
    }


# ══════════════════════════════════════════════════════════════════════════
# RELIABLE CHAT AGENT (v16.4.7) -  Two-phase: classify -> query -> summarize
# Does NOT depend on Ollama tool-calling. Works with any LLM.
# ══════════════════════════════════════════════════════════════════════════

# ── ai/chat ──

@router.post("/api/ai/chat", dependencies=[Depends(require_role("admin", "analyst"))])
async def reliable_chat_endpoint(req: AIQuery, db: AsyncSession = Depends(get_db)):
    """Reliable AI chat -  two-phase architecture that works with any LLM.
    
    Unlike /api/ai/agent-query which depends on Ollama tool-calling (unreliable),
    this endpoint uses: LLM classifies intent -> Python queries DB -> LLM summarizes.
    Falls back gracefully at every phase. Always returns real data.
    
    Body: {"question": "How many critical findings does Uber have?"}
    """
    if not req.text:
        raise HTTPException(422, "question required")

    from arguswatch.agent.chat_agent_reliable import reliable_chat

    try:
        result = await reliable_chat(
            question=req.text,
            db=db,
            provider=req.provider,
        )
        return result
    except Exception as e:
        logger.error(f"[reliable_chat] Error: {e}")
        return {"answer": f"Chat error: {str(e)[:200]}", "method": "reliable_two_phase", "error": True}


# ── ai/investigate ──
@router.post("/api/ai/investigate", dependencies=[Depends(require_role("admin", "analyst"))])
async def investigate_endpoint(request: Request, db: AsyncSession = Depends(get_db)):
    """Agentic investigation: LLM reasons about compromise results and investigates further.

    Called by AI Bar AFTER compromise check returns. The LLM decides what follow-up
    queries to run (check findings, exposure, actors, related emails, darkweb).

    Body: {
        "query": "admin@starbucks.com",
        "query_type": "email",
        "compromise_results": { ... from /api/search/compromise/ ... },
        "provider": "ollama"
    }
    """
    body = await request.json()
    query = body.get("query", "")
    query_type = body.get("query_type", "unknown")
    compromise_results = body.get("compromise_results", {})
    provider = body.get("provider", "auto")

    if not query:
        raise HTTPException(422, "query required")

    from arguswatch.agent.investigate_agent import investigate_ioc

    try:
        result = await investigate_ioc(
            query=query,
            query_type=query_type,
            compromise_results=compromise_results,
            db=db,
            provider=provider,
        )
        return result
    except Exception as e:
        logger.error(f"[investigate] Error: {e}")
        return {"brief": f"Investigation error: {str(e)[:200]}", "agentic": False, "error": True}


# ── ai-match-confidence ──
@router.post("/api/ai-match-confidence", dependencies=[Depends(require_role("admin", "analyst"))])
async def ai_match_confidence_endpoint(limit: int = 5, db: AsyncSession = Depends(get_db)):
    """AI scores confidence on ambiguous matches (keyword, brand, tech_stack).
    Flags low-confidence matches as potential FPs. Skips exact_domain/subdomain (definitive).
    Default: 5 at a time.
    """
    from arguswatch.services.ai_pipeline_hooks import hook_ai_match_confidence, _pipeline_ai_available, _provider

    if not _pipeline_ai_available():
        return {"error": "No AI provider available."}

    # Find findings with ambiguous correlation types that haven't been confidence-scored yet
    AMBIGUOUS_TYPES = ["keyword_match", "brand_typosquat", "tech_stack_match", "pattern_match", "context_match"]
    r = await db.execute(
        select(Finding).where(
            Finding.correlation_type.in_(AMBIGUOUS_TYPES),
            Finding.ai_match_confidence == None,
        ).order_by(Finding.created_at.desc()).limit(min(limit, 20))
    )
    findings = r.scalars().all()

    if not findings:
        return {"message": "No ambiguous matches to score", "scored": 0, "provider": _provider()}

    stats = {"scored": 0, "low_confidence": 0, "high_confidence": 0, "errors": 0, "details": [], "provider": _provider()}

    for f in findings:
        try:
            # Get customer context
            cust_name = f.customer_name or ""
            cust_industry = ""
            if f.customer_id:
                cr = await db.execute(select(Customer).where(Customer.id == f.customer_id))
                cust = cr.scalar_one_or_none()
                if cust:
                    cust_name = cust.name
                    cust_industry = cust.industry or ""

            result = await hook_ai_match_confidence(
                ioc_type=f.ioc_type or "",
                ioc_value=(f.ioc_value or "")[:200],
                source=(f.all_sources or ["unknown"])[0] if isinstance(f.all_sources, list) else "unknown",
                correlation_type=f.correlation_type or "",
                matched_asset=f.matched_asset or "",
                customer_name=cust_name,
                customer_industry=cust_industry,
                match_proof=str(f.match_proof or "")[:300],
            )

            if result and "confidence" in result:
                f.ai_match_confidence = float(result["confidence"])
                f.ai_match_reasoning = result.get("reasoning", "")[:500]
                stats["scored"] += 1
                if result["confidence"] < 0.4:
                    stats["low_confidence"] += 1
                elif result["confidence"] > 0.7:
                    stats["high_confidence"] += 1
                stats["details"].append({
                    "finding_id": f.id, "ioc": (f.ioc_value or "")[:40],
                    "correlation": f.correlation_type, "confidence": round(result["confidence"], 2),
                    "reasoning": (result.get("reasoning", ""))[:80],
                })
        except Exception as e:
            stats["errors"] += 1
            stats["details"].append({"finding_id": f.id, "error": str(e)[:80]})

    await db.commit()
    stats["details"] = stats["details"][:10]
    return stats


