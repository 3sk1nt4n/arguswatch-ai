"""
Customer-Targeted Intel Matcher v15 - 3-Class IOC Model
=========================================================
DESIGN PHILOSOPHY (from Testi's analysis):
  "Most IOCs never match customers. Stop treating all IOCs as equal."

3-CLASS IOC MODEL:
  Class 1 - Direct Exposure (matchable)
    CVEs, customer IPs in threat feeds, phishing targeting customer domain,
    leaked credentials with customer email domain.
    -> Assigns customer_id, creates findings, dispatches alerts.
    
  Class 2 - Environmental Risk (indirect)
    Banking trojan campaign active, Exchange zero-day in wild,
    ransomware targeting healthcare.
    -> Does NOT require asset match.
    -> Increases sector exposure score via threat_pressure engine.
    
  Class 3 - Global Threat Pressure Index
    50 Feodo C2 IPs -> banking malware activity HIGH.
    -> Unmatchable IOCs converted into sector-level risk signals.
    -> Handled by threat_pressure.py, NOT this file.

THIS FILE HANDLES CLASS 1 ONLY - direct matches with 5 strategies:
  1. Exact IP match
  2. CIDR range check (Python ipaddress)
  3. Domain boundary match (NOT substring! - fixes Problem C)
  4. CVE->CveProductMap->tech_stack WITH version checking (fixes Problem D)
  5. Brand/keyword in dark web + ransomware feeds

PROBLEM C FIX - Domain Matching:
  OLD (broken): ILIKE '%at.com%' -> matches "chat.com", "format.com"
  NEW (correct): Check domain boundaries:
   - Exact match: "hackthebox.com" == "hackthebox.com"
   - Subdomain: "*.hackthebox.com" (ends with .hackthebox.com)
   - In URL: "https://phishing-hackthebox.com/login" (domain appears at boundary)
    Never raw substring.

PROBLEM D FIX - Version Checking:
  OLD (broken): product name matches -> full match (creates false positive for patched systems)
  NEW (correct): 
   - If customer version known AND CVE version_range known -> check _version_in_range()
   - If version unknown -> create probable_exposure with lower confidence, NOT a full match
   - If version confirms vulnerable -> full match with high confidence
"""

import logging
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, text

from arguswatch.models import (
    Detection, CustomerAsset, Customer, ThreatActor,
    DarkWebMention, DetectionStatus, SeverityLevel,
    CveProductMap, Finding, ProbableExposure,
)

logger = logging.getLogger("arguswatch.customer_intel_matcher")


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _normalize_product(tech_value: str) -> str:
    """Extract product name: 'nginx/1.18.0' -> 'nginx', 'FortiOS 7.2' -> 'fortios'."""
    v = tech_value.lower().strip()
    v = re.split(r"[/:\s]+\d", v)[0].strip()
    return v.replace("-", "").replace("_", "").replace(" ", "")


def _extract_version(tech_value: str) -> str | None:
    """Extract version: 'nginx/1.18.0' -> '1.18.0', 'FortiOS 7.2' -> '7.2'."""
    m = re.search(r"(\d+(?:\.\d+)+)", tech_value)
    return m.group(1) if m else None


def _products_match(customer_product: str, cpe_product: str) -> bool:
    """Fuzzy product name matching. 'nginx' ↔ 'Nginx', 'openssh' ↔ 'Openssh'."""
    cp = _normalize_product(customer_product)
    pp = _normalize_product(cpe_product)
    if len(cp) < 3 or len(pp) < 3:
        return False
    return cp in pp or pp in cp


def _version_in_range(version_str: str, version_range: str) -> bool:
    """Check if version falls within CVE's affected range.
    Ported from correlation_engine._version_in_range().
    Returns True (vulnerable) if in range, False (patched) if not.
    Returns True when range can't be parsed (conservative).
    """
    if not version_range or not version_str:
        return True  # No range data - can't determine

    def _parse_ver(s):
        try:
            return tuple(int(x) for x in re.split(r"[.\-]", s.strip())[:4])
        except ValueError:
            return None

    try:
        asset_ver = _parse_ver(version_str)
        if not asset_ver:
            return True
        for condition in [c.strip() for c in version_range.split(",")]:
            if condition.startswith("<= "):
                bound = _parse_ver(condition[3:])
                if bound and asset_ver > bound:
                    return False
            elif condition.startswith("< "):
                bound = _parse_ver(condition[2:])
                if bound and asset_ver >= bound:
                    return False
            elif condition.startswith(">= "):
                bound = _parse_ver(condition[3:])
                if bound and asset_ver < bound:
                    return False
        return True
    except Exception:
        return True


def _ip_in_any_cidr(ip_str: str, cidrs: list):
    """Check if IP falls within any CIDR network. Returns match or None."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False) if isinstance(cidr, str) else cidr
            if ip in network:
                return str(cidr)
        except (ValueError, TypeError):
            continue
    return None


def _domain_matches_ioc(customer_domain: str, ioc_value: str) -> str | None:
    """PROBLEM C FIX: Domain boundary matching instead of raw substring.
    
    Returns correlation_type if match, None if no match.
    
    Rules:
   - Exact: "hackthebox.com" == "hackthebox.com" -> "exact_domain"
   - Subdomain: "api.hackthebox.com" ends with ".hackthebox.com" -> "subdomain"  
   - In URL path: "https://evil.com/hackthebox.com/phish" -> "keyword" (low confidence)
   - NEVER: "chat.com" matching "at.com" (substring without boundary)
    """
    if not ioc_value:
        return None
    
    ioc_lower = ioc_value.lower().strip()
    dom_lower = customer_domain.lower().strip()
    
    # Strip protocol/path to get just the hostname from URLs
    hostname = ioc_lower
    if "://" in hostname:
        hostname = hostname.split("://", 1)[1]
    if "/" in hostname:
        hostname = hostname.split("/", 1)[0]
    if ":" in hostname:
        hostname = hostname.split(":", 1)[0]
    
    # Exact match
    if hostname == dom_lower:
        return "exact_domain"
    
    # Subdomain: hostname ends with ".customer.com"
    if hostname.endswith("." + dom_lower):
        return "subdomain"
    
    # Domain appears as full word in URL path (with boundaries)
    # Check: character before domain is non-alphanumeric (., /, @, etc.)
    # AND character after is non-alphanumeric or end of string
    pattern = r'(?:^|[^a-zA-Z0-9])' + re.escape(dom_lower) + r'(?:$|[^a-zA-Z0-9])'
    if re.search(pattern, ioc_lower):
        return "keyword"
    
    return None


def _domain_in_text(customer_domain: str, raw_text: str) -> bool:
    """Check if domain appears in raw_text with word boundaries."""
    if not raw_text:
        return False
    pattern = r'(?:^|[^a-zA-Z0-9])' + re.escape(customer_domain.lower()) + r'(?:$|[^a-zA-Z0-9])'
    return bool(re.search(pattern, raw_text.lower()))


# ═══════════════════════════════════════════════════════════════════════
# MAIN MATCHER - CLASS 1: DIRECT EXPOSURE
# ═══════════════════════════════════════════════════════════════════════

async def match_customer_intel(customer_id: int, db: AsyncSession) -> dict:
    """Match global detections to one customer using 8 strategies.
    
    Only handles Class 1 (Direct Exposure) IOCs.
    Class 2/3 handled by threat_pressure.py.
    
    ONBOARDING ENFORCEMENT:
   - state='created' -> BLOCKED, must register assets first
   - no industry set -> WARNING, D3 scoring will be zero
    """
    customer = (await db.execute(
        select(Customer).where(Customer.id == customer_id)
    )).scalar_one_or_none()
    if not customer:
        return {"error": f"Customer {customer_id} not found"}

    # ── ONBOARDING GATE ──
    if customer.onboarding_state == "created":
        return {
            "customer": customer.name, "customer_id": customer_id,
            "total_matches": 0, "blocked": True,
            "reason": "Customer is in 'created' state - register assets via /api/customers/onboard or /api/customers/{id}/assets before matching can run",
        }

    assets = (await db.execute(
        select(CustomerAsset).where(CustomerAsset.customer_id == customer_id)
    )).scalars().all()
    if not assets:
        return {
            "customer": customer.name, "customer_id": customer_id,
            "total_matches": 0, "assets_checked": 0,
            "note": "No assets - run recon first",
        }

    # Warn if no industry (D3 scoring will be zero)
    industry_warning = None
    if not customer.industry:
        industry_warning = "No industry set - D3 actor intent scoring disabled. Set via PATCH /api/customers/{id}"

    # Organize assets by type
    domains = [a.asset_value.lower() for a in assets if a.asset_type in ("domain", "email_domain")]
    subdomains = [a.asset_value.lower() for a in assets if a.asset_type in ("subdomain",)]
    ips = [a.asset_value.strip() for a in assets if a.asset_type in ("ip",)]
    cidrs = []
    for a in assets:
        if a.asset_type in ("cidr",):
            try:
                cidrs.append(ipaddress.ip_network(a.asset_value.strip(), strict=False))
            except Exception:
                pass
    if not cidrs and len(ips) >= 3:
        subnets = {}
        for ip_str in ips:
            try:
                subnet = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                subnets.setdefault(str(subnet), []).append(ip_str)
            except Exception:
                pass
        for s_str, s_ips in subnets.items():
            if len(s_ips) >= 3:
                try:
                    cidrs.append(ipaddress.ip_network(s_str, strict=False))
                except Exception:
                    pass

    # V16.4.7: Skip unconfirmed industry defaults from tech_stack matching
    tech_stack = [(a.asset_value, a) for a in assets
                  if a.asset_type in ("tech_stack",)
                  and getattr(a, "discovery_source", None) != "industry_default"]
    keywords = [a.asset_value.lower() for a in assets
                if a.asset_type in ("keyword", "brand_name", "org_name")]
    email_domains = set()
    for a in assets:
        if a.asset_type in ("email",) and "@" in a.asset_value:
            email_domains.add(a.asset_value.split("@")[1].lower())

    stats = {
        "customer": customer.name, "customer_id": customer_id,
        "assets_checked": len(assets),
        "ip_matches": 0, "cidr_matches": 0, "domain_matches": 0,
        "tech_matches": 0, "brand_matches": 0, "darkweb_matches": 0,
        "probable_exposures": 0,
        "total_matches": 0, "matched_detection_ids": [],
    }

    # ═══ GLOBAL EXCLUSION: Financial PII - never attribute to specific customers ═══
    # Card numbers, SSNs, IBANs are real signals but cannot be attributed
    # to a specific MSSP customer from external feeds. They stay as
    # customer_id=NULL global threat indicators feeding D2/D3 for sector scoring.
    # S3/S5/S6 are prevented from accidentally matching these.
    GLOBAL_ONLY_IOC_TYPES = frozenset({
        "visa_card", "mastercard", "amex_card", "ssn",
        "iban", "swift_bic", "ach_routing",
    })

    # ═══ STRATEGY 1: Exact IP ═══
    # IPv6 gate: ipv6 detections only match if customer has explicitly registered
    # an ipv6 asset. Since S1 matches against registered customer IPs only,
    # and S2 filters on ioc_type=="ipv4", ipv6 is naturally gated.
    # No customer currently registers ipv6 -> ipv6 never fires -> zero noise.
    if ips:
        for ip in ips:
            r = await db.execute(
                select(Detection).where(
                    Detection.customer_id.is_(None),
                    Detection.ioc_value == ip,
                )
            )
            for det in r.scalars().all():
                det.customer_id = customer_id
                det.matched_asset = ip
                det.correlation_type = "exact_ip"
                stats["ip_matches"] += 1
                stats["matched_detection_ids"].append(det.id)

    # ═══ STRATEGY 2: CIDR range ═══
    if cidrs:
        r = await db.execute(
            select(Detection).where(
                Detection.customer_id.is_(None),
                Detection.ioc_type == "ipv4",
            ).limit(10000)
        )
        for det in r.scalars().all():
            matched_cidr = _ip_in_any_cidr(det.ioc_value, cidrs)
            if matched_cidr:
                det.customer_id = customer_id
                det.matched_asset = str(matched_cidr)
                det.correlation_type = "ip_range"
                stats["cidr_matches"] += 1
                stats["matched_detection_ids"].append(det.id)

    # ═══ STRATEGY 3: Domain boundary matching (PROBLEM C FIX) ═══
    all_domains = set(domains + subdomains)
    # Add email domains for credential leak matching
    all_domains.update(email_domains)
    
    # V16.4.5: IOC types that carry their own domain identity.
    # URL/domain/email IOCs must match on their OWN value, never raw_text context.
    DOMAIN_BEARING_IOC_TYPES = frozenset({
        "url", "uri", "domain", "fqdn", "hostname", "email",
        "subdomain", "malicious_url_path", "s3_public_url",
    })

    if all_domains:
        # Only match domains with 5+ characters to avoid false positives
        safe_domains = [d for d in all_domains if len(d) >= 5]
        
        for domain in safe_domains:
            # Load unmatched detections that MIGHT contain this domain
            # Use ILIKE for initial filter, then validate with boundary check
            r = await db.execute(
                select(Detection).where(
                    Detection.customer_id.is_(None),
                    or_(
                        Detection.ioc_value.ilike(f"%{domain}%"),
                        Detection.raw_text.ilike(f"%{domain}%"),
                    )
                ).limit(500)
            )
            for det in r.scalars().all():
                # GLOBAL EXCLUSION: financial PII never attributed to customers
                if det.ioc_type in GLOBAL_ONLY_IOC_TYPES:
                    continue
                # BOUNDARY CHECK - not raw substring
                corr_type = _domain_matches_ioc(domain, det.ioc_value)
                if not corr_type:
                    # V16.4.5: ONLY allow raw_text fallback for NON-domain-bearing IOCs.
                    # URL/domain/email IOCs must match on their OWN value.
                    # Before this fix, a gist mentioning "github.com" caused ALL IOCs
                    # from that gist (hostingmalaya.com, googleapis.com, etc.)
                    # to be attributed to GitHub. This was the #1 false positive source.
                    if det.ioc_type in DOMAIN_BEARING_IOC_TYPES:
                        continue  # URL/domain IOC must match on its own value
                    # For hashes/CVEs/advisories: check raw_text with boundary matching
                    if _domain_in_text(domain, det.raw_text):
                        corr_type = "keyword"
                    else:
                        continue  # False positive from ILIKE - skip
                
                det.customer_id = customer_id
                det.matched_asset = domain
                det.correlation_type = corr_type
                stats["domain_matches"] += 1
                stats["matched_detection_ids"].append(det.id)

    # ═══ STRATEGY 4: CVE->CveProductMap->tech_stack WITH VERSION CHECK (PROBLEM D FIX) ═══
    if tech_stack:
        r = await db.execute(
            select(Detection).where(
                Detection.customer_id.is_(None),
                Detection.ioc_type == "cve_id",
            ).limit(5000)
        )
        cve_detections = r.scalars().all()

        if cve_detections:
            cve_ids = list(set(d.ioc_value.upper() for d in cve_detections))
            cpm_r = await db.execute(
                select(CveProductMap).where(CveProductMap.cve_id.in_(cve_ids))
            )
            cve_to_products = {}
            for cpm in cpm_r.scalars().all():
                cve_to_products.setdefault(cpm.cve_id.upper(), []).append(cpm)

            for det in cve_detections:
                cve_upper = det.ioc_value.upper()
                products = cve_to_products.get(cve_upper, [])
                matched = False

                for cpm in products:
                    for tech_value, tech_asset in tech_stack:
                        if not _products_match(tech_value, cpm.product_name):
                            continue
                        
                        # PRODUCT MATCHED - now version check (PROBLEM D FIX)
                        customer_version = _extract_version(tech_value)
                        cve_range = cpm.version_range or ""
                        
                        if customer_version and cve_range:
                            # Both version and range known -> definitive check
                            if _version_in_range(customer_version, cve_range):
                                # VULNERABLE - full match
                                det.customer_id = customer_id
                                det.matched_asset = tech_value
                                det.correlation_type = "tech_stack"
                                det.confidence = 0.9
                                if cpm.actively_exploited:
                                    det.severity = SeverityLevel.CRITICAL
                                    det.sla_hours = 4
                                elif cpm.cvss_score and cpm.cvss_score >= 9.0:
                                    det.severity = SeverityLevel.CRITICAL
                                elif cpm.cvss_score and cpm.cvss_score >= 7.0:
                                    det.severity = SeverityLevel.HIGH
                                stats["tech_matches"] += 1
                                stats["matched_detection_ids"].append(det.id)
                                logger.info(
                                    f"CVE CONFIRMED: {cve_upper} -> {cpm.product_name} "
                                    f"v{customer_version} in range '{cve_range}' "
                                    f"-> {customer.name} VULNERABLE"
                                    f"{' [KEV]' if cpm.actively_exploited else ''}"
                                )
                                matched = True
                                break
                            else:
                                # PATCHED - customer version outside range
                                logger.debug(
                                    f"CVE PATCHED: {cve_upper} -> {cpm.product_name} "
                                    f"v{customer_version} NOT in range '{cve_range}' - skip"
                                )
                                continue
                        
                        elif customer_version and not cve_range:
                            # Version known but no range data -> probable exposure
                            db.add(ProbableExposure(
                                customer_id=customer_id,
                                exposure_type="probable_cve",
                                source_detail=(
                                    f"{cve_upper} affects {cpm.product_name}, "
                                    f"customer runs v{customer_version} but no version range data"
                                ),
                                product_name=cpm.product_name,
                                cve_id=cve_upper,
                                confidence=0.5,
                                risk_points=min(8.0, (cpm.cvss_score or 5.0) * 0.8),
                            ))
                            stats["probable_exposures"] += 1
                            matched = True  # Don't try other products
                            break
                        
                        else:
                            # No version on customer asset -> unknown_version exposure
                            db.add(ProbableExposure(
                                customer_id=customer_id,
                                exposure_type="unknown_version",
                                source_detail=(
                                    f"{cve_upper} affects {cpm.product_name}, "
                                    f"customer has '{tech_value}' but version unknown"
                                ),
                                product_name=cpm.product_name,
                                cve_id=cve_upper,
                                confidence=0.3,
                                risk_points=min(6.0, (cpm.cvss_score or 5.0) * 0.6),
                            ))
                            stats["probable_exposures"] += 1
                            matched = True
                            break
                    
                    if matched:
                        break

    # ═══ STRATEGY 5: Brand/keyword in dark web ═══
    brand_terms = set(keywords + [d.split(".")[0] for d in domains if "." in d and len(d.split(".")[0]) >= 4])
    if brand_terms:
        for term in brand_terms:
            if len(term) < 4:
                continue
            # Dark web mentions - with boundary check for short terms
            r = await db.execute(
                select(DarkWebMention).where(
                    DarkWebMention.customer_id.is_(None),
                    or_(
                        DarkWebMention.title.ilike(f"%{term}%"),
                        DarkWebMention.content_snippet.ilike(f"%{term}%"),
                    ),
                ).limit(200)
            )
            for mention in r.scalars().all():
                # Boundary check: short terms like "apple" must appear as whole word
                if len(term) < 8:
                    text_to_check = (mention.title or "") + " " + (mention.content_snippet or "")
                    if not _domain_in_text(term, text_to_check):
                        continue
                mention.customer_id = customer_id
                stats["darkweb_matches"] += 1

            # Ransomware/paste/RSS detections
            r = await db.execute(
                select(Detection).where(
                    Detection.customer_id.is_(None),
                    Detection.source.in_(["ransomfeed", "paste", "hudsonrock", "rss"]),
                    or_(
                        Detection.ioc_value.ilike(f"%{term}%"),
                        Detection.raw_text.ilike(f"%{term}%"),
                    ),
                ).limit(200)
            )
            for det in r.scalars().all():
                # GLOBAL EXCLUSION: financial PII never attributed to customers
                if det.ioc_type in GLOBAL_ONLY_IOC_TYPES:
                    continue
                # V16.4.5: URL/domain IOCs must contain the brand term in their value,
                # not just in surrounding raw_text context.
                if det.ioc_type in DOMAIN_BEARING_IOC_TYPES:
                    if not _domain_in_text(term, det.ioc_value):
                        continue  # Brand not in URL itself - skip
                # Boundary check: short brand terms must appear as whole word
                elif len(term) < 8:
                    if not _domain_in_text(term, det.raw_text or det.ioc_value):
                        continue
                det.customer_id = customer_id
                det.matched_asset = term
                det.correlation_type = "brand_name"
                stats["brand_matches"] += 1
                stats["matched_detection_ids"].append(det.id)

    # ═══ STRATEGY 6: Context Attribution - Raw Text Proximity Window ═══
    # FIXES: ~46 sub-types (API keys, session tokens, OAuth, privileged creds,
    # infra leaks) when they co-occur with identifiable IOCs.
    #
    # HOW IT WORKS:
    #   1. Load raw_text of each detection matched by S1-S5
    #   2. Run pattern_matcher.scan_text() on that raw_text
    #   3. For EVERY IOC found in the same text, look for unmatched detections
    #      with that same ioc_value
    #   4. Attribute them to this customer (same text context = same owner)
    #
    # WHY THIS WORKS:
    #   Stealer logs naturally bundle: email:password + session cookies + API keys
    #   Pastebin dumps naturally group: email:password + internal hostnames + DB configs
    #   GitHub leaks contain: .env files with API keys + db_connection_strings + domains
    #
    # ALSO: Metadata-key fallback for when raw_text is truncated
    #   Same paste_key / telegram_msg_id / source_url = same context

    stats["context_matches"] = 0

    # V16.4.5: Only cascade from HIGH-CONFIDENCE matches.
    # Before: any "keyword" match from raw_text triggered cascade that attributed
    # 50+ unrelated IOCs from the same text. This was the #1 false positive amplifier.
    # After: only cascade from exact_domain, exact_ip, subdomain, tech_stack, cidr matches.
    HIGH_CONFIDENCE_CORR_TYPES = frozenset({
        "exact_domain", "exact_ip", "exact_email", "subdomain",
        "ip_range", "tech_stack", "email_pattern",
    })
    high_conf_det_ids = []
    if stats["matched_detection_ids"]:
        # Filter to only high-confidence matches for cascading
        hc_r = await db.execute(
            select(Detection.id).where(
                Detection.id.in_(stats["matched_detection_ids"][:200]),
                Detection.correlation_type.in_(HIGH_CONFIDENCE_CORR_TYPES),
            )
        )
        high_conf_det_ids = [row[0] for row in hc_r.all()]

    if high_conf_det_ids:
        from arguswatch.engine.pattern_matcher import scan_text as pm_scan

        # PHASE A: Raw text proximity - scan matched detection's raw_text
        # for additional IOCs, then find unmatched detections with those values
        matched_r = await db.execute(
            select(Detection).where(
                Detection.id.in_(high_conf_det_ids[:100]),
            )
        )
        matched_dets = matched_r.scalars().all()
        
        # Collect context IOC values from matched detections' raw_text
        context_ioc_values = set()
        context_metadata_keys = set()
        
        for det in matched_dets:
            # Phase A: scan raw_text for sibling IOCs
            if det.raw_text and len(det.raw_text) > 10:
                # Scan the raw text for ALL IOC patterns
                sibling_matches = pm_scan(det.raw_text)
                for m in sibling_matches:
                    if m.value != det.ioc_value and len(m.value) >= 6:
                        context_ioc_values.add((m.ioc_type, m.value))
            
            # Phase B: collect metadata keys for fallback matching
            meta = det.metadata_ or {}
            source = det.source or ""
            for key_name in ("paste_key", "paste_url", "telegram_msg_id",
                             "message_id", "source_url"):
                if meta.get(key_name):
                    context_metadata_keys.add((source, key_name, str(meta[key_name])))

        # Phase A: attribute unmatched detections with same IOC values
        if context_ioc_values:
            # Batch query: find unmatched detections whose ioc_value matches
            # any value found in matched detection's raw_text
            context_values_list = [v for _, v in context_ioc_values]
            # Query in batches of 50 to avoid huge IN clauses
            for i in range(0, len(context_values_list), 50):
                batch = context_values_list[i:i+50]
                try:
                    sib_r = await db.execute(
                        select(Detection).where(
                            Detection.customer_id.is_(None),
                            Detection.ioc_value.in_(batch),
                        ).limit(100)
                    )
                    for sib_det in sib_r.scalars().all():
                        # GLOBAL EXCLUSION: financial PII stays as global threat indicator
                        if sib_det.ioc_type in GLOBAL_ONLY_IOC_TYPES:
                            continue
                        sib_det.customer_id = customer_id
                        sib_det.matched_asset = f"context_proximity"
                        sib_det.correlation_type = "context_proximity"
                        sib_det.confidence = 0.65
                        sib_det.match_proof = {
                            "method": "context_proximity",
                            "reason": "IOC value found in raw_text of customer-matched detection",
                        }
                        stats["context_matches"] += 1
                        stats["matched_detection_ids"].append(sib_det.id)
                        logger.info(
                            f"S6 PROXIMITY: {sib_det.ioc_type}:{sib_det.ioc_value[:30]} "
                            f"-> {customer.name} (found in matched detection's raw_text)"
                        )
                except Exception as e:
                    logger.debug(f"S6 proximity batch error: {e}")

        # Phase B: metadata-key fallback (same paste/message = same context)
        if context_metadata_keys:
            for src, key_name, identifier in context_metadata_keys:
                try:
                    sib_r = await db.execute(
                        select(Detection).where(
                            Detection.customer_id.is_(None),
                            Detection.source == src,
                            Detection.metadata_[key_name].as_string() == identifier,
                        ).limit(50)
                    )
                    for sib_det in sib_r.scalars().all():
                        if sib_det.id in stats["matched_detection_ids"]:
                            continue
                        sib_det.customer_id = customer_id
                        sib_det.matched_asset = f"context_meta:{key_name}"
                        sib_det.correlation_type = "context_metadata"
                        sib_det.confidence = 0.70
                        sib_det.match_proof = {
                            "method": "context_metadata",
                            "reason": f"Same {key_name} as customer-matched IOC",
                            "key": key_name, "value": identifier[:50],
                        }
                        stats["context_matches"] += 1
                        stats["matched_detection_ids"].append(sib_det.id)
                except Exception as e:
                    logger.debug(f"S6 metadata fallback error: {e}")
                    continue

    # ═══ STRATEGY 7: Cloud/Org Asset Match ═══
    # Match IOCs that contain customer's cloud identifiers:
    #  - AWS account ID in S3 bucket URL
    #  - GitHub org name in repo path
    #  - Azure tenant in blob URL
    #  - Customer internal domain (.corp/.internal) in hostname

    stats["cloud_matches"] = 0

    # Get customer's registered cloud/org assets
    cloud_identifiers = []
    for a in assets:
        if a.asset_type in ("github_org", "aws_account", "azure_tenant",
                            "gcp_project", "org_name", "internal_domain"):
            cloud_identifiers.append((a.asset_type, a.asset_value.lower()))

    if cloud_identifiers:
        for asset_type, identifier in cloud_identifiers:
            if len(identifier) < 4:
                continue
            r = await db.execute(
                select(Detection).where(
                    Detection.customer_id.is_(None),
                    or_(
                        Detection.ioc_value.ilike(f"%{identifier}%"),
                        Detection.raw_text.ilike(f"%{identifier}%"),
                    ),
                ).limit(200)
            )
            for det in r.scalars().all():
                # Verify with boundary check
                text_to_check = (det.raw_text or "") + " " + (det.ioc_value or "")
                if not _domain_in_text(identifier, text_to_check):
                    continue

                det.customer_id = customer_id
                det.matched_asset = f"{asset_type}:{identifier}"
                det.correlation_type = "cloud_org_match"
                det.match_proof = {
                    "method": "cloud_org_match",
                    "asset_type": asset_type,
                    "identifier": identifier,
                }
                stats["cloud_matches"] += 1
                stats["matched_detection_ids"].append(det.id)

    # ═══ STRATEGY 8: Token Body Decoding ═══
    # FIXES: jwt_token, jwt_token_alt, saml_assertion, azure_bearer,
    # azure_sas_token, kerberos_ccache (6 sub-types)
    #
    # HOW IT WORKS:
    #   JWT payload contains iss (issuer), sub (subject), tid (Azure tenant),
    #   upn (user email), email fields - all base64-encoded in the token.
    #   Current code matches the token SHAPE but throws away the BODY.
    #   This strategy decodes the body, extracts domains/emails/tenant IDs,
    #   then matches them against customer assets.
    #
    # EXAMPLE:
    #   eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29m...
    #   Payload: {"iss": "https://login.microsoftonline.com/TENANT_ID/v2.0",
    #             "upn": "admin@acme.com", "tid": "abc123-def456"}
    #   -> Extract domain "acme.com" from upn
    #   -> Match against customer asset "acme.com"
    #   -> Token attributed to customer Acme

    stats["token_decode_matches"] = 0

    # Only run if we have domains to match against
    if all_domains:
        from arguswatch.utils import extract_domains_from_token
        
        TOKEN_TYPES = ("jwt_token", "jwt_token_alt", "saml_assertion",
                       "azure_bearer", "azure_sas_token", "bearer_token_header",
                       "kerberos_ccache", "google_oauth_bearer", "google_oauth_token")
        
        token_r = await db.execute(
            select(Detection).where(
                Detection.customer_id.is_(None),
                Detection.ioc_type.in_(TOKEN_TYPES),
            ).limit(500)
        )
        for det in token_r.scalars().all():
            try:
                extracted_domains = extract_domains_from_token(det.ioc_type, det.ioc_value)
                for ext_domain in extracted_domains:
                    # Check if this domain matches any customer domain
                    for cust_domain in all_domains:
                        match_type = _domain_matches_ioc(cust_domain, ext_domain)
                        if match_type:
                            det.customer_id = customer_id
                            det.matched_asset = cust_domain
                            det.correlation_type = "token_decode"
                            det.confidence = 0.80
                            det.match_proof = {
                                "method": "token_body_decode",
                                "token_type": det.ioc_type,
                                "extracted_domain": ext_domain,
                                "matched_customer_domain": cust_domain,
                            }
                            stats["token_decode_matches"] += 1
                            stats["matched_detection_ids"].append(det.id)
                            logger.info(
                                f"S8 TOKEN DECODE: {det.ioc_type} -> domain '{ext_domain}' "
                                f"-> {customer.name} ({cust_domain})"
                            )
                            break
                    if det.customer_id:
                        break
            except Exception as e:
                logger.debug(f"S8 token decode error: {e}")
                continue

    stats["total_matches"] = (
        stats["ip_matches"] + stats["cidr_matches"] + stats["domain_matches"] +
        stats["tech_matches"] + stats["brand_matches"] + stats["darkweb_matches"] +
        stats["context_matches"] + stats["cloud_matches"] + stats["token_decode_matches"]
    )

    await db.flush()
    await db.commit()

    logger.info(
        f"Match [{customer.name}]: {stats['total_matches']} direct, "
        f"{stats['probable_exposures']} probable - "
        f"IP:{stats['ip_matches']} CIDR:{stats['cidr_matches']} "
        f"Domain:{stats['domain_matches']} Tech:{stats['tech_matches']} "
        f"Brand:{stats['brand_matches']} DarkWeb:{stats['darkweb_matches']}"
    )

    # POST-MATCH: create findings + alerts for CRITICAL/HIGH
    if stats["matched_detection_ids"]:
        await _promote_matched_to_findings(stats["matched_detection_ids"], customer_id, db)

    stats.pop("matched_detection_ids", None)
    if industry_warning:
        stats["industry_warning"] = industry_warning
    return stats


async def _promote_matched_to_findings(detection_ids: list, customer_id: int, db: AsyncSession):
    """Create Finding records for CRITICAL/HIGH matched detections and dispatch alerts."""
    from arguswatch.engine.alert_dispatcher import dispatch_finding_alert

    try:
        r = await db.execute(
            select(Detection).where(
                Detection.id.in_(detection_ids),
                Detection.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH]),
                Detection.finding_id.is_(None),
            )
        )
        detections = r.scalars().all()
        if not detections:
            return

        cr = await db.execute(select(Customer).where(Customer.id == customer_id))
        customer = cr.scalar_one_or_none()

        findings_created = 0
        alerts_sent = 0
        _new_finding_ids = []

        for det in detections:
            existing = await db.execute(
                select(Finding).where(
                    Finding.ioc_value == det.ioc_value,
                    Finding.customer_id == customer_id,
                ).limit(1)
            )
            if existing.scalar_one_or_none():
                continue

            sla_h = det.sla_hours or 72

            # Determine if this is confirmed exposure evidence
            _src = det.source or ""
            _iot = det.ioc_type or ""
            _is_exposure = False
            _exposure_type = None
            if _src in ("ransomwatch", "ransomfeed"):
                _is_exposure = True
                _exposure_type = "ransomware_leak"
            elif _src == "hudsonrock":
                _is_exposure = True
                _exposure_type = "stealer_log"
            elif _src == "paste" and _iot in ("email_password_combo", "csv_credential_dump"):
                _is_exposure = True
                _exposure_type = "credential_dump"
            elif _iot == "data_exfiltration_evidence":
                _is_exposure = True
                _exposure_type = "data_exfiltration"

            finding = Finding(
                customer_id=customer_id,
                ioc_type=det.ioc_type,
                ioc_value=det.ioc_value,
                severity=det.severity,
                status=DetectionStatus.NEW,
                confidence=det.confidence or 0.5,
                source_count=det.source_count or 1,
                matched_asset=det.matched_asset,
                correlation_type=det.correlation_type,
                sla_hours=sla_h,
                sla_deadline=datetime.utcnow() + timedelta(hours=sla_h),
                all_sources=[det.source] if det.source else [],
                first_seen=det.first_seen or datetime.utcnow(),
                last_seen=det.last_seen or datetime.utcnow(),
                confirmed_exposure=_is_exposure,
                exposure_type=_exposure_type,
            )
            db.add(finding)
            await db.flush()
            det.finding_id = finding.id
            findings_created += 1
            _new_finding_ids.append(finding.id)

            if customer:
                try:
                    result = await dispatch_finding_alert(finding, customer)
                    if result.get("slack") or result.get("email"):
                        alerts_sent += 1
                except Exception as e:
                    logger.warning(f"Alert dispatch failed: {e}")

        await db.commit()

        # ═══════════════════════════════════════════════════════════════
        # POST-MATCH PIPELINE: Run the full enrichment->score->triage->action
        # chain for every new finding. Without this, 108 severity entries,
        # 1059 lines of enrichment, 84 playbook mappings, and 88 kill chain
        # entries are DEAD CODE for matched findings.
        # ═══════════════════════════════════════════════════════════════
        for _fid in _new_finding_ids:
            try:
                await _post_match_pipeline(_fid, db)
            except Exception as _pme:
                logger.warning(f"Post-match pipeline error for finding {_fid}: {_pme}")

        if findings_created:
            logger.info(f"Post-match: {findings_created} findings, {alerts_sent} alerts for {customer.name if customer else customer_id}")
    except Exception as e:
        logger.error(f"Post-match error: {e}")
        try:
            await db.rollback()
        except Exception:
            pass


async def _post_match_pipeline(finding_id: int, db: AsyncSession):
    """Run the full pipeline for a newly created finding.

    This is THE critical wiring function. Without it:
     - 108 severity entries -> DEAD CODE
     - 1059-line enrichment pipeline -> NEVER CALLED
     - 84 playbook mappings -> NEVER CALLED
     - 88 kill chain entries -> NEVER CALLED
     - 99 MITRE ATT&CK mappings -> NEVER USED

    Pipeline: Score -> Enrich -> AI Triage -> Remediation -> Campaign -> MITRE tag
    Each stage is independent -  failure in one doesn't block the others.
    """
    from sqlalchemy import select as _sel

    r = await db.execute(_sel(Finding).where(Finding.id == finding_id))
    finding = r.scalar_one_or_none()
    if not finding:
        return

    # ── 1. SEVERITY SCORING (IOC_SLA_MAP: 108 types -> correct severity + SLA) ──
    try:
        from arguswatch.engine.severity_scorer import score as score_ioc, get_mitre_context
        scored = score_ioc(finding.ioc_type, finding.ioc_type, confidence=finding.confidence)
        if scored:
            # Only upgrade severity, never downgrade (collector may have specific intel)
            SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            old_rank = SEV_RANK.get(str(finding.severity.value if hasattr(finding.severity, 'value') else finding.severity).upper(), 2)
            new_rank = SEV_RANK.get(scored.severity, 2)
            if new_rank > old_rank:
                finding.severity = scored.severity
                finding.sla_hours = scored.sla_hours
                from datetime import datetime, timedelta, timezone
                finding.sla_deadline = datetime.utcnow() + timedelta(hours=scored.sla_hours)
                logger.debug(f"[post_match] Finding {finding_id}: severity upgraded to {scored.severity} (SLA {scored.sla_hours}h)")

        # Tag with MITRE ATT&CK
        mitre = get_mitre_context(finding.ioc_type)
        if mitre.get("technique") != "unknown":
            if hasattr(finding, 'metadata_') and isinstance(finding.metadata_, dict):
                finding.metadata_["mitre_technique"] = mitre["technique"]
                finding.metadata_["mitre_tactic"] = mitre["tactic"]
            elif hasattr(finding, 'metadata_'):
                finding.metadata_ = {"mitre_technique": mitre["technique"], "mitre_tactic": mitre["tactic"]}
    except Exception as e:
        logger.debug(f"[post_match] Severity/MITRE error for {finding_id}: {e}")

    # ── 2. ENRICHMENT (55 types across 16 sources) ──
    enrichment_data = {}
    try:
        # Find the source detection to enrich
        if finding.ioc_value:
            from arguswatch.models import Detection
            det_r = await db.execute(
                _sel(Detection).where(Detection.finding_id == finding_id).limit(1)
            )
            det = det_r.scalar_one_or_none()
            if det:
                from arguswatch.services.enrichment_pipeline import enrich_detection
                enrich_result = await enrich_detection(det.id)
                enrichment_data = enrich_result or {}
                logger.debug(f"[post_match] Enriched {finding_id}: {enrich_result.get('enrichments', [])}")

                # If enrichment changed detection severity, propagate to finding
                await db.refresh(det)
                if det.severity and det.confidence:
                    finding.confidence = max(finding.confidence or 0.5, det.confidence)
    except Exception as e:
        logger.debug(f"[post_match] Enrichment error for {finding_id}: {e}")

    # ── 2b. AUTO-CRITICALITY SCORING (8-factor weighted model) ──
    # Runs AFTER enrichment so it has VT scores, key liveness, breach dates.
    try:
        from arguswatch.engine.ioc_registry import get_registry, calculate_dynamic_severity
        registry = await get_registry(db)
        reg_entry = registry.get(finding.ioc_type, {})

        if reg_entry.get("auto_score_enabled", True):
            # Collect ACTUAL enrichment data from DB (not just source names)
            _enrich_flat = {}
            try:
                from arguswatch.models import Enrichment, Detection
                _det_r = await db.execute(
                    _sel(Detection).where(Detection.finding_id == finding_id).limit(1)
                )
                _det = _det_r.scalar_one_or_none()
                if _det:
                    _enr_r = await db.execute(
                        _sel(Enrichment).where(Enrichment.detection_id == _det.id)
                    )
                    for enr in _enr_r.scalars().all():
                        if isinstance(enr.data, dict):
                            _enrich_flat.update(enr.data)
            except Exception:
                pass

            # Get customer industry for context
            _industry = ""
            try:
                _cust_r = await db.execute(_sel(Customer).where(Customer.id == finding.customer_id))
                _cust = _cust_r.scalar_one_or_none()
                if _cust:
                    _industry = _cust.industry or ""
            except Exception:
                pass

            # Calculate detection age
            _age_days = 0
            if finding.first_seen:
                _age_days = (datetime.utcnow() - finding.first_seen).total_seconds() / 86400

            auto_result = calculate_dynamic_severity(
                ioc_type=finding.ioc_type,
                enrichment=_enrich_flat,
                source_status=reg_entry.get("status", "WORKING"),
                detection_age_days=_age_days,
                customer_industry=_industry,
                exposure_confirmed=finding.confirmed_exposure or False,
                registry_entry=reg_entry,
            )

            # Apply auto-scored severity (only upgrade, never downgrade)
            SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            current_rank = SEV_RANK.get(
                str(finding.severity.value if hasattr(finding.severity, 'value') else finding.severity).upper(), 2)
            auto_rank = SEV_RANK.get(auto_result["severity"], 2)

            if auto_rank > current_rank:
                finding.severity = auto_result["severity"]
                finding.sla_hours = auto_result["sla_hours"]
                finding.sla_deadline = datetime.utcnow() + timedelta(hours=auto_result["sla_hours"])
                logger.info(
                    f"[auto_score] Finding {finding_id}: {finding.ioc_type} -> "
                    f"{auto_result['severity']} (score={auto_result['score']:.2f}, "
                    f"{auto_result['override_reason']})"
                )

            # Store auto-score details in metadata
            if hasattr(finding, 'metadata_') and isinstance(finding.metadata_, dict):
                finding.metadata_["auto_score"] = auto_result["score"]
                finding.metadata_["auto_severity"] = auto_result["severity"]
                finding.metadata_["auto_reason"] = auto_result["override_reason"]
            elif hasattr(finding, 'metadata_'):
                finding.metadata_ = {
                    "auto_score": auto_result["score"],
                    "auto_severity": auto_result["severity"],
                    "auto_reason": auto_result["override_reason"],
                }
    except Exception as e:
        logger.debug(f"[post_match] Auto-scoring error for {finding_id}: {e}")

    # ── 3. AI TRIAGE (if LLM is available -  non-blocking) ──
    try:
        from arguswatch.services.ai_pipeline_hooks import hook_ai_triage
        customer_ctx = {"customer_id": finding.customer_id, "industry": "", "matched_asset": finding.matched_asset or ""}
        # Try to get customer industry
        try:
            cust_r = await db.execute(_sel(Customer).where(Customer.id == finding.customer_id))
            cust = cust_r.scalar_one_or_none()
            if cust:
                customer_ctx["industry"] = cust.industry or ""
        except Exception:
            pass

        ai_result = await hook_ai_triage(
            ioc_type=finding.ioc_type,
            ioc_value=finding.ioc_value,
            source=finding.all_sources[0] if finding.all_sources else "",
            enrichment_data=enrichment_data.get("enrichments", {}),
            customer_context=customer_ctx,
            raw_text="",
        )
        if ai_result and ai_result.get("severity"):
            finding.ai_severity = ai_result.get("severity")
            finding.ai_confidence = ai_result.get("confidence")
            if hasattr(finding, 'triage_narrative'):
                finding.triage_narrative = ai_result.get("reasoning", "")[:500]
    except Exception as e:
        logger.debug(f"[post_match] AI triage skipped for {finding_id}: {e}")

    # ── 4. REMEDIATION ACTION (84 playbook mappings) ──
    try:
        from arguswatch.engine.action_generator import generate_action
        action = await generate_action(finding_id, db)
        if action:
            logger.debug(f"[post_match] Remediation created for finding {finding_id}")
    except Exception as e:
        logger.debug(f"[post_match] Action generation error for {finding_id}: {e}")

    # ── 5. CAMPAIGN DETECTION (88 kill chain entries) ──
    try:
        from arguswatch.engine.campaign_detector import check_and_create_campaign
        # Refresh finding object -  pipeline stages above modified severity, metadata, etc.
        await db.refresh(finding)
        campaign = await check_and_create_campaign(finding, db)
        if campaign:
            logger.info(f"[post_match] Campaign detected from finding {finding_id}: {campaign}")
    except Exception as e:
        logger.debug(f"[post_match] Campaign detection error for {finding_id}: {e}")

    await db.commit()
    logger.debug(f"[post_match] Pipeline complete for finding {finding_id}")


async def match_all_customers(db: AsyncSession) -> dict:
    """Run matching + threat pressure for ALL active customers."""
    r = await db.execute(select(Customer).where(Customer.active == True))
    customers = r.scalars().all()

    total_stats = {"customers_processed": 0, "total_matches": 0, "total_probable": 0, "per_customer": {}}

    # Step 1: Calculate global threat pressure (Class 2/3 IOCs)
    try:
        from arguswatch.engine.threat_pressure import calculate_threat_pressure
        pressure_result = await calculate_threat_pressure(db, window_hours=48)
        total_stats["threat_pressure"] = pressure_result
    except Exception as e:
        logger.warning(f"Threat pressure calculation failed: {e}")

    # Step 2: Run direct matching for each customer (Class 1 IOCs)
    for customer in customers:
        try:
            result = await match_customer_intel(customer.id, db)
            total_stats["per_customer"][customer.name] = {
                "direct": result.get("total_matches", 0),
                "probable": result.get("probable_exposures", 0),
            }
            total_stats["total_matches"] += result.get("total_matches", 0)
            total_stats["total_probable"] += result.get("probable_exposures", 0)
            total_stats["customers_processed"] += 1
        except Exception as e:
            logger.error(f"Match failed for {customer.name}: {e}")
            try:
                await db.rollback()
            except Exception:
                pass

    # Step 3: Calculate probable exposures per customer
    for customer in customers:
        try:
            from arguswatch.engine.threat_pressure import calculate_probable_exposures
            await calculate_probable_exposures(customer.id, db)
        except Exception as e:
            logger.warning(f"Probable exposure calc failed for {customer.name}: {e}")

    # Step 4: Recalculate exposure scores with ALL data layers
    try:
        from arguswatch.engine.exposure_scorer import recalculate_all_exposures
        await recalculate_all_exposures(db)
    except Exception as e:
        logger.warning(f"Exposure recalc failed: {e}")

    logger.info(
        f"All-customer match: {total_stats['total_matches']} direct, "
        f"{total_stats['total_probable']} probable, "
        f"{total_stats['customers_processed']} customers"
    )
    return total_stats
