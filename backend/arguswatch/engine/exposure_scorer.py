"""
Exposure Scoring Engine v15 - 5-Dimension Orthogonal Risk Model
=================================================================
DESIGN: Risk = Likelihood × Impact (ISO 27005 / FAIR aligned)

Likelihood (0-100):
  1. Direct Exposure        (45%) - hard evidence: matched CVEs, IPs, credentials
  2. Active Exploitation    (20%) - is the vuln being weaponized RIGHT NOW?
  3. Threat Actor Intent    (15%) - are actors targeting this sector/tech/region?

Impact (0-100):
  4. Attack Surface Posture (10%) - internet-facing services, risky tech stack
  5. Asset Criticality      (10%) - business impact of affected systems

NO OVERLAP:
  - Direct Exposure = "do you have a confirmed vulnerability?"
  - Active Exploitation = "is someone actually using it?" (EPSS/KEV/exploit PoC)
  - Actor Intent = "are threat groups interested in your type?" (sector+geo+tech)
  - Attack Surface = "how exposed are your systems?" (ports, services, configs)
  - Asset Criticality = "how important is the affected asset?" (DC vs marketing site)

These 5 dimensions are orthogonal - measuring different, independent things.

SCORING: 0-100 scale
  80-100 = CRITICAL - immediate action required
  60-79  = HIGH - address within 24-48h
  40-59  = MEDIUM - address within 1 week
  <40    = LOW - monitor, schedule remediation
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, text

from arguswatch.models import (
    Detection, DarkWebMention, CustomerExposure,
    ThreatActor, Customer, CustomerAsset, SeverityLevel,
    CveProductMap, Finding, GlobalThreatActivity, ProbableExposure,
)

logger = logging.getLogger("arguswatch.engine.exposure_scorer")

# Option 4 formula weights are hardcoded in score_customer_actor():
#   Base = max((D1×0.50 + D2×0.30 + D3×0.20), D4×0.20)
#   Impact_modifier = 0.75 + D4×0.00125 + D5×0.00125
#   Risk = min(Base × Impact_modifier, 100)


def _label(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


# ═══════════════════════════════════════════════════════════════════
# DIMENSION 1: Direct Exposure (45%) - hard evidence
# "Do you have a confirmed, matched vulnerability?"
# ═══════════════════════════════════════════════════════════════════

async def _dim1_direct_exposure(cid: int, db: AsyncSession) -> tuple[float, dict]:
    score = 0.0
    factors = {}

    # Matched CVEs with CVSS
    cve_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.ioc_type == "cve_id",
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    cve_dets = cve_r.scalars().all()
    if cve_dets:
        max_cvss = 0.0
        for det in cve_dets:
            cpm_r = await db.execute(
                select(CveProductMap).where(CveProductMap.cve_id == det.ioc_value.upper()).limit(1)
            )
            cpm = cpm_r.scalar_one_or_none()
            cvss = (cpm.cvss_score if cpm and cpm.cvss_score else 0) or \
                   float((det.metadata_ or {}).get("cvss_score", 0) or 0)
            max_cvss = max(max_cvss, cvss)
        pts = min(35, (max_cvss / 10.0) * 35)
        score += pts
        factors["matched_cves"] = {
            "points": round(pts, 1),
            "detail": f"{len(cve_dets)} confirmed CVEs (max CVSS {max_cvss})",
            "count": len(cve_dets), "max_cvss": max_cvss,
        }

    # Leaked credentials
    cred_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_(["email_password_combo", "breachdirectory_combo",
                                     "username_password_combo", "email",
                                     "executive_email"]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    cred_dets = cred_r.scalars().all()
    if cred_dets:
        cred_count = len(cred_dets)
        # Stealer logs (HudsonRock/SpyCloud) are more dangerous than breach dumps
        # A stolen credential IS the exploit - no scanning, no exploit code needed
        stealer_count = sum(1 for d in cred_dets if d.source in ("hudsonrock", "spycloud", "flare"))
        breach_count = cred_count - stealer_count
        # FIX D: Executive email = CEO/CFO/CISO credential leak = MUCH higher impact
        # CEO credential → full org impersonation, board-level access
        exec_count = sum(1 for d in cred_dets if d.ioc_type == "executive_email")
        non_exec = cred_count - exec_count
        # Stealer logs: 10 pts each | Breach dumps: 4 pts each | Executive: 25 pts each
        cred_pts = min(50, stealer_count * 10 + (breach_count - exec_count) * 4 + exec_count * 25)
        score += cred_pts
        factors["credential_leaks"] = {
            "points": cred_pts,
            "detail": f"{cred_count} credentials exposed ({stealer_count} stealer logs, {breach_count} breach dumps"
                      + (f", {exec_count} EXECUTIVE)" if exec_count else ")"),
            "stealer_count": stealer_count, "breach_count": breach_count,
            "executive_count": exec_count,
        }

    # Customer IP in botnet/threat feed
    ip_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type == "ipv4",
            Detection.correlation_type.in_(["exact_ip", "ip_range"]),
        )
    )
    ip_hits = ip_r.scalar() or 0
    if ip_hits > 0:
        pts = min(20, ip_hits * 10)
        score += pts
        factors["ip_in_threat_feed"] = {"points": pts, "detail": f"{ip_hits} customer IPs in threat feeds"}

    # Ransomware leak mention
    ransom_r = await db.execute(
        select(func.count(DarkWebMention.id)).where(
            DarkWebMention.customer_id == cid,
            DarkWebMention.mention_type == "ransomware_leak",
        )
    )
    if (ransom_r.scalar() or 0) > 0:
        score += 40  # Ransomware leak is the strongest direct exposure signal
        factors["ransomware_leak"] = {"points": 40, "detail": "Customer in ransomware leak site"}

    # Phishing targeting customer domain
    phish_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_(["url", "domain"]),
            Detection.source.in_(["openphish", "urlscan", "phishtank", "urlhaus"]),
        )
    )
    phish = phish_r.scalar() or 0
    if phish > 0:
        pts = min(15, phish * 5)
        score += pts
        factors["phishing_targeting"] = {"points": pts, "detail": f"{phish} phishing URLs targeting customer"}

    # ── Cat 2 + Cat 11: API Keys & OAuth/SaaS Tokens ──
    # Leaked AWS key = full cloud compromise. Leaked OAuth token = full account takeover.
    token_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "aws_access_key", "aws_secret_key", "aws_root_key",
                "github_pat_classic", "github_oauth_token", "github_app_token", "github_fine_grained_pat",
                "gitlab_pat", "slack_bot_token", "slack_user_token",
                "stripe_live_key", "stripe_test_key", "openai_api_key", "anthropic_api_key",
                "sendgrid_api_key", "twilio_account_sid", "twilio_auth_token", "azure_sas_token",
                "private_key", "jwt_token", "jwt_token_alt",
                "google_api_key", "google_oauth_token", "google_oauth_bearer",
                "github_saas_token", "github_user_token", "azure_bearer", "bearer_token_header",
                "slack_bot_oauth", "slack_user_oauth",
                "exposed_secret",  # FIX C: fallback for grep.app/GitHub pre-classification
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    token_dets = token_r.scalars().all()
    if token_dets:
        # Privileged keys (AWS root, private keys) = 20 pts each
        # Standard API keys = 10 pts each
        priv_keys = sum(1 for d in token_dets if d.ioc_type in
                        ("aws_root_key", "aws_secret_key", "private_key"))
        standard_keys = len(token_dets) - priv_keys
        pts = min(50, priv_keys * 20 + standard_keys * 10)
        score += pts
        factors["api_key_leaks"] = {
            "points": pts,
            "detail": f"{len(token_dets)} API keys/tokens exposed ({priv_keys} privileged)",
            "privileged_count": priv_keys, "standard_count": standard_keys,
        }

    # ── Cat 7: Infrastructure & Code Leaks ──
    # Exposed .env file = ALL secrets at once. DB config = direct database access.
    # Also includes Cat 1 non-email credential types (remote_credential, db_connection_string)
    infra_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "config_file", "db_config", "backup_file",
                "internal_hostname", "db_connection_string",
                "remote_credential", "ldap_dn", "plaintext_password",
                "email_hash_combo", "crypto_seed_phrase",
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    infra_count = infra_r.scalar() or 0
    if infra_count > 0:
        pts = min(30, infra_count * 15)
        score += pts
        factors["infrastructure_leaks"] = {
            "points": pts,
            "detail": f"{infra_count} infrastructure/config files exposed",
        }

    # ── Cat 8: Financial & Identity Data - GLOBAL THREAT INDICATORS ──
    # Credit cards, SSNs, IBANs CANNOT be attributed to a specific customer
    # from external feeds. A Visa number doesn't identify the merchant.
    # 
    # BUT: Mass card dumps confirm active financial threat actors operating.
    # Route to D2/D3 as sector-level signals, not D1 customer-specific.
    #
    # HOW IT WORKS:
    #   1. These are stored with customer_id=NULL, correlation_type="global_financial_threat"
    #   2. D1 does NOT score them per-customer (removed below)
    #   3. D2 reads global financial_pii detection volume as exploitation signal
    #   4. D3 reads financial_pii as actor intent for Financial/Retail customers
    #
    # HONEST FRAMING FOR MSSP CUSTOMERS:
    #   "We detect mass financial PII dumps and route the sector-level risk
    #    to your exposure score. We cannot tell you YOUR cards were in this
    #    dump without a PCI forensics engagement - and anyone who claims
    #    otherwise is lying."
    
    # Count GLOBAL (customer_id=NULL) financial PII detections for sector amplifier
    fin_global_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id.is_(None),
            Detection.ioc_type.in_([
                "visa_card", "mastercard", "amex_card", "ssn", "iban", "swift_bic", "ach_routing",
            ]),
            Detection.created_at > func.now() - text("INTERVAL '7 days'"),
        )
    )
    fin_global_count = fin_global_r.scalar() or 0
    if fin_global_count > 0:
        # Only score for Financial/Retail/Banking sector customers
        customer_r = await db.execute(
            select(Customer).where(Customer.id == cid)
        )
        cust = customer_r.scalar_one_or_none()
        industry = (cust.industry or "").lower() if cust else ""
        financial_sectors = {"financial", "banking", "retail", "insurance", "fintech", "payment"}
        if any(s in industry for s in financial_sectors):
            # Sector-level signal: mass financial PII detected globally
            pts = min(15, (fin_global_count // 50) * 5)  # 5 pts per 50 PII items, cap 15
            if pts > 0:
                score += pts
                factors["financial_sector_threat"] = {
                    "points": pts,
                    "detail": f"{fin_global_count} financial PII records detected globally in last 7 days - sector-level threat signal",
                    "note": "Global indicator, not customer-attributed. PCI forensics required for specific attribution.",
                }

    # ── Cat 10: Session & Auth Tokens ──
    # Kerberos ccache, NTLM hashes, SAML assertions = immediate domain/service compromise
    session_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "session_cookie", "saml_assertion", "kerberos_ccache",
                "ntlm_hash", "ntlm_hash_format",
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    session_dets = session_r.scalars().all()
    if session_dets:
        # Kerberos/NTLM = domain compromise (25 pts each)
        # Session cookies = account takeover (15 pts each)
        krb_count = sum(1 for d in session_dets if d.ioc_type in
                        ("kerberos_ccache", "ntlm_hash", "ntlm_hash_format", "saml_assertion"))
        cookie_count = len(session_dets) - krb_count
        pts = min(50, krb_count * 25 + cookie_count * 15)
        score += pts
        factors["session_token_leaks"] = {
            "points": pts,
            "detail": f"{len(session_dets)} session/auth tokens ({krb_count} Kerberos/NTLM, {cookie_count} cookies)",
            "domain_compromise_risk": krb_count > 0,
        }

    # ── Cat 12: SaaS Misconfiguration ──
    # Public S3 buckets, exposed Elasticsearch = data breach waiting to happen
    misconfig_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "s3_bucket_ref", "s3_public_url", "azure_blob_public", "gcs_public_bucket",
                "open_analytics_service", "elasticsearch_exposed",
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    misconfig_count = misconfig_r.scalar() or 0
    if misconfig_count > 0:
        pts = min(30, misconfig_count * 15)
        score += pts
        factors["saas_misconfiguration"] = {
            "points": pts,
            "detail": f"{misconfig_count} public cloud resources / exposed services",
        }

    # ── Cat 13: Privileged Account Anomaly ──
    # Domain admin creds, AWS root keys, Golden Ticket indicators
    # These are FUNDAMENTALLY different from regular user credentials
    priv_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "privileged_credential", "aws_root_key", "breakglass_credential",
                "golden_ticket_indicator",
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    priv_count = priv_r.scalar() or 0
    if priv_count > 0:
        pts = min(50, priv_count * 25)
        score += pts
        factors["privileged_account_exposure"] = {
            "points": pts,
            "detail": f"{priv_count} privileged/admin credentials exposed",
        }

    # ── Cat 14: Shadow IT Discovery ──
    # ngrok tunnels, personal cloud shares, rogue dev endpoints
    shadow_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "personal_cloud_share", "dev_tunnel_exposed", "rogue_dev_endpoint",
                
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    shadow_count = shadow_r.scalar() or 0
    if shadow_count > 0:
        pts = min(15, shadow_count * 5)
        score += pts
        factors["shadow_it"] = {
            "points": pts,
            "detail": f"{shadow_count} shadow IT resources (unmonitored attack surface)",
        }

    # ── Cat 15: Data Exfiltration Anomaly ──
    # wget/curl to external, base64 exfil, file-sharing uploads = ACTIVE BREACH
    exfil_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "data_transfer_cmd", "archive_and_exfil",
                "base64_exfil", "file_share_exfil", "sql_outfile_exfil",
                
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    exfil_count = exfil_r.scalar() or 0
    if exfil_count > 0:
        pts = min(50, exfil_count * 25)  # Exfil = breach in progress, very high score
        score += pts
        factors["data_exfiltration"] = {
            "points": pts,
            "detail": f"{exfil_count} data exfiltration indicators - POTENTIAL ACTIVE BREACH",
        }

    # ── Cat 17: Crypto Addresses ──
    # Relevant for ransomware payment tracking (informational, lower severity)
    crypto_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_(["bitcoin_address", "ethereum_address", "monero_address"]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    crypto_count = crypto_r.scalar() or 0
    if crypto_count > 0:
        pts = min(10, crypto_count * 5)
        score += pts
        factors["crypto_addresses"] = {
            "points": pts,
            "detail": f"{crypto_count} cryptocurrency addresses (ransomware payment tracking)",
        }

    return min(100.0, score), factors


# ═══════════════════════════════════════════════════════════════════
# DIMENSION 2: Active Exploitation (20%) - weaponization signals
# "Is someone actually exploiting this vulnerability right now?"
# ═══════════════════════════════════════════════════════════════════

async def _dim2_active_exploitation(cid: int, db: AsyncSession) -> tuple[float, dict]:
    score = 0.0
    factors = {}

    # CISA KEV - actively exploited in the wild
    cve_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.ioc_type == "cve_id",
        )
    )
    cve_dets = cve_r.scalars().all()
    kev_count = 0
    max_epss = 0.0

    for det in cve_dets:
        cpm_r = await db.execute(
            select(CveProductMap).where(CveProductMap.cve_id == det.ioc_value.upper()).limit(1)
        )
        cpm = cpm_r.scalar_one_or_none()
        if cpm and cpm.actively_exploited:
            kev_count += 1
        # EPSS score
        meta = det.metadata_ or {}
        epss = float(meta.get("epss_score", 0) or 0)
        max_epss = max(max_epss, epss)

    if kev_count > 0:
        pts = min(50, kev_count * 25)
        score += pts
        factors["cisa_kev"] = {
            "points": pts,
            "detail": f"{kev_count} CVEs in CISA KEV (confirmed exploited in wild)",
        }

    if max_epss > 0.1:
        # EPSS: scale 0-1 to 0-30 points
        pts = min(30, max_epss * 30)
        score += pts
        factors["epss_probability"] = {
            "points": round(pts, 1),
            "detail": f"EPSS {max_epss:.1%} probability of exploitation within 30 days",
            "max_epss": max_epss,
        }

    # Multi-source confirmation (same IOC from 3+ feeds = likely active)
    multi_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.source_count >= 3,
        )
    )
    multi = multi_r.scalar() or 0
    if multi > 0:
        score += 20
        factors["multi_source"] = {"points": 20, "detail": f"{multi} IOCs confirmed by 3+ sources"}

    # Active credential exploitation - stealer logs ARE active exploitation
    # SpyCloud active_session:true = attacker has live session cookies RIGHT NOW
    # HudsonRock stealer logs = credentials harvested from active malware
    stealer_r = await db.execute(
        select(Detection).where(
            Detection.customer_id == cid,
            Detection.source.in_(["spycloud", "hudsonrock", "flare"]),
            Detection.ioc_type.in_(["email_password_combo", "email", "username_password_combo"]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        ).limit(50)
    )
    stealer_dets = stealer_r.scalars().all()
    if stealer_dets:
        stealer_count = len(stealer_dets)
        # Check for active_session flag (SpyCloud)
        active_sessions = sum(1 for d in stealer_dets
                              if (d.metadata_ or {}).get("active_session") == True)
        if active_sessions > 0:
            # Active session = attacker has live cookies RIGHT NOW
            # This is MORE urgent than KEV - the breach is already happening
            pts = min(70, active_sessions * 35)
            score += pts
            factors["active_session_theft"] = {
                "points": pts,
                "detail": f"{active_sessions} ACTIVE session cookies stolen - attacker has live access",
            }
        elif stealer_count > 0:
            # Stealer logs without active_session = credentials harvested recently
            # Equivalent to "exploit available + being used in campaigns"
            pts = min(50, stealer_count * 10)
            score += pts
            factors["stealer_log_exploitation"] = {
                "points": pts,
                "detail": f"{stealer_count} credentials from active stealer malware (Raccoon/RedLine/Vidar)",
            }

    # ── Active exploitation: Privileged accounts & Golden Tickets ──
    # Golden Ticket / Kerberos ccache = domain IS compromised (not "might be")
    # Domain admin creds in stealer logs = imminent full-environment takeover
    priv_exploit_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "golden_ticket", "kerberos_ccache", "kerberos_ticket",
                "ntlm_hash", "domain_admin_cred", "aws_root_key",
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    priv_exploit = priv_exploit_r.scalar() or 0
    if priv_exploit > 0:
        pts = min(60, priv_exploit * 30)  # Near-KEV severity
        score += pts
        factors["privileged_exploitation"] = {
            "points": pts,
            "detail": f"{priv_exploit} privileged auth artifacts - domain/cloud compromise likely",
        }

    # ── Active exploitation: Data Exfiltration ──
    # Exfil commands = breach IS happening RIGHT NOW
    # This is the most urgent non-CVE signal possible
    exfil_exploit_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "data_transfer_cmd", "archive_and_exfil",
                "base64_exfil", "file_share_exfil", "sql_outfile_exfil",
                
            ]),
            Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
        )
    )
    exfil_exploit = exfil_exploit_r.scalar() or 0
    if exfil_exploit > 0:
        pts = min(70, exfil_exploit * 35)  # Maximum urgency
        score += pts
        factors["active_exfiltration"] = {
            "points": pts,
            "detail": f"{exfil_exploit} data exfiltration indicators - ACTIVE BREACH IN PROGRESS",
        }

    return min(100.0, score), factors


# ═══════════════════════════════════════════════════════════════════
# DIMENSION 3: Threat Actor Intent (15%) - targeting signals
# "Are threat groups interested in your type of organization?"
# ═══════════════════════════════════════════════════════════════════

async def _dim3_actor_intent(customer: Customer, actor: ThreatActor,
                              db: AsyncSession) -> tuple[float, dict]:
    score = 0.0
    factors = {}
    industry = (customer.industry or "").lower()

    # Sector targeting from actor profile
    if industry:
        actor_sectors = [s.lower() for s in (actor.target_sectors or [])]
        if any(industry in s or s in industry for s in actor_sectors):
            score += 40
            factors["sector_target"] = {
                "points": 40,
                "detail": f"{actor.name} actively targets {customer.industry}",
            }

    # Global threat pressure targeting this sector
    if industry:
        gta_r = await db.execute(
            select(GlobalThreatActivity).where(GlobalThreatActivity.activity_level > 2.0)
        )
        max_pressure = 0.0
        for gta in gta_r.scalars().all():
            gta_sectors = [s.lower() for s in (gta.targeted_sectors or [])]
            if any(industry in s or s in industry for s in gta_sectors):
                max_pressure = max(max_pressure, gta.activity_level)
        if max_pressure > 0:
            pts = min(30, max_pressure * 3)
            score += pts
            factors["sector_pressure"] = {
                "points": round(pts, 1),
                "detail": f"Threat pressure {max_pressure:.1f}/10 against {customer.industry}",
            }

    # Actor motivation alignment
    motivation = (actor.motivation or "").lower()
    MOTIVE_MAP = {
        "financial": ["financial", "banking", "retail", "insurance"],
        "espionage": ["government", "defense", "technology", "energy"],
        "destruction": ["energy", "healthcare", "critical infrastructure"],
        "hacktivism": ["government", "education"],
    }
    for motive, sectors in MOTIVE_MAP.items():
        if motive in motivation and industry and any(industry in s for s in sectors):
            score += 20
            factors["motive_alignment"] = {
                "points": 20,
                "detail": f"{actor.name} ({motivation}) aligns with {industry} targeting",
            }
            break

    # ── FIX 3: Hash→Campaign→Sector Chain ──
    # Hashes can't be attributed to a specific customer, but ThreatFox/MalwareBazaar
    # tag them with malware_family and campaign info. When:
    #   1. A hash is tagged with a malware family (e.g., "Emotet", "QakBot")
    #   2. That malware family targets the customer's sector
    #   3. The hash is recent (within decay window)
    # → Create a sector-level exposure signal in D3
    #
    # This makes Cat 6 (hashes) contribute to customer risk even without EDR.
    # NOT a direct detection - a "your sector is under active attack by this malware" signal.
    
    if industry:
        # Malware families → sectors they target (from threat intel knowledge)
        MALWARE_SECTOR_MAP = {
            "emotet":     ["financial", "banking", "healthcare", "government"],
            "qakbot":     ["financial", "banking", "manufacturing", "legal"],
            "trickbot":   ["financial", "banking", "healthcare"],
            "icedid":     ["financial", "banking", "retail"],
            "raccoon":    ["financial", "technology", "retail", "cryptocurrency"],
            "redline":    ["financial", "technology", "gaming", "cryptocurrency"],
            "vidar":      ["financial", "technology", "cryptocurrency"],
            "cobalt":     ["financial", "government", "defense", "energy", "technology"],
            "cobaltstrike": ["financial", "government", "defense", "energy", "technology"],
            "lockbit":    ["manufacturing", "healthcare", "technology", "financial", "construction"],
            "alphv":      ["healthcare", "technology", "financial", "legal"],
            "blackcat":   ["healthcare", "technology", "financial", "legal"],
            "clop":       ["financial", "retail", "technology", "healthcare"],
            "conti":      ["healthcare", "government", "manufacturing"],
            "revil":      ["technology", "financial", "legal", "manufacturing"],
            "akira":      ["education", "healthcare", "manufacturing", "technology"],
            "black basta": ["manufacturing", "technology", "financial", "construction"],
            "play":       ["technology", "manufacturing", "retail"],
            "lazarus":    ["financial", "cryptocurrency", "defense", "technology"],
            "apt28":      ["government", "defense", "military", "energy"],
            "apt29":      ["government", "defense", "technology", "think tank"],
            "sandworm":   ["energy", "government", "critical infrastructure"],
        }
        
        # Check global_threat_activity for active malware campaigns targeting customer's sector
        try:
            campaign_r = await db.execute(
                select(GlobalThreatActivity).where(
                    GlobalThreatActivity.activity_level > 3.0,  # Significant activity only
                )
            )
            sector_campaigns = 0
            campaign_details = []
            
            for gta in campaign_r.scalars().all():
                malware = (gta.malware_family or "").lower()
                
                # Check if this malware family targets customer's sector
                targeted_sectors = MALWARE_SECTOR_MAP.get(malware, [])
                if not targeted_sectors:
                    # Fallback: check gta.targeted_sectors
                    targeted_sectors = [s.lower() for s in (gta.targeted_sectors or [])]
                
                if any(industry in s or s in industry for s in targeted_sectors):
                    sector_campaigns += 1
                    campaign_details.append(f"{malware} ({gta.activity_level:.1f}/10)")
                    
                    # Also check: do we have RECENT hashes for this malware family
                    # that haven't been matched to any customer?
                    # This is the "your sector is under active attack" signal
                    hash_r = await db.execute(
                        select(func.count(Detection.id)).where(
                            Detection.customer_id.is_(None),
                            Detection.ioc_type.in_(["sha256", "md5", "sha1", "hash_sha256"]),
                            Detection.source.in_(["threatfox", "malwarebazaar"]),
                            Detection.raw_text.ilike(f"%{malware}%"),
                        )
                    )
                    hash_count = hash_r.scalar() or 0
                    if hash_count > 0:
                        # Create probable exposure for hash→campaign→sector chain
                        from arguswatch.models import ProbableExposure
                        existing_pe = await db.execute(
                            select(ProbableExposure).where(
                                ProbableExposure.customer_id == customer.id,
                                ProbableExposure.exposure_type == "malware_sector_campaign",
                                ProbableExposure.product_name == malware,
                            ).limit(1)
                        )
                        if not existing_pe.scalar_one_or_none():
                            db.add(ProbableExposure(
                                customer_id=customer.id,
                                exposure_type="malware_sector_campaign",
                                source_detail=(
                                    f"{malware} campaign active ({hash_count} IOCs, "
                                    f"activity {gta.activity_level:.1f}/10) - "
                                    f"targets {industry} sector"
                                ),
                                product_name=malware,
                                confidence=0.4,
                                risk_points=min(8.0, gta.activity_level * 0.8),
                            ))
            
            if sector_campaigns > 0:
                pts = min(25, sector_campaigns * 8)
                score += pts
                factors["malware_campaign_targeting"] = {
                    "points": pts,
                    "detail": f"{sector_campaigns} active malware campaigns target {industry}: {', '.join(campaign_details[:5])}",
                    "campaigns": campaign_details[:5],
                }
        except Exception as e:
            logger.debug(f"D3 hash→campaign→sector error: {e}")

    return min(100.0, score), factors


# ═══════════════════════════════════════════════════════════════════
# DIMENSION 4: Attack Surface Posture (10%) - structural exposure
# "How exposed are your systems, independent of threat intel?"
# ═══════════════════════════════════════════════════════════════════

async def _dim4_attack_surface(cid: int, db: AsyncSession) -> tuple[float, dict]:
    score = 0.0
    factors = {}

    # Count internet-facing services
    asset_r = await db.execute(
        select(CustomerAsset).where(CustomerAsset.customer_id == cid)
    )
    assets = asset_r.scalars().all()

    ip_count = sum(1 for a in assets if a.asset_type in ("ip",))
    subdomain_count = sum(1 for a in assets if a.asset_type in ("subdomain",))
    tech_count = sum(1 for a in assets if a.asset_type in ("tech_stack",))

    # Internet exposure scale
    if subdomain_count > 20:
        pts = 30
        factors["large_surface"] = {"points": 30, "detail": f"{subdomain_count} subdomains - large attack surface"}
    elif subdomain_count > 5:
        pts = 15
        factors["moderate_surface"] = {"points": 15, "detail": f"{subdomain_count} subdomains"}
    else:
        pts = 5
    score += pts

    # High-risk technology presence
    RISKY_TECH = {"exchange": 25, "fortios": 25, "fortigate": 25, "confluence": 20,
                  "ivanti": 25, "citrix": 20, "esxi": 20, "vmware": 18, "moveit": 25,
                  "sharepoint": 15, "rdp": 20, "ssh": 5, "wordpress": 10}
    max_tech_risk = 0
    risky_found = []
    for asset in assets:
        if asset.asset_type == "tech_stack":
            av = asset.asset_value.lower().split("/")[0].split(":")[0].strip()
            for tech, risk in RISKY_TECH.items():
                if tech in av:
                    max_tech_risk = max(max_tech_risk, risk)
                    risky_found.append(asset.asset_value)
                    break
    if max_tech_risk > 0:
        score += max_tech_risk
        factors["risky_tech"] = {
            "points": max_tech_risk,
            "detail": f"High-risk tech: {', '.join(risky_found[:3])}",
            "technologies": risky_found[:5],
        }

    # Probable exposures (unknown version, tech baseline)
    pe_r = await db.execute(
        select(func.count(ProbableExposure.id)).where(ProbableExposure.customer_id == cid)
    )
    probable = pe_r.scalar() or 0
    if probable > 0:
        pts = min(20, probable * 4)
        score += pts
        factors["probable_exposures"] = {"points": pts, "detail": f"{probable} probable exposures (unverified versions)"}

    # ── Cat 12: SaaS Misconfiguration (also scored in D1 for exposure, here for surface) ──
    misconfig_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "s3_bucket_ref", "s3_public_url", "azure_blob_public", "gcs_public_bucket",
                "open_analytics_service", "elasticsearch_exposed",
            ]),
        )
    )
    misconfig_surface = misconfig_r.scalar() or 0
    if misconfig_surface > 0:
        pts = min(20, misconfig_surface * 10)
        score += pts
        factors["misconfigured_services"] = {
            "points": pts,
            "detail": f"{misconfig_surface} publicly exposed cloud services (S3/ES/Grafana)",
        }

    # ── Cat 14: Shadow IT (also scored in D1, here for surface expansion) ──
    shadow_surface_r = await db.execute(
        select(func.count(Detection.id)).where(
            Detection.customer_id == cid,
            Detection.ioc_type.in_([
                "ngrok_tunnel", "serveo_tunnel", "rogue_endpoint",
            ]),
        )
    )
    shadow_surface = shadow_surface_r.scalar() or 0
    if shadow_surface > 0:
        pts = min(15, shadow_surface * 5)
        score += pts
        factors["shadow_it_surface"] = {
            "points": pts,
            "detail": f"{shadow_surface} shadow IT endpoints (unmonitored tunnels/services)",
        }

    return min(100.0, score), factors


# ═══════════════════════════════════════════════════════════════════
# DIMENSION 5: Asset Criticality (10%) - business impact
# "How important is the affected system to the business?"
# ═══════════════════════════════════════════════════════════════════

async def _dim5_asset_criticality(cid: int, db: AsyncSession) -> tuple[float, dict]:
    score = 0.0
    factors = {}

    # Check which assets have been hit by IOCs
    hit_r = await db.execute(
        select(CustomerAsset).where(
            CustomerAsset.customer_id == cid,
            CustomerAsset.ioc_hit_count > 0,
        )
    )
    hit_assets = hit_r.scalars().all()

    if not hit_assets:
        return 0.0, {}

    CRIT_SCORE = {"critical": 100, "high": 70, "medium": 40, "low": 20}
    max_crit = 0
    crit_asset_names = []

    for asset in hit_assets:
        crit = (asset.criticality or "medium").lower()
        crit_score = CRIT_SCORE.get(crit, 40)
        if crit_score > max_crit:
            max_crit = crit_score
            crit_asset_names = [asset.asset_value]
        elif crit_score == max_crit:
            crit_asset_names.append(asset.asset_value)

    score = max_crit
    factors["criticality"] = {
        "points": max_crit,
        "detail": f"{'CRITICAL' if max_crit >= 80 else 'HIGH' if max_crit >= 60 else 'MEDIUM'} business impact - {', '.join(crit_asset_names[:3])}",
        "max_criticality": max_crit,
        "affected_assets": crit_asset_names[:5],
    }

    return min(100.0, score), factors


# ═══════════════════════════════════════════════════════════════════
# COMBINED SCORER - Option 4 with guardrails
#
# FORMULA:
#   Base = max(
#     (D1 × 0.50) + (D2 × 0.30) + (D3 × 0.20),    ← exposure-driven
#     D4 × 0.20                                       ← baseline floor
#   )
#   Impact_modifier = 0.75 + (D4 × 0.00125) + (D5 × 0.00125)
#   Risk = min(Base × Impact_modifier, 100)
#
# WHY THIS WORKS:
#   - D1 dominates (50% of base) - correct, exposure is king
#   - D2 strongly amplifies (30%) - KEV/EPSS are weaponization signals
#   - D3 cannot dominate alone (20% cap) - intent without exposure = noise
#   - Impact_modifier range: 0.75 → 1.00 (never penalizes more than 25%)
#   - Day-1 customer with no assets still gets 75% of their real score
#   - Baseline floor: large attack surface alone produces low-but-nonzero risk
#     (handles misconfiguration, password spraying, phishing without CVEs)
#   - Clean cap at 100 - no wraparound, no overflow
#
# EDGE CASES HANDLED:
#   D1=0, D2=0, D3=0, D4=80, D5=60 → Base=max(0, 16)=16, Impact=0.925 → Risk=14.8 (LOW)
#   D1=90, D2=50, D3=0, D4=0, D5=0 → Base=60, Impact=0.75 → Risk=45 (MEDIUM)
#   D1=90, D2=80, D3=40, D4=50, D5=90 → Base=77, Impact=0.925 → Risk=71 (HIGH)
#   D1=100, D2=100, D3=100, D4=100, D5=100 → Base=100, Impact=1.0 → Risk=100 (CRITICAL)
# ═══════════════════════════════════════════════════════════════════

async def score_customer_actor(customer: Customer, actor: ThreatActor,
                                db: AsyncSession) -> dict:
    d1, f1 = await _dim1_direct_exposure(customer.id, db)
    d2, f2 = await _dim2_active_exploitation(customer.id, db)
    d3, f3 = await _dim3_actor_intent(customer, actor, db)
    d4, f4 = await _dim4_attack_surface(customer.id, db)
    d5, f5 = await _dim5_asset_criticality(customer.id, db)

    # ── Option 4 Formula ──
    # Base: exposure-driven with baseline floor from attack surface
    exposure_base = (d1 * 0.50) + (d2 * 0.30) + (d3 * 0.20)
    surface_floor = d4 * 0.20  # Guardrail 1: attack surface alone ≠ zero risk
    base = max(exposure_base, surface_floor)

    # Impact modifier: scales 0.75 → 1.00 based on surface + criticality
    # D4 and D5 are 0-100, so ×0.00125 maps them to 0-0.125 each
    impact_modifier = 0.75 + (d4 * 0.00125) + (d5 * 0.00125)

    # Final: Guardrail 2: clean cap, no overflow
    final = min(base * impact_modifier, 100.0)

    all_factors = {}
    for prefix, fdict in [("exposure", f1), ("exploitation", f2), ("intent", f3),
                           ("surface", f4), ("criticality", f5)]:
        for k, v in fdict.items():
            all_factors[f"{prefix}_{k}"] = v

    top_threat = ""
    if all_factors:
        top_key = max(all_factors, key=lambda k: all_factors[k].get("points", 0))
        top_threat = all_factors[top_key].get("detail", "")

    return {
        "customer_id": customer.id,
        "actor_id": actor.id,
        "actor_name": actor.name,
        "score": round(final, 1),
        "label": _label(final),
        "dimensions": {
            "direct_exposure": round(d1, 1),
            "active_exploitation": round(d2, 1),
            "actor_intent": round(d3, 1),
            "attack_surface": round(d4, 1),
            "asset_criticality": round(d5, 1),
        },
        "base": round(base, 1),
        "impact_modifier": round(impact_modifier, 3),
        "factors": all_factors,
        "top_threat": top_threat,
    }


async def recalculate_all_exposures(db: AsyncSession) -> dict:
    r1 = await db.execute(select(Customer).where(Customer.active == True))
    customers = r1.scalars().all()
    r2 = await db.execute(select(ThreatActor).limit(200))
    actors = r2.scalars().all()

    stats = {"customers": len(customers), "actors": len(actors),
             "pairs_scored": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    for customer in customers:
        for actor in actors:
            result = await score_customer_actor(customer, actor, db)
            if result["score"] < 3:
                continue
            r3 = await db.execute(
                select(CustomerExposure).where(
                    CustomerExposure.customer_id == customer.id,
                    CustomerExposure.actor_id == actor.id,
                )
            )
            exposure = r3.scalar_one_or_none()
            if not exposure:
                exposure = CustomerExposure(customer_id=customer.id, actor_id=actor.id)
                db.add(exposure)
            exposure.exposure_score = result["score"]
            exposure.sector_match = "intent_sector_target" in result["factors"]
            exposure.factor_breakdown = result["factors"]
            exposure.last_calculated = datetime.utcnow()
            det_r = await db.execute(
                select(func.count(Detection.id)).where(Detection.customer_id == customer.id)
            )
            exposure.detection_count = det_r.scalar() or 0
            dw_r = await db.execute(
                select(func.count(DarkWebMention.id)).where(DarkWebMention.customer_id == customer.id)
            )
            exposure.darkweb_mentions = dw_r.scalar() or 0
            stats[result["label"].lower()] = stats.get(result["label"].lower(), 0) + 1
            stats["pairs_scored"] += 1

    await db.flush()
    logger.info(f"Exposure recalc: {stats}")
    return stats


async def get_customer_risk_summary(customer_id: int, db: AsyncSession) -> dict:
    r = await db.execute(select(Customer).where(Customer.id == customer_id))
    customer = r.scalar_one_or_none()
    if not customer:
        return {}

    r2 = await db.execute(
        select(CustomerExposure, ThreatActor)
        .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
        .where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc()).limit(5)
    )
    top_exposures = r2.all()

    counts = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        r3 = await db.execute(
            select(func.count(Detection.id)).where(
                Detection.customer_id == customer_id,
                Detection.severity == sev,
                Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
            )
        )
        counts[sev] = r3.scalar() or 0

    # CVSS summary
    max_cvss, kev_count = 0.0, 0
    cve_r = await db.execute(
        select(Detection).where(Detection.customer_id == customer_id, Detection.ioc_type == "cve_id").limit(100)
    )
    for det in cve_r.scalars().all():
        cpm_r = await db.execute(select(CveProductMap).where(CveProductMap.cve_id == det.ioc_value.upper()).limit(1))
        cpm = cpm_r.scalar_one_or_none()
        if cpm:
            max_cvss = max(max_cvss, cpm.cvss_score or 0)
            if cpm.actively_exploited: kev_count += 1

    pe_r = await db.execute(select(func.count(ProbableExposure.id)).where(ProbableExposure.customer_id == customer_id))
    probable_count = pe_r.scalar() or 0

    overall = max((e.CustomerExposure.exposure_score for e in top_exposures), default=0.0)

    return {
        "customer_id": customer_id,
        "customer_name": customer.name,
        "industry": customer.industry,
        "overall_score": round(overall, 1),
        "risk_label": _label(overall),
        "severity_counts": counts,
        "cvss_summary": {"max_cvss": max_cvss, "kev_count": kev_count},
        "probable_exposures": probable_count,
        "total_open": sum(counts.values()),
        "top_actors": [{
            "actor": e.ThreatActor.name,
            "mitre_id": e.ThreatActor.mitre_id,
            "score": round(e.CustomerExposure.exposure_score, 1),
            "label": _label(e.CustomerExposure.exposure_score),
            "sector_match": e.CustomerExposure.sector_match,
            "factors": e.CustomerExposure.factor_breakdown or {},
        } for e in top_exposures],
    }


from arguswatch.celery_app import celery_app as _celery_app

@_celery_app.task(name="arguswatch.engine.exposure_scorer.run_exposure_task")
def run_exposure_task():
    import asyncio
    from arguswatch.database import async_session
    async def _run():
        async with async_session() as db:
            r = await recalculate_all_exposures(db)
            await db.commit()
            return r
    return asyncio.run(_run())
