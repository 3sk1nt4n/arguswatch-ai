"""
Campaign Detector - identifies coordinated attacks from finding patterns.

A campaign is declared when:
 - Same customer_id + same actor_id
 - 3+ distinct findings within a 14-day window
 - At least 2 different ioc_types (not all the same)

Kill chain stage is determined by the mix of IOC types:
  RECON      - domain, certificate, whois activity
  DELIVERY   - phishing_url, phishing_email, malicious_doc
  EXPLOITATION- cve_id, exploit_kit_url
  C2         - ipv4, ipv6, domain (after exploitation)
  EXFILTRATION- credential_combo, leaked_api_key, data_leak (dark web)
  PERSISTENCE - ransomware mention on leak site

Called from the ingest pipeline after attribution.
"""
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from arguswatch.models import Finding, Campaign, SeverityLevel, DetectionStatus

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.engine.campaign_detector")

CAMPAIGN_WINDOW_DAYS = 14
CAMPAIGN_THRESHOLD = 3      # minimum distinct findings to declare a campaign

# IOC type -> kill chain stage mapping (v16.4.7: expanded from 20 to 80+ types)
IOC_KILL_CHAIN = {
    # ── Recon ──
    "domain":                "recon",
    "cidr_range":            "recon",
    "internal_hostname":     "recon",
    "onion_address":         "recon",
    "advisory":              "recon",

    # ── Delivery ──
    "url":                   "delivery",
    "malicious_url_path":    "delivery",
    "email":                 "delivery",
    "executive_email":       "delivery",

    # ── Exploitation ──
    "cve_id":                "exploitation",
    "sha256":                "exploitation",
    "sha512":                "exploitation",
    "md5":                   "exploitation",
    "sha1":                  "exploitation",
    "config_file":           "exploitation",
    "backup_file":           "exploitation",
    "db_config":             "exploitation",
    "elasticsearch_exposed": "exploitation",
    "s3_bucket_ref":         "exploitation",
    "s3_public_url":         "exploitation",
    "azure_blob_public":     "exploitation",
    "gcs_public_bucket":     "exploitation",
    "open_analytics_service":"exploitation",
    "dev_tunnel_exposed":    "exploitation",
    "rogue_dev_endpoint":    "exploitation",

    # ── C2 / Persistence ──
    "ipv4":                  "c2",
    "ipv6":                  "c2",
    "bitcoin_address":       "c2",
    "ethereum_address":      "c2",
    "monero_address":        "c2",
    "apt_group":             "c2",

    # ── Credential Theft ──
    "email_password_combo":  "exfiltration",
    "username_password_combo":"exfiltration",
    "email_hash_combo":      "exfiltration",
    "breachdirectory_combo": "exfiltration",
    "plaintext_password":    "exfiltration",
    "db_connection_string":  "exfiltration",
    "remote_credential":     "exfiltration",
    "ldap_dn":               "exfiltration",
    "ntlm_hash":             "exfiltration",
    "ntlm_hash_format":      "exfiltration",
    "golden_ticket_indicator":"exfiltration",
    "privileged_credential": "exfiltration",
    "breakglass_credential": "exfiltration",
    "session_cookie":        "exfiltration",
    "jwt_token":             "exfiltration",
    "saml_assertion":        "exfiltration",

    # ── API Key Theft ──
    "aws_access_key":        "exfiltration",
    "aws_secret_key":        "exfiltration",
    "aws_root_key":          "exfiltration",
    "github_pat_classic":    "exfiltration",
    "github_fine_grained_pat":"exfiltration",
    "github_oauth_token":    "exfiltration",
    "github_app_token":      "exfiltration",
    "gitlab_pat":            "exfiltration",
    "openai_api_key":        "exfiltration",
    "anthropic_api_key":     "exfiltration",
    "stripe_live_key":       "exfiltration",
    "sendgrid_api_key":      "exfiltration",
    "google_api_key":        "exfiltration",
    "slack_bot_token":       "exfiltration",
    "slack_user_token":      "exfiltration",
    "azure_sas_token":       "exfiltration",
    "azure_bearer":          "exfiltration",
    "private_key":           "exfiltration",
    "exposed_secret":        "exfiltration",
    "google_oauth_token":    "exfiltration",

    # ── Data Exfiltration ──
    "data_transfer_cmd":     "exfiltration",
    "base64_exfil":          "exfiltration",
    "sql_outfile_exfil":     "exfiltration",
    "archive_and_exfil":     "exfiltration",
    "csv_credential_dump":   "exfiltration",
    "csv_pii_dump":          "exfiltration",
    "csv_financial_dump":    "exfiltration",
    "sql_dump_header":       "exfiltration",
    "sql_dump_detected":     "exfiltration",
    "sql_schema_dump":       "exfiltration",
    "archive_sensitive_data":"exfiltration",
    "file_share_exfil":      "exfiltration",
    "personal_cloud_share":  "exfiltration",

    # ── Impact / Extortion ──
    "ransomware_group":      "persistence",
    "ransom_note":           "persistence",
    "data_auction":          "persistence",

    # ── Financial (exfiltration stage) ──
    "visa_card":             "exfiltration",
    "mastercard":            "exfiltration",
    "amex_card":             "exfiltration",
    "ssn":                   "exfiltration",
    "iban":                  "exfiltration",
    "swift_bic":             "exfiltration",

    # ── Aliases and additional types ──
    "hash_sha256":           "exploitation",
    "github_saas_token":     "exfiltration",
    "twilio_account_sid":    "exfiltration",
    "google_oauth_bearer":   "exfiltration",
    "github_user_token":     "exfiltration",
    "slack_user_oauth":      "exfiltration",
    "slack_bot_oauth":       "exfiltration",
}

STAGE_PRIORITY = {
    "recon": 1,
    "delivery": 2,
    "exploitation": 3,
    "c2": 4,
    "exfiltration": 5,
    "persistence": 6,
}


def _determine_kill_chain_stage(ioc_types: list[str]) -> str:
    """Return the highest (most advanced) kill chain stage seen."""
    stages = []
    for ioc_type in ioc_types:
        stage = IOC_KILL_CHAIN.get(ioc_type)
        if stage:
            stages.append(stage)
    if not stages:
        return "unknown"
    return max(stages, key=lambda s: STAGE_PRIORITY.get(s, 0))


def _campaign_name(actor_name: str, customer_id: int, seq: int) -> str:
    actor = actor_name or "Unknown Actor"
    return f"{actor} Campaign #{seq}"


async def check_and_create_campaign(
    finding: Finding,
    db: AsyncSession,
) -> Campaign | None:
    """Check if this finding, combined with recent findings for same customer+actor,
    should trigger or update a campaign.

    Returns the Campaign if created/updated, None otherwise.
    """
    if not finding.customer_id or not finding.actor_id:
        return None

    window_start = datetime.utcnow() - timedelta(days=CAMPAIGN_WINDOW_DAYS)

    # Count distinct findings for same customer+actor in window
    r = await db.execute(
        select(Finding).where(
            and_(
                Finding.customer_id == finding.customer_id,
                Finding.actor_id == finding.actor_id,
                Finding.created_at >= window_start,
                Finding.status != DetectionStatus.FALSE_POSITIVE,
            )
        )
    )
    related_findings = r.scalars().all()

    if len(related_findings) < CAMPAIGN_THRESHOLD:
        return None

    # Check we have at least 2 distinct IOC types
    ioc_types = list({f.ioc_type for f in related_findings})
    if len(ioc_types) < 2:
        return None

    kill_chain_stage = _determine_kill_chain_stage(ioc_types)

    # Determine campaign severity - max severity of constituent findings
    severities = [_sev(f.severity) or "MEDIUM" for f in related_findings]
    SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_sev_val = max(severities, key=lambda s: SEV_RANK.get(s, 0))
    max_sev = SeverityLevel(max_sev_val)

    # Check if an active campaign already exists for this customer+actor
    existing_r = await db.execute(
        select(Campaign).where(
            and_(
                Campaign.customer_id == finding.customer_id,
                Campaign.actor_id == finding.actor_id,
                Campaign.status == "active",
            )
        ).limit(1)
    )
    existing_campaign = existing_r.scalar_one_or_none()

    if existing_campaign:
        # Update existing campaign
        existing_campaign.finding_count = len(related_findings)
        existing_campaign.kill_chain_stage = kill_chain_stage
        existing_campaign.severity = max_sev
        existing_campaign.last_activity = datetime.utcnow()
        # Link this finding to it
        if not finding.campaign_id:
            finding.campaign_id = existing_campaign.id
        await db.flush()
        logger.info(
            f"Campaign {existing_campaign.id} updated: "
            f"{len(related_findings)} findings, stage={kill_chain_stage}"
        )
        return existing_campaign

    # Create new campaign
    seq_r = await db.execute(
        select(func.count(Campaign.id)).where(
            Campaign.customer_id == finding.customer_id
        )
    )
    seq = (seq_r.scalar() or 0) + 1

    campaign = Campaign(
        customer_id=finding.customer_id,
        actor_id=finding.actor_id,
        actor_name=finding.actor_name or "Unknown",
        name=_campaign_name(finding.actor_name or "", finding.customer_id, seq),
        kill_chain_stage=kill_chain_stage,
        finding_count=len(related_findings),
        severity=max_sev,
        status="active",
        first_seen=min(f.created_at or datetime.utcnow() for f in related_findings),
        last_activity=datetime.utcnow(),
    )
    db.add(campaign)
    await db.flush()

    # Link all related findings to this campaign
    for f in related_findings:
        if not f.campaign_id:
            f.campaign_id = campaign.id

    await db.flush()

    logger.warning(
        f"CAMPAIGN DECLARED: {campaign.name} | "
        f"customer={finding.customer_id} actor={finding.actor_name} | "
        f"{len(related_findings)} findings | stage={kill_chain_stage} | "
        f"severity={max_sev.value}"
    )

    # V16.4: AI Kill Chain Narrative - turns the finding timeline into a story
    try:
        from arguswatch.services.ai_pipeline_hooks import _llm_text, _pipeline_ai_available
        if _pipeline_ai_available():
            # Build finding timeline sorted by time
            timeline = sorted(related_findings, key=lambda f: f.created_at or datetime.utcnow())
            day_0 = timeline[0].created_at or datetime.utcnow()
            timeline_text = "\n".join([
                f"  Day {(f.created_at - day_0).days if f.created_at else 0}: "
                f"{f.ioc_type} | {f.ioc_value[:50]} | source: {(f.all_sources or ['?'])[0]} | {_sev(f.severity) if f.severity else '?'}"
                for f in timeline
            ])

            _narr_prompt = f"""You are a threat intelligence analyst examining a detected campaign.

Campaign: {campaign.name}
Actor: {finding.actor_name or "Unknown"}
Customer industry: {finding.customer.industry if finding.customer else "unknown"}
Finding count: {len(related_findings)}
Rule-based kill chain: {kill_chain_stage}
Max severity: {max_sev.value}

Finding timeline (sorted by time):
{timeline_text}

Answer these questions in a 3-paragraph narrative:
1. Is this a coherent attack sequence or coincidental detections? What kill chain stages are ACTUALLY present?
2. Based on the time progression, what is the most likely NEXT step the attacker will take?
3. How urgent is this? Hours, days, or weeks? What should the SOC do RIGHT NOW?

Be specific. Cite actual IOCs from the timeline. No hedging."""

            _narr = await _llm_text(
                "You are a threat intelligence analyst. Write campaign narratives from finding timelines.",
                _narr_prompt,
            )
            if _narr and len(_narr.strip()) > 50:
                campaign.ai_narrative = _narr.strip()
                await db.flush()
                logger.info(f"[campaign] AI narrative generated for campaign#{campaign.id}")
    except Exception as _ce:
        logger.debug(f"[campaign] AI narrative failed (non-fatal): {_ce}")

    return campaign
