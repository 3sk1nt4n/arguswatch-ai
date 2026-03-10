"""
Action Generator - instantiates playbooks with real values for a specific finding.

Instead of generic playbook text like:
  "Block the malicious IP in your firewall"

This produces:
  "Block IP 185.234.219.44 in firewall - attributed to Lazarus Group C2,
   first seen via ThreatFox 3 hours ago, confirmed by OTX (4 sources)"

The finding + customer context -> specific, actionable remediation steps.
Creates a FindingRemediation row with all steps, deadline, and assignment.
"""
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from arguswatch.models import (

    Finding, Customer, ThreatActor, Campaign,
    FindingRemediation, SeverityLevel
)

import re as _re

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)

def _strip_html(text: str) -> str:
    """Remove HTML tags and CSS from text. Safety net for DB fields."""
    if not isinstance(text, str):
        return str(text) if text else ""
    text = _re.sub(r'<style[^>]*>.*?</style>', '', text, flags=_re.DOTALL | _re.IGNORECASE)
    text = _re.sub(r'<[^>]+>', ' ', text)
    text = _re.sub(r'\{[^}]*\}', ' ', text)
    text = _re.sub(r'[\w\-]+\s*:\s*[\w\-\(\)\#\%\.\,\s]+;', ' ', text)
    text = _re.sub(r'\s+', ' ', text).strip()
    return text

def _safe_val(text, max_len: int = 200) -> str:
    """Strip HTML/CSS and truncate. Safety net for all interpolated values."""
    if text is None:
        return ""
    cleaned = _strip_html(str(text))
    return cleaned[:max_len] if len(cleaned) > max_len else cleaned


logger = logging.getLogger("arguswatch.engine.action_generator")

# IOC type -> playbook key mapping (base)
IOC_TO_PLAYBOOK = {
    "ipv4":              "malicious_ip",
    "ipv6":              "malicious_ip",
    "domain":            "malicious_domain",
    "fqdn":              "malicious_domain",
    "url":               "malicious_domain",
    "email":             "phishing",
    "phishing_email":    "phishing",
    "phishing_url":      "phishing",
    "sha256":            "malware_hash",
    "md5":               "malware_hash",
    "sha1":              "malware_hash",
    "cve_id":            "unpatched_cve",
    "credential_combo":  "credential_combo",
    "email_password_combo": "credential_combo",
    "leaked_api_key":    "leaked_api_key",
    "aws_access_key":    "leaked_api_key",
    "github_pat":        "leaked_api_key",
    "btc_address":       "ransomware",
    "data_leak":         "data_leak",
    "typosquat_domain":  "malicious_domain",
}

# correlation_type overrides IOC_TO_PLAYBOOK when present.
# The same IOC type needs different remediation steps depending on HOW it matched.
# e.g. domain matched via "typosquat" -> brand abuse response, not generic block.
CORRELATION_TO_PLAYBOOK = {
    "typosquat":    "typosquat",
    "tech_stack":   "unpatched_cve",    # CVE matched because customer owns the product
    "exec_name":    "exec_exposure",    # Executive name in credential dump
    "subdomain":    "malicious_domain", # Subdomain of customer domain - phishing risk
    "exact_domain": "malicious_domain",
    "brand_name":   "typosquat",        # Brand name impersonation = same as typosquat
    "cloud_asset":  "cloud_exposure",   # Cloud asset exposed
}

SLA_HOURS = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 24,
    SeverityLevel.MEDIUM: 72,
    SeverityLevel.LOW: 168,
    SeverityLevel.INFO: 720,
}


async def generate_action(finding_id: int, db: AsyncSession) -> FindingRemediation | None:
    """Generate an instantiated remediation for a finding.
    
    Looks up playbook for finding's IOC type, substitutes real values,
    creates FindingRemediation row. Returns None if playbook not found.
    """
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = r.scalar_one_or_none()
    if not finding:
        return None

    # Don't create duplicate actions
    existing_r = await db.execute(
        select(FindingRemediation).where(
            FindingRemediation.finding_id == finding_id,
            FindingRemediation.status.in_(["pending", "in_progress"]),
        ).limit(1)
    )
    if existing_r.scalar_one_or_none():
        return None

    # Correlation type overrides ioc_type for playbook selection when present
    # Primary: correlation-based routing (HOW it matched matters more than WHAT it is)
    # Secondary: centralized get_playbook() from playbooks.py (84 types mapped)
    # Tertiary: legacy IOC_TO_PLAYBOOK (kept for backward compat)
    # Final: "generic" fallback
    from arguswatch.engine.playbooks import get_playbook as _get_pb
    playbook_key = CORRELATION_TO_PLAYBOOK.get(finding.correlation_type or "")
    if not playbook_key:
        _pb = _get_pb(finding.ioc_type, finding.source or "")
        playbook_key = _pb.ioc_type if _pb else IOC_TO_PLAYBOOK.get(finding.ioc_type, "generic")

    # Get context for interpolation
    customer = None
    if finding.customer_id:
        cr = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
        customer = cr.scalar_one_or_none()

    actor = None
    if finding.actor_id:
        ar = await db.execute(select(ThreatActor).where(ThreatActor.id == finding.actor_id))
        actor = ar.scalar_one_or_none()

    campaign = None
    if finding.campaign_id:
        capr = await db.execute(select(Campaign).where(Campaign.id == finding.campaign_id))
        campaign = capr.scalar_one_or_none()

    ctx = _build_context(finding, customer, actor, campaign)
    steps_tech, steps_gov, evidence = _instantiate_playbook(playbook_key, ctx)

    # ═══ V16.4.7: Try AI-customized remediation first ═══
    ai_steps = None
    ai_title = None
    try:
        from arguswatch.services.ai_pipeline_hooks import hook_ai_remediation
        ai_result = await hook_ai_remediation(
            ioc_type=finding.ioc_type or "",
            ioc_value=_safe_val(finding.ioc_value, 200),
            source=", ".join(finding.all_sources or ["unknown"]),
            customer_name=customer.name if customer else f"Customer #{finding.customer_id}",
            customer_industry=customer.industry if customer else "unknown",
            matched_asset=_safe_val(finding.matched_asset, 100),
            severity=_sev(finding.severity) or "MEDIUM",
            playbook_key=playbook_key,
            template_steps=steps_tech[:4],  # Give AI the template as starting point
        )
        if ai_result.get("ai_generated") and ai_result.get("steps_technical"):
            ai_steps = ai_result["steps_technical"]
            if ai_result.get("steps_governance"):
                steps_gov = ai_result["steps_governance"]
            if ai_result.get("title"):
                ai_title = ai_result["title"][:490]
            logger.info(f"AI-customized remediation for finding {finding_id} ({ai_result.get('provider','?')})")
    except Exception as e:
        logger.debug(f"AI remediation skipped for finding {finding_id}: {e}")

    final_steps = ai_steps or steps_tech

    sev = finding.severity or SeverityLevel.MEDIUM
    sla_h = SLA_HOURS.get(sev, 72)
    # Campaign escalation - tighten SLA if part of active campaign
    if campaign and campaign.status == "active":
        sla_h = max(4, sla_h // 2)

    deadline = datetime.utcnow() + timedelta(hours=sla_h)
    assigned_role = _assign_role(playbook_key, sev)

    remediation = FindingRemediation(
        finding_id=finding_id,
        playbook_key=playbook_key + ("_ai" if ai_steps else ""),
        action_type=finding.ioc_type,
        title=ai_title or _title(playbook_key, ctx),
        steps_technical=final_steps,
        steps_governance=steps_gov,
        evidence_required=evidence,
        assigned_role=assigned_role,
        assigned_to=assigned_role,  # replaced by real analyst on assignment
        deadline=deadline,
        sla_hours=sla_h,
        status="pending",
    )
    db.add(remediation)
    await db.flush()
    logger.info(
        f"Action created for finding {finding_id}: {playbook_key} | "
        f"deadline={deadline.strftime('%Y-%m-%d %H:%M')} | role={assigned_role}"
    )
    return remediation


def _build_context(finding: Finding, customer, actor, campaign) -> dict:
    """Build substitution context from real finding data."""
    sources_str = ", ".join(finding.all_sources or [finding.ioc_type]) or "unknown"
    actor_str = actor.name if actor else (finding.actor_name or "unknown actor")
    customer_str = customer.name if customer else f"Customer #{finding.customer_id}"
    campaign_str = campaign.name if campaign else None

    # Ransomware countdown: look for due_date in finding metadata
    ransomware_countdown = None
    meta = getattr(finding, "metadata_", None) or {}
    due_date_str = meta.get("due_date") or meta.get("ransom_deadline")
    if due_date_str:
        try:
            from datetime import datetime, timezone as _dt

            due = _dt.fromisoformat(due_date_str.replace("Z", "+00:00"))
            now = _dt.utcnow().replace(tzinfo=due.tzinfo)
            delta = due - now
            if delta.total_seconds() > 0:
                days = delta.days
                hours = delta.seconds // 3600
                ransomware_countdown = f"{days} days {hours} hours"
            else:
                ransomware_countdown = "EXPIRED (deadline passed)"
        except Exception:
            ransomware_countdown = due_date_str

    return {
        "ioc_value": _safe_val(finding.ioc_value),
        "ioc_type": finding.ioc_type,
        "customer": customer_str,
        "actor": actor_str,
        "sources": _safe_val(sources_str, 300),
        "source_count": finding.source_count or 1,
        "confidence_pct": int((finding.confidence or 0.5) * 100),
        "correlation_type": finding.correlation_type or "matched",
        "matched_asset": _safe_val(finding.matched_asset or "customer asset"),
        "severity": _sev(finding.severity) or "MEDIUM",
        "campaign": campaign_str,
        "campaign_stage": campaign.kill_chain_stage if campaign else None,
        "sla_hours": SLA_HOURS.get(finding.severity, 72) if finding.severity else 72,
        "ransomware_countdown": ransomware_countdown,
    }


def _title(playbook_key: str, ctx: dict) -> str:
    titles = {
        "malicious_ip":    f"Block malicious IP {ctx['ioc_value']} - {ctx['actor']}",
        "malicious_domain": f"Quarantine domain {ctx['ioc_value']} - {ctx['actor']}",
        "phishing":        f"Phishing campaign targeting {ctx['customer']} - {ctx['actor']}",
        "malware_hash":    f"Malware {ctx['ioc_value'][:16]}… detected - {ctx['actor']}",
        "unpatched_cve":   f"Patch {ctx['ioc_value']} on {ctx['matched_asset']} immediately",
        "credential_combo": f"Credential exposure for {ctx['customer']} - reset required",
        "leaked_api_key":  f"Revoke leaked API key for {ctx['customer']}",
        "ransomware":      f"Ransomware: {ctx['actor']} targeting {ctx['customer']}" + (f" - COUNTDOWN: {ctx['ransomware_countdown']}" if ctx.get('ransomware_countdown') else ""),
        "data_leak":       f"Data leak detected for {ctx['customer']} - {ctx['actor']}",
        "typosquat":       f"Typosquat domain {ctx['ioc_value']} impersonating {ctx['matched_asset']}",
        "exec_exposure":   f"Executive credential exposure: {ctx['matched_asset']} - {ctx['actor']}",
        "cloud_exposure":  f"Cloud asset {ctx['ioc_value']} exposed - {ctx['customer']}",
    }
    base = titles.get(playbook_key, f"Remediate {ctx['ioc_type']} finding for {ctx['customer']}")
    if ctx.get("campaign"):
        base += f" [Campaign: {ctx['campaign']}]"
    return base[:490]  # VARCHAR(500) safety net


def _instantiate_playbook(playbook_key: str, ctx: dict) -> tuple[list, list, list]:
    """Return (technical_steps, governance_steps, evidence_required) with real values."""

    c = ctx  # shorthand

    playbooks = {

        "malicious_ip": (
            [
                f"Block {c['ioc_value']} in all perimeter firewalls and WAF immediately (SLA: {c['sla_hours']}h)",
                f"Search SIEM for any inbound/outbound connections to {c['ioc_value']} in last 90 days",
                f"If connections found: isolate affected hosts and initiate forensic review",
                f"Add {c['ioc_value']} to threat intel platform blocklist (TIP/EDR)",
                f"Check {c['matched_asset']} for any sessions or connections to {c['ioc_value']}",
                f"Source corroboration: {c['source_count']} sources ({c['sources']}) - confidence {c['confidence_pct']}%",
                f"Actor attribution: {c['actor']} - check their known TTPs for follow-on actions",
            ],
            [
                f"Document blocking action with timestamp for {c['customer']} security log",
                f"Notify {c['customer']} SOC team via secure channel - reference finding ID",
                f"If connections confirmed: initiate breach assessment per IR policy",
                "Retain SIEM logs for this IP for minimum 12 months",
            ],
            [
                f"Firewall rule export showing {c['ioc_value']} blocked",
                f"SIEM search results (screenshot + export) - connection history for {c['ioc_value']}",
                "EDR/TIP blocklist confirmation",
            ],
        ),

        "malicious_domain": (
            [
                f"Block {c['ioc_value']} in DNS resolver, proxy, and EDR immediately",
                f"Search web proxy/firewall logs for any access to {c['ioc_value']} in last 30 days",
                f"Check if {c['matched_asset']} ({c['correlation_type']}) has resolved or accessed {c['ioc_value']}",
                f"If accessed: check for malware download, credential harvest, or C2 callback patterns",
                f"Run passive DNS to identify related infrastructure (same registrar, IP range)",
                f"Attribution: {c['actor']} - {c['sources']} ({c['source_count']} sources)",
            ],
            [
                f"Report domain to registrar for abuse investigation",
                f"Document DNS block with timestamp for {c['customer']} change log",
                "If users accessed domain: notify affected users, mandate password reset",
            ],
            [
                f"DNS block confirmation (screenshot of resolver config)",
                f"Proxy access log export - search results for {c['ioc_value']}",
                "EDR telemetry - no active connections to domain",
            ],
        ),

        "unpatched_cve": (
            [
                f"Verify {c['matched_asset']} is running the affected version for {c['ioc_value']}",
                f"Check CISA KEV - if {c['ioc_value']} is listed: patch deadline is 14 days from CISA listing",
                f"Apply vendor patch for {c['ioc_value']} to {c['matched_asset']} immediately",
                f"If patch not available: implement compensating controls (WAF rule, network segmentation)",
                f"Verify patch applied: run authenticated scan against {c['matched_asset']}",
                f"Check {c['actor']} TTPs - this CVE is attributed to them; check for active exploitation indicators",
                f"Review logs on {c['matched_asset']} for exploitation attempts (dates around {c['ioc_value']} disclosure)",
            ],
            [
                f"Document {c['ioc_value']} patching status in vulnerability register for {c['customer']}",
                "If actively exploited (KEV): executive notification required",
                f"Confirm patch in next vulnerability scan report for {c['customer']}",
            ],
            [
                f"Vulnerability scan output showing {c['ioc_value']} remediated on {c['matched_asset']}",
                "Change ticket number with completion date",
                f"If compensating control: WAF rule export or network segmentation diagram",
            ],
        ),

        "credential_combo": (
            [
                f"Immediately force password reset for all accounts in the leaked combo ({c['matched_asset']})",
                f"Search IdP (Okta/Entra/AD) for logins from unknown IPs using these credentials in last 30 days",
                f"Invalidate ALL active sessions for affected accounts - password reset alone is insufficient",
                f"Enable MFA on affected accounts if not already active - mandatory, not optional",
                f"Check breach source: {c['sources']} - determine exposure window and credential age",
                f"Cross-reference leaked email against other customer systems for password reuse",
                f"Actor context: {c['actor']} - credential dumps from this actor often precede targeted phishing",
            ],
            [
                f"Notify affected employees at {c['customer']} with clear non-alarming guidance",
                "If executive credentials: immediate CISO notification, treat as targeted attack",
                "Document exposure window for potential breach notification assessment",
                "If > 50 accounts: may trigger breach notification obligations - escalate to legal",
            ],
            [
                "IdP admin panel screenshot showing password reset completed",
                "Session invalidation log export",
                "MFA enrollment confirmation for all affected accounts",
                "Login history audit - confirm no unauthorized access in exposure window",
            ],
        ),

        "leaked_api_key": (
            [
                f"Revoke {c['ioc_value'][:20]}… in provider console IMMEDIATELY - do not wait",
                f"Source: {c['sources']} - key was found in {'public paste/repo' if 'paste' in c['sources'] or 'github' in c['sources'] else 'dark web'}",
                f"Audit all API calls made with this key since its creation date",
                f"Treat the entire repository/codebase as compromised - rotate ALL secrets",
                "Run TruffleHog/GitLeaks on full commit history - assume more secrets are exposed",
                "Install pre-commit hooks (GitLeaks) to prevent recurrence",
                f"Actor context: {c['actor']} - if attributed, this may be targeted credential harvesting",
            ],
            [
                f"If {c['ioc_value'][:12]} is an AWS key: check for unauthorized IAM users, EC2 launches, S3 access",
                "Document revocation timestamp - establishes end of exposure window",
                "Review billing for unexpected charges - API key abuse often triggers cost spikes",
                "If PII-adjacent API: breach notification assessment required",
            ],
            [
                f"Screenshot of key revocation in provider console",
                "API call audit log export - show no unauthorized use",
                "TruffleHog scan output - clean repo confirmation",
                "Pre-commit hook installation proof",
            ],
        ),

        "phishing": (
            [
                f"Block sender domain/IP in email gateway: {c['ioc_value']}",
                f"Retract/quarantine any emails from {c['ioc_value']} delivered to {c['customer']} mailboxes",
                f"Search mail logs for all recipients who received emails from {c['ioc_value']}",
                "Contact all recipients: advise not to click links, not to enter credentials",
                f"Check if any user clicked links or submitted credentials - review proxy and IdP logs",
                f"Attribution: {c['actor']} - known phishing TTPs: check their lure themes against this email",
                f"Matched via {c['correlation_type']} against asset: {c['matched_asset']}",
            ],
            [
                f"Report phishing domain to registrar and hosting provider",
                "If credentials submitted: escalate to credential_combo playbook immediately",
                f"Document all affected users at {c['customer']} for incident report",
            ],
            [
                "Email gateway block rule confirmation",
                "Mail log export - list of all recipients",
                "Proxy log export - confirm no clicks to phishing URL",
                "IdP login history - confirm no credential compromise",
            ],
        ),

        "malware_hash": (
            [
                f"Quarantine any file/process matching hash {c['ioc_value']} across all endpoints",
                f"Search EDR telemetry for {c['ioc_value']} across {c['customer']} environment",
                f"If found: isolate affected host(s) from network immediately",
                f"Collect memory dump and disk image from any infected host before remediation",
                f"Attribution: {c['actor']} - {c['sources']} ({c['source_count']} sources, {c['confidence_pct']}% confidence)",
                "Check lateral movement indicators from any infected host (new connections, credential use)",
                "Rebuild affected systems from clean image after forensic collection",
            ],
            [
                "If host confirmed infected: initiate IR retainer engagement",
                "Document isolation action with timestamp",
                f"Notify {c['customer']} CISO - malware confirmed in environment",
            ],
            [
                f"EDR scan results showing {c['ioc_value']} found/not-found",
                "Host isolation confirmation",
                "Forensic image creation confirmation",
                "Clean rebuild completion sign-off",
            ],
        ),

        "typosquat": (
            [
                f"Document typosquat domain: {c['ioc_value']} - impersonating {c['matched_asset']} ({c['customer']})",
                f"Source: {c['sources']} ({c['source_count']} corroborating sources, {c['confidence_pct']}% confidence)",
                f"Submit UDRP complaint to registrar immediately - evidence window is time-sensitive",
                f"Block {c['ioc_value']} in DNS resolver, email gateway, and web proxy",
                f"Search all {c['customer']} mail logs for emails FROM or TO {c['ioc_value']} in last 30 days",
                f"Check if any {c['customer']} users clicked links or submitted data to {c['ioc_value']}",
                f"Alert {c['customer']} employees: phishing domain impersonating your brand is active",
                f"Monitor certificate transparency logs for additional {c['matched_asset']} variants",
                f"Actor context: {c['actor']} - typosquat campaigns often precede phishing or credential harvest",
            ],
            [
                f"Document registrar, registration date, and hosting provider for {c['ioc_value']}",
                f"File abuse report with registrar AND hosting provider",
                "Prepare legal takedown notice if UDRP not available",
                f"Notify {c['customer']} marketing/legal team - brand abuse has reputational and legal dimensions",
                "Draft customer advisory if any user data may have been submitted to the typosquat site",
            ],
            [
                f"Screenshot of {c['ioc_value']} website before takedown (evidence preservation)",
                "UDRP / abuse report submission confirmation",
                "DNS block confirmation across all DNS resolvers",
                "Mail log export showing no successful phishing from this domain",
                f"Employee notification confirmation (sent to all {c['customer']} users)",
            ],
        ),

        "exec_exposure": (
            [
                f"Executive/VIP credentials exposed: {c['ioc_value']} matched {c['matched_asset']} ({c['customer']})",
                f"Source: {c['sources']} - treat as targeted attack targeting {c['customer']} leadership",
                f"IMMEDIATELY notify {c['matched_asset']} and their EA - do not send via standard email (potentially compromised)",
                f"Force password reset via out-of-band channel (phone call to personal number, in-person)",
                f"Verify executive's accounts via IdP (Okta/Entra) - check for unauthorized login in last 30/60/90 days",
                f"Invalidate ALL active sessions for {c['matched_asset']} accounts across ALL services",
                f"Mandatory MFA reenrollment - existing MFA may be compromised if device was targeted",
                "Check executive's email for forwarding rules (common attacker persistence mechanism)",
                f"Actor context: {c['actor']} - executive credential targeting often precedes BEC (Business Email Compromise)",
                "Brief executive on social engineering / spear-phishing risk - they are now a known target",
            ],
            [
                f"CISO and board notification required - executive credential exposure is material risk",
                f"Legal hold on all {c['matched_asset']} email and calendar data - potential breach notification obligation",
                "Retain DFIR firm if any unauthorized access confirmed",
                "Executive security briefing: heightened alertness for personal phishing, SIM swap attacks",
            ],
            [
                "IdP login history showing no unauthorized access in exposure window",
                "Password reset + session invalidation confirmation for all affected accounts",
                "MFA reenrollment confirmation (new device, not existing potentially-compromised device)",
                "Email forwarding rule audit export",
                f"Written confirmation from {c['matched_asset']} that they have been briefed",
            ],
        ),

        "cloud_exposure": (
            [
                f"Cloud asset exposed: {c['ioc_value']} matched {c['matched_asset']} for {c['customer']}",
                f"Source: {c['sources']} - cloud exposure found via {c['correlation_type']} matching",
                f"Check {c['ioc_value']} for public exposure: verify bucket/blob ACLs, endpoint authentication",
                f"Search CloudTrail/Azure Monitor/GCP Audit for unauthorized access to {c['ioc_value']} in last 90 days",
                "If S3: run `aws s3api get-bucket-acl` and `get-bucket-policy` - confirm no public access",
                "If Azure blob: check container access level - ensure private, not blob or container",
                "Check for exposed credentials, PII, or sensitive files in the exposed asset",
                f"Enable access logging on {c['ioc_value']} if not already enabled",
                f"Actor context: {c['actor']} - cloud exposure is frequently targeted for data theft and cryptomining",
            ],
            [
                f"Document all data types potentially accessible via {c['ioc_value']}",
                "If PII accessible: breach notification assessment required",
                "Cloud security posture review - check for other misconfigured assets in same environment",
                f"Notify {c['customer']} cloud/infrastructure team for remediation",
            ],
            [
                "Cloud provider ACL/policy screenshot showing access restricted",
                "Access log export covering 90-day window prior to discovery",
                "Data classification of exposed content (what types of data were accessible)",
                "Cloud security scan showing no other public resources in environment",
            ],
        ),

        "ransomware": (
            [
                f"RANSOMWARE ALERT: {c['actor']} has listed {c['customer']} on their leak site" + (f" - COUNTDOWN: {c.get('ransomware_countdown','unknown')}" if c.get('ransomware_countdown') else ""),
                f"Source: {c['sources']} ({c['source_count']} corroborating sources)",
                "IMMEDIATE ACTION 1: Engage IR retainer NOW - do not wait for business hours",
                "IMMEDIATE ACTION 2: Isolate confirmed or suspected compromised systems from network",
                "IMMEDIATE ACTION 3: Verify backup integrity - check backups have not been encrypted or deleted",
                f"IMMEDIATE ACTION 4: Contact legal counsel - breach notification may be required for {c['customer']}",
                "IMMEDIATE ACTION 5: Do NOT pay ransom without counsel - payment may violate OFAC sanctions",
                "Preserve forensic evidence - do not power off systems (volatile memory contains artefacts)",
                "Block all known actor IOCs at perimeter immediately",
                f"Brief {c['customer']} CISO, CEO, and legal - this is a P0 incident",
                "Engage PR/communications team - prepare holding statement for media/customers",
                "Check if data has already been exfiltrated - search for staging/exfil artefacts",
            ],
            [
                "Activate formal incident response plan and assign incident commander",
                f"File cyber incident report with relevant authorities (FBI IC3, CISA, relevant regulators for {c['customer']})",
                "Begin ransomware negotiation assessment - engage specialist firm if needed",
                "Prepare breach notification letters (regulatory deadlines may apply: GDPR 72h, HIPAA 60d)",
                "Document everything: timeline, affected systems, data accessed, actions taken",
                "Post-incident: conduct full purple team exercise to find initial access vector",
            ],
            [
                "IR firm engagement confirmation and timeline",
                "Backup integrity verification report",
                "Legal counsel engagement confirmation",
                "Network isolation confirmation (affected systems)  ",
                "Regulatory notification submissions (if required)",
                "Full forensic timeline report",
            ],
        ),

        "generic": (
            [
                f"Investigate {c['ioc_type']} indicator: {c['ioc_value']}",
                f"Corroborated by {c['source_count']} sources: {c['sources']}",
                f"Matched to {c['customer']} via {c['correlation_type']}: {c['matched_asset']}",
                f"Attribution: {c['actor']}",
                "Apply appropriate block/containment based on IOC type",
                "Monitor for recurrence",
            ],
            [
                "Document investigation steps and outcome",
                f"Notify {c['customer']} security contact",
            ],
            [
                "Investigation log with findings",
                "Containment action confirmation",
            ],
        ),
    }

    return playbooks.get(playbook_key, playbooks["generic"])


def _assign_role(playbook_key: str, severity: SeverityLevel) -> str:
    roles = {
        "malicious_ip":    "Network Security Engineer",
        "malicious_domain": "Network Security Engineer",
        "unpatched_cve":   "Vulnerability Management",
        "credential_combo": "IT Administrator",
        "leaked_api_key":  "Security Lead",
        "phishing":        "SOC Analyst",
        "malware_hash":    "Incident Response",
        "ransomware":      "Incident Response",
        "data_leak":       "Security Lead",
        "typosquat":       "Security Lead",
        "exec_exposure":   "CISO",
        "cloud_exposure":  "Cloud Security",
    }
    role = roles.get(playbook_key, "SOC Analyst")
    if severity == SeverityLevel.CRITICAL:
        role = f"CISO / {role}"
    return role
