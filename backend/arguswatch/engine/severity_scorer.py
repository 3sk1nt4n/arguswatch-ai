"""
Severity Scorer - spec-exact SLA tiers + auto-override conditions.
CRITICAL: 1-4h | HIGH: 4-24h | MEDIUM: 24-72h | LOW: 72h+
KEV actively_exploited:true → auto-upgrade to CRITICAL 24h.
"""
from dataclasses import dataclass

@dataclass
class ScoredResult:
    severity: str
    sla_hours: int
    assignee_role: str
    override_reason: str = ""

# IOC type → (severity, sla_hours, assignee_role)
IOC_SLA_MAP = {
    # Category 1-2: Credentials & API Keys
    "aws_access_key":          ("CRITICAL", 2,  "security_lead"),
    "aws_secret_key":          ("CRITICAL", 2,  "security_lead"),
    "aws_root_key":            ("CRITICAL", 1,  "security_lead"),
    "github_pat_classic":      ("CRITICAL", 2,  "dev_lead"),
    "github_oauth_token":      ("CRITICAL", 2,  "dev_lead"),
    "github_fine_grained_pat": ("CRITICAL", 2,  "dev_lead"),
    "github_saas_token":       ("CRITICAL", 2,  "dev_lead"),
    "gitlab_pat":              ("CRITICAL", 2,  "dev_lead"),
    "openai_api_key":          ("CRITICAL", 2,  "security_lead"),
    "anthropic_api_key":       ("CRITICAL", 2,  "security_lead"),
    "stripe_live_key":         ("CRITICAL", 1,  "security_lead"),
    "private_key":             ("CRITICAL", 2,  "dev_secops"),
    "email_password_combo":    ("CRITICAL", 4,  "it_admin"),
    "breachdirectory_combo":   ("CRITICAL", 4,  "it_admin"),
    "plaintext_password":      ("HIGH",     8,  "it_admin"),
    "db_connection_string":    ("CRITICAL", 2,  "dev_secops"),
    "remote_credential":       ("CRITICAL", 2,  "it_admin"),

    # Category 10-11: Session & OAuth
    "session_cookie":          ("CRITICAL", 1,  "dev_secops"),
    "jwt_token":               ("HIGH",     4,  "dev_secops"),
    "google_oauth_bearer":     ("CRITICAL", 1,  "dev_secops"),
    "google_oauth_token":      ("CRITICAL", 1,  "dev_secops"),
    "slack_bot_token":         ("CRITICAL", 1,  "dev_secops"),
    "slack_user_token":        ("CRITICAL", 1,  "dev_secops"),
    "slack_bot_oauth":         ("CRITICAL", 1,  "dev_secops"),
    "slack_user_oauth":        ("CRITICAL", 1,  "dev_secops"),
    "ntlm_hash_format":        ("CRITICAL", 2,  "security_lead"),
    "kerberos_ccache":         ("CRITICAL", 1,  "security_lead"),
    "golden_ticket_indicator": ("CRITICAL", 1,  "security_lead"),

    # Category 3-4: Network & Domain
    "ipv4":                    ("MEDIUM",   48, "network_secops"),
    "ipv6":                    ("MEDIUM",   48, "network_secops"),
    "domain":                  ("MEDIUM",   48, "security_team"),
    "url":                     ("HIGH",     8,  "security_team"),
    "onion_address":           ("HIGH",     8,  "security_team"),
    "malicious_url_path":      ("HIGH",     8,  "security_team"),

    # Category 6: Hashes
    "sha256":                  ("MEDIUM",   24, "secops"),
    "md5":                     ("MEDIUM",   24, "secops"),
    "sha1":                    ("MEDIUM",   24, "secops"),

    # Category 9: Threat Actor
    "ransomware_group":        ("CRITICAL", 1,  "ciso_legal"),
    "ransom_note":             ("CRITICAL", 1,  "ciso_legal"),
    "data_auction":            ("CRITICAL", 1,  "ciso_legal"),
    "apt_group":               ("HIGH",     8,  "security_lead"),

    # Category 4: Phishing
    "phishing_domain":         ("HIGH",     8,  "security_team"),

    # Category 8: Financial & PII
    "visa_card":               ("CRITICAL", 2,  "ciso_legal"),
    "mastercard":              ("CRITICAL", 2,  "ciso_legal"),
    "ssn":                     ("CRITICAL", 2,  "ciso_legal"),
    "iban":                    ("CRITICAL", 2,  "ciso_legal"),

    # Category 12: SaaS Misconfig
    "s3_public_url":           ("HIGH",     4,  "devops_it"),
    "azure_blob_public":       ("HIGH",     4,  "devops_it"),
    "gcs_public_bucket":       ("HIGH",     4,  "devops_it"),
    "open_analytics_service":  ("HIGH",     4,  "devops_it"),

    # Category 13: Privileged Account
    "privileged_credential":   ("HIGH",     4,  "security_lead"),
    "breakglass_credential":   ("CRITICAL", 1,  "ciso"),

    # Category 14: Shadow IT
    "personal_cloud_share":    ("MEDIUM",   120,"it_admin"),
    "dev_tunnel_exposed":      ("HIGH",     48, "it_admin"),
    "rogue_dev_endpoint":      ("MEDIUM",   120,"it_admin"),

    # Category 15: Data Exfil
    "data_transfer_cmd":       ("CRITICAL", 2,  "soc_lead_ciso"),
    "sql_outfile_exfil":       ("CRITICAL", 2,  "soc_lead_ciso"),
    "base64_exfil":            ("HIGH",     4,  "soc_lead"),

    # CVE
    "cve_id":                  ("HIGH",     72, "it_dev"),
    "cve_kev":                 ("HIGH",     72, "it_dev"),

    # Dark web
    "ransomware_leak":         ("CRITICAL", 1,  "ciso_legal"),
    "darkweb_mention":         ("HIGH",     8,  "security_lead"),
    "paste_dump":              ("HIGH",     8,  "security_lead"),
    "github_secret":           ("CRITICAL", 2,  "dev_lead"),
    "c2_ip":                   ("HIGH",     4,  "network_secops"),
    "phishing_url":            ("HIGH",     8,  "security_team"),
    "malware_hash":            ("MEDIUM",   24, "secops"),
}

DEFAULTS = {
    "CRITICAL": (2,  "security_lead"),
    "HIGH":     (8,  "security_team"),
    "MEDIUM":   (48, "secops"),
    "LOW":      (72, "it_admin"),
    "INFO":     (168,"analyst"),
}

def score(
    category: str,
    ioc_type: str,
    confidence: float = 0.75,
    kev_actively_exploited: bool = False,
    context_metadata: dict | None = None,
) -> ScoredResult:
    meta = context_metadata or {}
    key = ioc_type.lower()
    sev, sla, assignee = IOC_SLA_MAP.get(key, ("MEDIUM", 48, "secops"))

    # Confidence downgrade
    if confidence < 0.5:
        sev = _downgrade(sev)
    elif confidence < 0.7 and sev == "CRITICAL":
        sev = "HIGH"

    override_reason = ""

    # SLA Override 1: KEV actively_exploited
    if kev_actively_exploited and key == "cve_id":
        sev = "CRITICAL"
        sla = 24
        override_reason = "KEV actively_exploited:true → auto-upgraded to CRITICAL 24h"

    # SLA Override 2: Confirmed active key
    if meta.get("api_key_active") and key in ("aws_access_key", "stripe_live_key"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "API key confirmed active → Tier 3 escalation 1h"

    # SLA Override 3: Confirmed real data in ransom/leak
    if meta.get("data_confirmed") and key in ("ransomware_leak", "ransomware_group"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "Data sample confirmed real → Tier 3 immediate"

    # SLA Override 4: Active login detected
    if meta.get("active_login_detected"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "Active login detected on compromised credential → Tier 3 1h"

    # SLA Override 5: Corporate password match
    if meta.get("corporate_password_match"):
        sev = "CRITICAL"
        sla = 2
        override_reason = "Exposed password matches corporate IdP hash → CRITICAL 2h"

    # SLA Override 6: EPSS > 0.7 = minimum HIGH (VulnPilot Triple-Lock Rule)
    # If exploit probability is above 70%, this CVE MUST be at least HIGH
    # regardless of what CVSS says. Prevents dangerous downgrades.
    epss = float(meta.get("epss_score", 0) or 0)
    if epss > 0.7 and key == "cve_id" and sev in ("MEDIUM", "LOW", "INFO"):
        sev = "HIGH"
        sla = min(sla, 24)
        override_reason = f"EPSS {epss:.0%} > 70% → minimum HIGH 24h (Triple-Lock Rule)"
    if epss > 0.9 and key == "cve_id" and sev != "CRITICAL":
        sev = "CRITICAL"
        sla = min(sla, 12)
        override_reason = f"EPSS {epss:.0%} > 90% → auto-upgraded to CRITICAL 12h (Triple-Lock Rule)"

    # Pull correct SLA from map after potential override
    if not override_reason:
        sla = IOC_SLA_MAP.get(key, (sev, DEFAULTS[sev][0], assignee))[1]

    return ScoredResult(severity=sev, sla_hours=sla, assignee_role=assignee, override_reason=override_reason)

def _downgrade(sev: str) -> str:
    chain = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    idx = chain.index(sev) if sev in chain else 2
    return chain[min(idx + 1, len(chain) - 1)]
