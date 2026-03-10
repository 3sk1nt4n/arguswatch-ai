"""
Severity Scorer - spec-exact SLA tiers + auto-override conditions.
CRITICAL: 1-4h | HIGH: 4-24h | MEDIUM: 24-72h | LOW: 72h+
KEV actively_exploited:true -> auto-upgrade to CRITICAL 24h.
"""
from dataclasses import dataclass

@dataclass
class ScoredResult:
    severity: str
    sla_hours: int
    assignee_role: str
    override_reason: str = ""

# IOC type -> (severity, sla_hours, assignee_role)
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
    "exposed_secret":          ("CRITICAL", 2,  "security_lead"),
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
    "ntlm_hash":               ("CRITICAL", 2,  "security_lead"),
    # V16.4.7: REMOVED kerberos_ccache -  binary format, impossible to detect in text
    "golden_ticket_indicator": ("CRITICAL", 1,  "security_lead"),
    "saml_assertion":          ("HIGH",     4,  "security_lead"),

    # Category 3-4: Network & Domain
    "ipv4":                    ("MEDIUM",   48, "network_secops"),
    "ipv6":                    ("MEDIUM",   48, "network_secops"),
    "cidr_range":              ("MEDIUM",   48, "network_secops"),
    "domain":                  ("MEDIUM",   48, "security_team"),
    "url":                     ("HIGH",     8,  "security_team"),
    "onion_address":           ("HIGH",     8,  "security_team"),
    "malicious_url_path":      ("HIGH",     8,  "security_team"),

    # Category 5: Email
    "email":                   ("LOW",      120,"secops"),
    "executive_email":         ("HIGH",     8,  "security_lead"),
    "email_hash_combo":        ("CRITICAL", 4,  "it_admin"),

    # Category 6: Hashes
    "sha256":                  ("MEDIUM",   24, "secops"),
    "hash_sha256":             ("MEDIUM",   24, "secops"),  # alias used in some collectors
    "sha512":                  ("MEDIUM",   24, "secops"),
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
    "amex_card":               ("CRITICAL", 2,  "ciso_legal"),
    "ssn":                     ("CRITICAL", 2,  "ciso_legal"),
    "iban":                    ("CRITICAL", 2,  "ciso_legal"),
    "swift_bic":               ("MEDIUM",   48, "finance_secops"),
    "bitcoin_address":         ("MEDIUM",   72, "secops"),
    "ethereum_address":        ("MEDIUM",   72, "secops"),
    "monero_address":          ("MEDIUM",   72, "secops"),

    # Category 2 continued: API Keys missing from original
    "google_api_key":          ("HIGH",     4,  "dev_lead"),
    "sendgrid_api_key":        ("CRITICAL", 2,  "dev_secops"),
    "twilio_account_sid":      ("MEDIUM",   24, "dev_lead"),
    "azure_sas_token":         ("CRITICAL", 2,  "dev_secops"),
    "azure_bearer":            ("CRITICAL", 1,  "dev_secops"),
    "github_app_token":        ("CRITICAL", 2,  "dev_lead"),
    "github_user_token":       ("HIGH",     4,  "dev_lead"),
    "username_password_combo":  ("CRITICAL", 4,  "it_admin"),

    # Category 7: Infrastructure Leaks
    "config_file":             ("HIGH",     8,  "devops_it"),
    "backup_file":             ("MEDIUM",   48, "devops_it"),
    "db_config":               ("HIGH",     8,  "devops_it"),
    "internal_hostname":       ("MEDIUM",   72, "it_admin"),
    "ldap_dn":                 ("MEDIUM",   48, "it_admin"),

    # Category 12: SaaS Misconfig
    "s3_public_url":           ("HIGH",     4,  "devops_it"),
    "s3_bucket_ref":           ("HIGH",     4,  "devops_it"),
    "azure_blob_public":       ("HIGH",     4,  "devops_it"),
    "gcs_public_bucket":       ("HIGH",     4,  "devops_it"),
    "open_analytics_service":  ("HIGH",     4,  "devops_it"),
    "elasticsearch_exposed":   ("HIGH",     4,  "devops_it"),

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
    "sql_dump_header":         ("HIGH",     4,  "soc_lead"),
    "sql_dump_detected":       ("HIGH",     8,  "soc_lead"),
    "sql_schema_dump":         ("HIGH",     8,  "soc_lead"),
    "csv_pii_dump":            ("CRITICAL", 2,  "ciso_legal"),
    "csv_credential_dump":     ("CRITICAL", 2,  "soc_lead_ciso"),
    "csv_financial_dump":      ("HIGH",     4,  "ciso_legal"),
    "archive_sensitive_data":  ("HIGH",     8,  "soc_lead"),
    "archive_and_exfil":       ("CRITICAL", 2,  "soc_lead_ciso"),
    "file_share_exfil":        ("HIGH",     8,  "soc_lead"),
    "base64_exfil":            ("HIGH",     4,  "soc_lead"),

    # Threat intel
    "advisory":                ("MEDIUM",   72, "secops"),

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

# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING -  every IOC type -> technique + tactic
# Used by: dashboard display, investigation narratives, campaign detector,
#          STIX export, and AI triage prompts for contextual reasoning.
#
# Format: "ioc_type": ("technique_id", "tactic", "one-line description")
# ══════════════════════════════════════════════════════════════════════

IOC_MITRE_MAP = {
    # ── Credential Access (TA0006) ──
    "email_password_combo":    ("T1078.004", "Credential Access",  "Valid account credentials from breach dump"),
    "username_password_combo": ("T1078.004", "Credential Access",  "Valid account credentials from breach dump"),
    "email_hash_combo":        ("T1110.002", "Credential Access",  "Crackable password hash from breach"),
    "breachdirectory_combo":   ("T1078.004", "Credential Access",  "Credential from breach aggregator"),
    "plaintext_password":      ("T1552.001", "Credential Access",  "Plaintext password in unsecured file"),
    "db_connection_string":    ("T1552.001", "Credential Access",  "Database credential in exposed config"),
    "remote_credential":       ("T1021",     "Lateral Movement",   "Remote service credential (RDP/SSH/VNC) for lateral movement"),
    "ldap_dn":                 ("T1087.002", "Discovery",          "Active Directory object enumeration"),
    "ntlm_hash":               ("T1550.002", "Lateral Movement",   "Pass the Hash -  NTLM credential for lateral movement"),
    "ntlm_hash_format":        ("T1550.002", "Lateral Movement",   "Pass the Hash -  NTLM user:hash for lateral movement"),
    "privileged_credential":   ("T1078.002", "Privilege Escalation","Admin/root credential exposed"),
    "breakglass_credential":   ("T1098",     "Persistence",         "Emergency access account -  persistent backdoor if unreset"),
    "golden_ticket_indicator": ("T1550.003", "Lateral Movement",   "Pass the Ticket -  Kerberos golden ticket for domain-wide access"),
    "exposed_secret":          ("T1552.004", "Credential Access",  "Secret in public code repository"),

    # ── Unsecured Credentials / API Keys (T1552) ──
    "aws_access_key":          ("T1552.005", "Credential Access",  "AWS IAM key in public source"),
    "aws_secret_key":          ("T1552.005", "Credential Access",  "AWS secret key exposed"),
    "aws_root_key":            ("T1552.005", "Privilege Escalation","AWS root account key -  full account takeover"),
    "github_pat_classic":      ("T1552.004", "Credential Access",  "GitHub PAT in public repo/paste"),
    "github_fine_grained_pat": ("T1552.004", "Credential Access",  "GitHub fine-grained PAT exposed"),
    "github_oauth_token":      ("T1528",     "Credential Access",  "Stolen GitHub OAuth token"),
    "github_app_token":        ("T1552.004", "Credential Access",  "GitHub App installation token"),
    "github_saas_token":       ("T1552.004", "Credential Access",  "GitHub SaaS token exposed"),
    "github_user_token":       ("T1528",     "Credential Access",  "GitHub user-to-server token"),
    "gitlab_pat":              ("T1552.004", "Credential Access",  "GitLab PAT in public source"),
    "openai_api_key":          ("T1552.004", "Credential Access",  "OpenAI API key -  billing/data access"),
    "anthropic_api_key":       ("T1552.004", "Credential Access",  "Anthropic API key exposed"),
    "stripe_live_key":         ("T1552.004", "Credential Access",  "Stripe LIVE key -  payment system access"),
    "sendgrid_api_key":        ("T1552.004", "Credential Access",  "SendGrid key -  email impersonation risk"),
    "google_api_key":          ("T1552.004", "Credential Access",  "Google API key exposed"),
    "azure_sas_token":         ("T1552.004", "Credential Access",  "Azure shared access signature token"),
    "azure_bearer":            ("T1528",     "Credential Access",  "Azure OAuth bearer token"),
    "private_key":             ("T1552.004", "Credential Access",  "Private key (RSA/EC/SSH) exposed"),
    "twilio_account_sid":      ("T1552.004", "Credential Access",  "Twilio account credential exposed"),

    # ── Steal Application Access Token (T1528) ──
    "jwt_token":               ("T1528",     "Credential Access",  "Stolen JSON Web Token"),
    "saml_assertion":          ("T1606.002", "Lateral Movement",   "Forged/stolen SAML assertion -  cross-service lateral movement"),
    "session_cookie":          ("T1550.004", "Lateral Movement",   "Web session cookie hijack -  lateral access to services"),
    "google_oauth_token":      ("T1528",     "Credential Access",  "Google OAuth access token"),
    "google_oauth_bearer":     ("T1528",     "Credential Access",  "Google OAuth bearer token"),
    "slack_bot_token":         ("T1528",     "Credential Access",  "Slack bot token -  workspace access"),
    "slack_user_token":        ("T1528",     "Credential Access",  "Slack user token -  message/file access"),
    "slack_bot_oauth":         ("T1528",     "Credential Access",  "Slack bot OAuth token"),
    "slack_user_oauth":        ("T1528",     "Credential Access",  "Slack user OAuth token"),

    # ── Command and Control (TA0011) ──
    "ipv4":                    ("T1071.001", "Command and Control","Malicious IP (C2/scanning/botnet)"),
    "domain":                  ("T1071.001", "Command and Control","Malicious domain (C2/phishing infra)"),
    "url":                     ("T1071.001", "Command and Control","Malicious URL (payload/phishing)"),
    "malicious_url_path":      ("T1190",     "Initial Access",     "Exploitation path (wp-admin/phpmyadmin)"),
    "onion_address":           ("T1090.003", "Defense Evasion",     "Tor hidden service -  anonymized C2/exfil channel"),
    "cidr_range":              ("T1046",     "Discovery",          "Network range (scanning/recon)"),

    # ── Exfiltration (TA0010) ──
    "data_transfer_cmd":       ("T1048.003", "Exfiltration",       "Data exfil via curl/wget to external"),
    "base64_exfil":            ("T1027",     "Defense Evasion",     "Base64-encoded data -  obfuscation for exfil evasion"),
    "sql_outfile_exfil":       ("T1048",     "Exfiltration",       "SQL INTO OUTFILE data extraction"),
    "archive_and_exfil":       ("T1560.001", "Exfiltration",       "Archive + upload to external"),
    "csv_credential_dump":     ("T1003",     "Credential Access",  "Bulk credential dump in CSV"),
    "csv_pii_dump":            ("T1530",     "Collection",         "PII data collection for exfil"),
    "csv_financial_dump":      ("T1530",     "Collection",         "Financial data collected for exfil"),
    "sql_dump_header":         ("T1005",     "Collection",         "Database dump header detected"),
    "sql_dump_detected":       ("T1005",     "Collection",         "Full SQL dump detected"),
    "sql_schema_dump":         ("T1005",     "Collection",         "Database schema extraction"),
    "archive_sensitive_data":  ("T1560.001", "Collection",         "Sensitive files archived for exfil"),
    "file_share_exfil":        ("T1048.002", "Exfiltration",       "Data exfil via SMB/NFS file share"),
    "personal_cloud_share":    ("T1567.002", "Exfiltration",       "Data exfil via cloud storage (Drive/Dropbox)"),

    # ── Impact (TA0040) ──
    "ransomware_group":        ("T1486",     "Impact",             "Ransomware group claiming victim"),
    "ransom_note":             ("T1486",     "Impact",             "Ransomware note / extortion demand"),
    "data_auction":            ("T1657",     "Impact",             "Stolen data listed for sale"),

    # ── Reconnaissance (TA0043) ──
    "email":                   ("T1589.002", "Reconnaissance",     "Email address for targeting/phishing"),
    "executive_email":         ("T1589.002", "Reconnaissance",     "Executive email -  BEC/whaling target"),
    "advisory":                ("T1588.006", "Resource Development","Vulnerability advisory (GHSA/DSA)"),

    # ── Initial Access (TA0001) ──
    "cve_id":                  ("T1190",     "Initial Access",     "Exploitable vulnerability in tech stack"),

    # ── Discovery (TA0007) + Resource Development ──
    "config_file":             ("T1552.001", "Credential Access",  "Exposed config with secrets (.env/yml)"),
    "backup_file":             ("T1005",     "Collection",         "Exposed backup file (.bak/.sql/.dump)"),
    "db_config":               ("T1552.001", "Credential Access",  "Database config with credentials"),
    "internal_hostname":       ("T1018",     "Discovery",          "Internal hostname leaked externally"),
    "dev_tunnel_exposed":      ("T1572",     "Persistence",         "Dev tunnel as persistent external access (ngrok/localtunnel)"),
    "rogue_dev_endpoint":      ("T1133",     "Persistence",         "External remote service -  unauthorized persistent access"),

    # ── Cloud Misconfiguration ──
    "azure_blob_public":       ("T1530",     "Collection",         "Public Azure blob storage"),
    "gcs_public_bucket":       ("T1530",     "Collection",         "Public Google Cloud Storage bucket"),
    "elasticsearch_exposed":   ("T1530",     "Collection",         "Exposed Elasticsearch cluster"),
    "open_analytics_service":  ("T1530",     "Collection",         "Public analytics service (Firebase/Mixpanel)"),

    # ── Financial / PII ──
    "visa_card":               ("T1005",     "Collection",         "Payment card data stolen"),
    "mastercard":              ("T1005",     "Collection",         "Payment card data stolen"),
    "amex_card":               ("T1005",     "Collection",         "Payment card data stolen"),
    "ssn":                     ("T1005",     "Collection",         "Social Security Number exposed"),
    "iban":                    ("T1005",     "Collection",         "Bank account number exposed"),
    "swift_bic":               ("T1005",     "Collection",         "SWIFT/BIC code in leak context"),

    # ── Hashes ──
    "sha256":                  ("T1204.002", "Execution",          "Malware hash (SHA-256)"),
    "hash_sha256":             ("T1204.002", "Execution",          "Malware hash (SHA-256 alias)"),
    "sha512":                  ("T1204.002", "Execution",          "File hash (SHA-512)"),

    # ── Threat Actor Intelligence ──
    "apt_group":               ("T1583",     "Resource Development","Known APT group activity"),
    "bitcoin_address":         ("T1496",     "Impact",             "Crypto address (ransom/mining)"),
    "ethereum_address":        ("T1496",     "Impact",             "Ethereum address in threat context"),
    "monero_address":          ("T1496",     "Impact",             "Monero address (privacy coin -  ransom)"),

    # ── Collector-specific types ──
    "cve_kev":                 ("T1190",     "Initial Access",     "CISA Known Exploited Vulnerability"),
    "ransomware_leak":         ("T1486",     "Impact",             "Ransomware leak site posting"),
    "darkweb_mention":         ("T1213",     "Collection",         "Customer mentioned on dark web"),
    "paste_dump":              ("T1213",     "Collection",         "Credential/data dump on paste site"),
    "github_secret":           ("T1552.004", "Credential Access",  "Secret exposed in GitHub repo"),
    "c2_ip":                   ("T1071.001", "Command and Control","Confirmed C2 server IP"),
    "phishing_url":            ("T1566.002", "Initial Access",     "Phishing URL targeting org"),
    "malware_hash":            ("T1204.002", "Execution",          "Known malware sample hash"),
}


def get_mitre_context(ioc_type: str) -> dict:
    """Get MITRE ATT&CK context for an IOC type.
    Returns: {"technique": "T1552.004", "tactic": "Credential Access", "description": "..."}
    """
    entry = IOC_MITRE_MAP.get(ioc_type)
    if entry:
        return {"technique": entry[0], "tactic": entry[1], "description": entry[2]}
    return {"technique": "unknown", "tactic": "unknown", "description": f"No MITRE mapping for {ioc_type}"}


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
        override_reason = "KEV actively_exploited:true -> auto-upgraded to CRITICAL 24h"

    # SLA Override 2: Confirmed active key
    if meta.get("api_key_active") and key in ("aws_access_key", "stripe_live_key"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "API key confirmed active -> Tier 3 escalation 1h"

    # SLA Override 3: Confirmed real data in ransom/leak
    if meta.get("data_confirmed") and key in ("ransomware_leak", "ransomware_group"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "Data sample confirmed real -> Tier 3 immediate"

    # SLA Override 4: Active login detected
    if meta.get("active_login_detected"):
        sev = "CRITICAL"
        sla = 1
        override_reason = "Active login detected on compromised credential -> Tier 3 1h"

    # SLA Override 5: Corporate password match
    if meta.get("corporate_password_match"):
        sev = "CRITICAL"
        sla = 2
        override_reason = "Exposed password matches corporate IdP hash -> CRITICAL 2h"

    # SLA Override 6: EPSS > 0.7 = minimum HIGH (VulnPilot Triple-Lock Rule)
    # If exploit probability is above 70%, this CVE MUST be at least HIGH
    # regardless of what CVSS says. Prevents dangerous downgrades.
    epss = float(meta.get("epss_score", 0) or 0)
    if epss > 0.7 and key == "cve_id" and sev in ("MEDIUM", "LOW", "INFO"):
        sev = "HIGH"
        sla = min(sla, 24)
        override_reason = f"EPSS {epss:.0%} > 70% -> minimum HIGH 24h (Triple-Lock Rule)"
    if epss > 0.9 and key == "cve_id" and sev != "CRITICAL":
        sev = "CRITICAL"
        sla = min(sla, 12)
        override_reason = f"EPSS {epss:.0%} > 90% -> auto-upgraded to CRITICAL 12h (Triple-Lock Rule)"

    # Pull correct SLA from map after potential override
    if not override_reason:
        sla = IOC_SLA_MAP.get(key, (sev, DEFAULTS[sev][0], assignee))[1]

    return ScoredResult(severity=sev, sla_hours=sla, assignee_role=assignee, override_reason=override_reason)

def _downgrade(sev: str) -> str:
    chain = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    idx = chain.index(sev) if sev in chain else 2
    return chain[min(idx + 1, len(chain) - 1)]
