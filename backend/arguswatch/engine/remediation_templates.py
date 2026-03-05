"""
Remediation Templates - per-IOC-type actionable guidance
=========================================================
Every scored finding needs a clear, copy-paste-ready remediation action.
This module maps IOC types to specific, technical remediation steps.

Used by: finding_generator when creating findings from scored detections.
"""

# IOC type → (action_title, remediation_steps, urgency_note)
REMEDIATION_TEMPLATES: dict[str, dict] = {
    # ── Cat 1: Stolen Credentials ──
    "email_password_combo": {
        "title": "Force Password Reset - Compromised Credentials",
        "steps": [
            "Immediately force password reset for affected account",
            "Revoke all active sessions for the user",
            "Check login logs for unauthorized access from unknown IPs",
            "Enable MFA if not already enforced",
            "Notify the employee and provide phishing awareness guidance",
        ],
        "urgency": "Stealer log credentials may include session cookies that bypass MFA",
    },
    "breachdirectory_combo": {
        "title": "Credential Breach - Password Reuse Check",
        "steps": [
            "Force password reset for affected account",
            "Check if password is reused across other corporate systems",
            "Review login history for unauthorized access",
            "Enable MFA if not enforced",
        ],
        "urgency": "Older breach - credential stuffing attacks may already have been attempted",
    },
    "username_password_combo": {
        "title": "Force Password Reset - Username/Password Exposed",
        "steps": [
            "Identify the system this credential belongs to",
            "Force password reset immediately",
            "Check access logs for the affected system",
            "Enable MFA for the affected service",
        ],
    },
    "remote_credential": {
        "title": "Rotate Remote Access Credentials (RDP/SSH/VNC)",
        "steps": [
            "Immediately change the exposed credential",
            "Check remote access logs for unauthorized sessions",
            "Restrict remote access to VPN-only if not already",
            "Enable MFA for all remote access methods",
            "Consider disabling the exposed service temporarily",
        ],
        "urgency": "Remote access credentials are actively scanned by botnets within minutes of exposure",
    },
    "db_connection_string": {
        "title": "Rotate Database Credentials - Connection String Exposed",
        "steps": [
            "Immediately rotate the database password",
            "Audit the database for unauthorized queries or data access",
            "Restrict DB access to application servers only (no public access)",
            "Check if the connection string includes admin/root privileges",
            "Review .env / config management practices",
        ],
        "urgency": "Database connection strings often include admin credentials",
    },
    "plaintext_password": {
        "title": "Rotate Exposed Password",
        "steps": [
            "Identify which system/account this password belongs to",
            "Force immediate password reset",
            "Check for password reuse across systems",
        ],
    },

    # ── Cat 2: API Keys & Tokens ──
    "aws_access_key": {
        "title": "Rotate AWS Access Key - Potential Cloud Compromise",
        "steps": [
            "Immediately deactivate the exposed access key in IAM console",
            "Generate a new access key pair",
            "Review CloudTrail logs for unauthorized API calls",
            "Check for new IAM users, roles, or policies created",
            "Scan for unauthorized EC2 instances or S3 access",
            "If aws_secret_key also exposed: assume full compromise",
        ],
        "urgency": "Exposed AWS keys are exploited by automated scanners within MINUTES",
    },
    "aws_secret_key": {
        "title": "CRITICAL - AWS Secret Key Exposed - Full Cloud Compromise",
        "steps": [
            "Immediately deactivate ALL access keys for this IAM user",
            "Rotate the secret key and update all applications",
            "Review CloudTrail for unauthorized activity (last 90 days)",
            "Check for cryptomining instances, data exfiltration",
            "Consider creating a new IAM user instead of rotating",
        ],
        "urgency": "With secret key: attacker has FULL access to this IAM user's permissions",
    },
    "aws_root_key": {
        "title": "EMERGENCY - AWS Root Key Exposed - Account Takeover",
        "steps": [
            "IMMEDIATELY rotate root access keys",
            "Enable MFA on root account if not already",
            "Review ALL CloudTrail events for unauthorized activity",
            "Check billing for unexpected charges (cryptomining)",
            "Contact AWS support for incident investigation",
            "Consider creating a new AWS account if compromise confirmed",
        ],
        "urgency": "Root key = GOD MODE. Attacker can delete everything, create backdoors",
    },
    "github_pat_classic": {
        "title": "Revoke GitHub Personal Access Token",
        "steps": [
            "Revoke the token in GitHub Settings → Developer Settings → Tokens",
            "Generate a new token with minimum required scopes",
            "Check GitHub audit log for unauthorized actions",
            "Review if any repos were cloned or modified",
        ],
    },
    "stripe_live_key": {
        "title": "EMERGENCY - Rotate Stripe Live API Key",
        "steps": [
            "Roll the API key immediately in Stripe Dashboard",
            "Review recent transactions for unauthorized charges",
            "Check for new connected accounts or payout destinations",
            "Enable webhook signature verification",
            "Contact Stripe security team",
        ],
        "urgency": "Live Stripe key = attacker can process payments, access customer data",
    },
    "private_key": {
        "title": "Rotate Private Key - Certificate/SSH Compromise",
        "steps": [
            "Generate a new key pair immediately",
            "Revoke the old certificate/key",
            "Update all systems that use this key",
            "If SSH key: remove from all authorized_keys files",
            "If TLS cert: reissue certificate with new key",
        ],
    },
    "openai_api_key": {
        "title": "Rotate OpenAI API Key",
        "steps": [
            "Revoke the key in OpenAI dashboard",
            "Generate a new key",
            "Check usage logs for unexpected charges",
            "Set usage limits on new key",
        ],
    },

    # ── Cat 6: Hash IOCs (with EDR) ──
    "hash_sha256": {
        "title": "Malware Confirmed on Endpoint - Isolate and Investigate",
        "steps": [
            "Immediately isolate the affected host from the network",
            "Collect forensic image before remediation",
            "Run full AV/EDR scan on the host",
            "Check for lateral movement from this host",
            "Reset all credentials used on this machine",
            "Reimage the host after investigation",
        ],
        "urgency": "Confirmed malware presence - assume credential theft and lateral movement",
    },

    # ── Cat 7: Infrastructure Leaks ──
    "config_file": {
        "title": "Rotate ALL Secrets in Exposed Config File",
        "steps": [
            "Identify all secrets in the exposed file (.env, secrets.yml)",
            "Rotate every credential, API key, and token found",
            "Remove the file from public repositories",
            "Add config files to .gitignore",
            "Implement secret scanning in CI/CD pipeline",
        ],
    },
    "internal_hostname": {
        "title": "Internal Infrastructure Exposed - Review Network Segmentation",
        "steps": [
            "Verify the internal hostname is not externally resolvable",
            "Review firewall rules for the exposed service",
            "Check if the hostname reveals network architecture",
            "Implement split-horizon DNS if not already",
        ],
    },

    # ── Cat 8: Financial ──
    "visa_card": {
        "title": "PCI INCIDENT - Customer Payment Data Exposed",
        "steps": [
            "Engage PCI forensic investigator (PFI)",
            "Notify card brands per PCI DSS requirements",
            "Identify and contain the source of data exposure",
            "Begin PCI DSS incident response procedures",
            "Preserve evidence for forensic investigation",
        ],
        "urgency": "PCI DSS requires notification within 24-72 hours of confirmed breach",
    },
    "ssn": {
        "title": "PII INCIDENT - Social Security Numbers Exposed",
        "steps": [
            "Engage legal counsel for breach notification requirements",
            "Identify affected individuals",
            "Contain the source of exposure",
            "Prepare breach notification per state/federal law",
            "Offer credit monitoring to affected individuals",
        ],
        "urgency": "State breach notification laws have strict timelines (often 30-60 days)",
    },

    # ── Cat 9: Threat Actor ──
    "ransomware_group": {
        "title": "EMERGENCY - Ransomware Leak Site Mention - Engage IR Team",
        "steps": [
            "Immediately engage incident response team",
            "Verify if data samples are real (compare to internal data)",
            "Isolate potentially compromised systems",
            "Preserve all logs and evidence",
            "Engage legal counsel for regulatory obligations",
            "Do NOT pay ransom without legal/IR guidance",
        ],
        "urgency": "Ransomware leak posts typically precede data publication by 3-7 days",
    },

    # ── Cat 10: Session Tokens ──
    "session_cookie": {
        "title": "Invalidate All Sessions - Session Token Stolen",
        "steps": [
            "Force logout / invalidate all active sessions for the user",
            "Force password reset",
            "Check session logs for unauthorized access",
            "Rotate session signing keys if applicable",
        ],
    },
    "kerberos_ccache": {
        "title": "CRITICAL - Kerberos Ticket Stolen - Potential Domain Compromise",
        "steps": [
            "Reset the password for the affected principal",
            "If krbtgt: perform DOUBLE krbtgt password reset",
            "Review Domain Controller security logs",
            "Check for Golden Ticket or Silver Ticket indicators",
            "Audit all privileged account access",
        ],
        "urgency": "Kerberos ticket theft enables pass-the-ticket attacks against any service",
    },
    "golden_ticket_indicator": {
        "title": "EMERGENCY - Golden Ticket Detected - Full Domain Compromise",
        "steps": [
            "Perform DOUBLE krbtgt password reset (reset → wait → reset again)",
            "Reset ALL domain admin account passwords",
            "Review all Domain Controller security event logs",
            "Check for persistence mechanisms (scheduled tasks, services)",
            "Engage incident response team for full domain audit",
            "Assume all domain credentials are compromised",
        ],
        "urgency": "Golden Ticket = attacker has permanent domain admin access until krbtgt is double-reset",
    },

    # ── Cat 12: SaaS Misconfig ──
    "s3_public_url": {
        "title": "Restrict S3 Bucket - Publicly Accessible",
        "steps": [
            "Set bucket ACL to private (Block Public Access = ON)",
            "Review bucket contents for sensitive data",
            "Check S3 access logs for unauthorized downloads",
            "Enable S3 Object Lock if storing compliance data",
            "Set up AWS Config rule to detect future public buckets",
        ],
    },
    "elasticsearch_exposed": {
        "title": "Secure Elasticsearch - Publicly Accessible",
        "steps": [
            "Restrict access to VPC/internal network only",
            "Enable authentication (X-Pack Security or SearchGuard)",
            "Review data stored for sensitive information",
            "Check for unauthorized data access or deletion",
        ],
    },

    # ── Cat 13: Privileged Accounts ──
    "privileged_credential": {
        "title": "CRITICAL - Admin/Root Credential Exposed",
        "steps": [
            "Immediately rotate the privileged credential",
            "Review all admin actions for unauthorized changes",
            "Check for new accounts, persistence mechanisms",
            "Enable MFA for all privileged accounts",
            "Implement Privileged Access Management (PAM)",
        ],
    },

    # ── Cat 14: Shadow IT ──
    "dev_tunnel_exposed": {
        "title": "Shutdown Exposed Dev Tunnel (ngrok/serveo)",
        "steps": [
            "Identify the developer and the tunneled service",
            "Terminate the tunnel session",
            "Review what was exposed through the tunnel",
            "Implement network policy blocking tunnel services",
            "Provide secure alternative (corporate VPN)",
        ],
    },

    # ── Cat 15: Data Exfiltration ──
    "data_transfer_cmd": {
        "title": "EMERGENCY - Potential Data Exfiltration Detected",
        "steps": [
            "Immediately isolate the source host",
            "Block the destination IP/domain at the firewall",
            "Capture and analyze the data being transferred",
            "Preserve all logs for forensic investigation",
            "Engage incident response team",
        ],
        "urgency": "Active data exfiltration = breach in progress",
    },

    # ── Cat 16: CVE ──
    "cve_id": {
        "title": "Patch Vulnerability - CVE Confirmed Exploitable",
        "steps": [
            "Apply vendor patch or upgrade to fixed version",
            "If no patch available: implement vendor-recommended mitigations",
            "Check for indicators of exploitation (CISA KEV if applicable)",
            "Test patch in staging before production deployment",
            "Update vulnerability scanner signatures",
        ],
    },
}


def get_remediation(ioc_type: str) -> dict:
    """Get remediation template for an IOC type.
    Falls back to generic template if specific one doesn't exist.
    """
    if ioc_type in REMEDIATION_TEMPLATES:
        return REMEDIATION_TEMPLATES[ioc_type]

    # Category-based fallback
    CATEGORY_FALLBACKS = {
        "api_key": {"title": "Rotate Exposed API Key/Token", "steps": [
            "Revoke the exposed key/token immediately",
            "Generate a new credential with minimum required permissions",
            "Update all systems using this credential",
            "Review access logs for unauthorized usage",
        ]},
        "session": {"title": "Invalidate Stolen Session Token", "steps": [
            "Force logout all active sessions for affected user",
            "Force password reset",
            "Review session logs for unauthorized access",
        ]},
        "financial": {"title": "PCI/Regulatory Incident - Financial Data Exposed", "steps": [
            "Engage legal counsel for breach notification requirements",
            "Identify and contain the data exposure source",
            "Notify affected parties per regulatory requirements",
        ]},
        "crypto": {"title": "Monitor Crypto Address for Ransomware Payments", "steps": [
            "Document the address for law enforcement reporting",
            "Monitor blockchain transactions if relevant to active investigation",
        ]},
    }

    # Try to match by prefix
    for prefix, template in CATEGORY_FALLBACKS.items():
        if prefix in ioc_type:
            return template

    # Generic fallback
    return {
        "title": f"Investigate - {ioc_type.replace('_', ' ').title()}",
        "steps": [
            "Verify the finding is not a false positive",
            "Determine the scope of exposure",
            "Implement appropriate remediation",
            "Document findings and actions taken",
        ],
    }
