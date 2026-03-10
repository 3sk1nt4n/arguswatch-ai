"""
Pattern Matcher - 15 IOC categories, 100+ patterns.
Spec-exact implementation per ArgusWatch Master Architecture.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class IOCMatch:
    category: str
    ioc_type: str
    value: str
    context: str
    confidence: float
    line_number: int = 0

# ── Category 1: Stolen Credentials ──
CRED_PATTERNS = [
    (r'[\w\.\-\+]+@[\w\.\-]+\.[a-z]{2,}:[\S]{6,}', 'email_password_combo', 0.85),
    (r'[\w\.\-]{3,}:[^\s\{\}\(\);,]{6,}:[^\s\{\}\(\);,]{6,}', 'username_password_combo', 0.75),
    (r'[\w\.\-\+]+@[\w\.\-]+\.[a-z]{2,}:[a-f0-9]{32,64}', 'email_hash_combo', 0.85),
    (r'(?:rdp|ssh|vnc|ftp)://[\w\.\-]+:[\S]+@[\w\.\-\.]+', 'remote_credential', 0.90),
    (r'(?:mysql|postgresql|mssql|mongodb|redis)://[\S]+:[\S]+@[\S]+', 'db_connection_string', 0.92),
    (r'(?:CN|OU|DC)=[\w\s\,\=]+,DC=[\w]+', 'ldap_dn', 0.80),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[\S]{8,}["\']?', 'plaintext_password', 0.80),
    # V16.4.7: REMOVED crypto_seed_phrase -  12+ english words matches every README/doc. Massive FP rate.
    # BreachDirectory plaintext format
    (r'[\w\.\-\+]+@[\w\.\-]+:[^\s\|]{6,}', 'breachdirectory_combo', 0.88),
]

# ── Category 2: API Keys & Tokens (35+ patterns) ──
API_KEY_PATTERNS = [
    (r'\bAKIA[0-9A-Z]{16}\b', 'aws_access_key', 0.99),
    (r'\b(?:aws_secret|AWS_SECRET)[_\s]*(?:access[_\s]*)?key[_\s]*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?', 'aws_secret_key', 0.95),
    (r'\bAIza[0-9A-Za-z\-_]{35}\b', 'google_api_key', 0.99),
    (r'\bghp_[A-Za-z0-9]{36}\b', 'github_pat_classic', 0.99),
    (r'\bgho_[A-Za-z0-9]{36}\b', 'github_oauth_token', 0.99),
    (r'\bghs_[A-Za-z0-9]{36}\b', 'github_app_token', 0.99),
    (r'\bglpat-[A-Za-z0-9\-_]{20}\b', 'gitlab_pat', 0.99),
    (r'\bxoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}\b', 'slack_bot_token', 0.99),
    (r'\bxoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}\b', 'slack_user_token', 0.99),
    (r'\bsk_live_[A-Za-z0-9]{24,}\b', 'stripe_live_key', 0.99),
    # V16.4.7: REMOVED stripe_test_key -  sk_test_ keys are intentionally public. Not a security threat.
    (r'\bsk-[A-Za-z0-9]{20,}\b', 'openai_api_key', 0.92),
    (r'\bsk-(?:proj|prod|live)-[A-Za-z0-9\-_]{20,}\b', 'openai_api_key', 0.99),
    (r'\bsk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{40,}\b', 'anthropic_api_key', 0.99),
    (r'\bSG\.[A-Za-z0-9\-_]{15,}\.[A-Za-z0-9\-_]{15,}\b', 'sendgrid_api_key', 0.99),
    (r'\bAC[a-z0-9]{32}\b', 'twilio_account_sid', 0.90),
    # V16.4.7: REMOVED twilio_auth_token -  SK+32hex overlaps with Stripe keys, random hashes. Too many FPs.
    (r'\b[A-Za-z0-9_\-]{32,}\.blob\.core\.windows\.net[^\s]*sig=[A-Za-z0-9%]+', 'azure_sas_token', 0.92),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 'private_key', 0.99),
    (r'\bey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b', 'jwt_token', 0.88),
    # OAuth tokens (Category 11)
    (r'\bya29\.[A-Za-z0-9\-_]+\b', 'google_oauth_token', 0.99),
    (r'\bgithub_pat_[A-Za-z0-9_]{20,}\b', 'github_fine_grained_pat', 0.99),
]

# ── Category 3: Network IOCs ──
NETWORK_PATTERNS = [
    (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'ipv4', 0.70),
    (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', 'ipv6', 0.85),
    # private_ip DELETED - 10.x/172.16-31.x/192.168.x from external feeds is
    # unattributable victim internal network. Generates pure noise.
    (r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b', 'cidr_range', 0.80),
]

# ── Category 4: Domain & URL IOCs ──
DOMAIN_PATTERNS = [
    (r'\bhttps?://[^\s<>"\']{10,}', 'url', 0.75),
    (r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|xyz|info|biz|ru|cn|tk|ml|ga|cf|gq|pw|top|club|online|site|web|tech|store|live)\b', 'domain', 0.70),
    (r'\b[a-z0-9\-]+\.(php|asp|aspx|jsp|cgi)\?[\S]+', 'malicious_url_path', 0.80),
    (r'\.onion\b', 'onion_address', 0.95),
]

# ── Category 5: Email IOCs ──
EMAIL_PATTERNS = [
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'email', 0.75),
    (r'\b(?:ceo|cfo|ciso|cto|vp|director|president|executive)\s+[\w\s]+@[\w\.\-]+\.[a-z]{2,}', 'executive_email', 0.85),
]

# ── Category 6: File & Hash IOCs ──
HASH_PATTERNS = [
    (r'\b[a-fA-F0-9]{32}\b', 'md5', 0.75),
    (r'\b[a-fA-F0-9]{40}\b', 'sha1', 0.80),
    (r'\b[a-fA-F0-9]{64}\b', 'sha256', 0.88),
    (r'\b[a-fA-F0-9]{128}\b', 'sha512', 0.88),
]

# ── Category 7: Infrastructure & Code Leaks ──
INFRA_PATTERNS = [
    (r'(?:host|hostname|server|internal)[_\-\s]*[=:]\s*["\']?[\w\-\.]+\.(?:internal|local|corp|lan|intranet)["\']?', 'internal_hostname', 0.85),
    (r'(?:\.env|config\.yml|config\.json|secrets\.yml|\.aws/credentials)', 'config_file', 0.90),
    (r'(?:database_url|db_url|connection_string)\s*[=:]\s*["\']?[\S]+["\']?', 'db_config', 0.85),
    (r'(?:backup|dump|export)[\w\-]*\.(?:sql|bak|tar\.gz|zip)', 'backup_file', 0.80),
]

# ── Category 8: Financial & Identity ──
FINANCIAL_PATTERNS = [
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'visa_card', 0.80),
    (r'\b5[1-5][0-9]{14}\b', 'mastercard', 0.80),
    (r'\b3[47][0-9]{13}\b', 'amex_card', 0.80),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn', 0.85),
    (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})\b', 'iban', 0.85),
    # V16.4.7: FIXED swift_bic -  old regex matched every 10+ uppercase word (RANSOMWARE, CREDENTIAL, etc.)
    # New regex enforces ISO 3166-1 country code at positions 5-6. Rejects all English words.
    # Format: BBBB (bank) + CC (country) + LL (location) + optional bbb (branch)
    (r'\b[A-Z]{4}(?:A[DEFGILMNORSTUWXZ]|B[ABDEFGHIJLMNORSTVWYZ]|C[ACDFGHIKLMNORUVXYZ]|D[EJKMOZ]|E[CEGHRST]|F[IJKMOR]|G[ABDEFGHILMNPQRSTUWY]|H[KMNRTU]|I[DELMNOQRST]|J[EMOP]|K[EGHIMNPRWYZ]|L[ABCIKRSTUVY]|M[ACDGHKLMNOPQRSTUVWXYZ]|N[ACEFGILOPRUZ]|OM|P[AEGHKLNRSTWY]|QA|R[EOSUW]|S[ABCDEGHIJKLMNORSTUVXYZ]|T[CDFGHJKLMNOPRTVWZ]|U[AGKMSYZ]|V[ACEGINU]|W[FS]|Y[ET]|Z[AMW])[A-Z2-9][A-NP-Z1-9](?:[A-Z0-9]{3})?\b', 'swift_bic', 0.90),
    # V16.4.7: REMOVED ach_routing -  9-digit number matches too many non-routing values. Extreme FP rate.
]

# ── Category 9: Threat Actor Intelligence ──
ACTOR_PATTERNS = [
    (r'\b(?:lockbit|alphv|blackcat|clop|revil|conti|darkside|ransomhouse|play|akira|black\s*basta|noname057)\b', 'ransomware_group', 0.90),
    (r'\b(?:lazarus|apt\d{1,2}|cozy\s*bear|fancy\s*bear|sandworm|charming\s*kitten|equation\s*group)\b', 'apt_group', 0.90),
    (r'(?:ransom\s*note|ransom\s*demand|your\s*files\s*(?:have\s*been\s*)?encrypted)', 'ransom_note', 0.95),
    (r'(?:auction|for\s*sale|selling).*(?:data|database|records|GB|TB)', 'data_auction', 0.85),
]

# ── Category 10: Session & Auth Tokens ──
SESSION_PATTERNS = [
    (r'(?:session[_-]?id|jsessionid|phpsessid|aspsessionid)[=:][A-Za-z0-9\+/=\-_]{16,}', 'session_cookie', 0.90),
    (r'[A-Za-z0-9+/]{86}==', 'saml_assertion', 0.75),
    # V16.4.7: REMOVED kerberos_ccache -  binary format. Cannot reliably detect in text feeds.
    (r'(?:NTLM|ntlm)\s+[A-Za-z0-9+/=]{20,}', 'ntlm_hash', 0.90),
    (r'\b[a-fA-F0-9]{16,32}:[a-fA-F0-9]{32}\b', 'ntlm_hash_format', 0.92),
]

# ── Category 11: OAuth / SaaS Access Tokens ──
OAUTH_PATTERNS = [
    (r'\bya29\.[0-9A-Za-z\-_]+\b', 'google_oauth_bearer', 0.99),
    # V16.4.7: Slack OAuth patterns REMOVED -  xoxb-/xoxp- already matched by
    # strict patterns in API_KEY_PATTERNS (lines 41-42). The loose 50+ char version
    # here would double-fire on the same token with a different ioc_type label,
    # causing duplicate detections and duplicate liveness checks.
    # slack_bot_oauth -> use slack_bot_token
    # slack_user_oauth -> use slack_user_token
    (r'\bghu_[A-Za-z0-9]{36}\b', 'github_user_token', 0.99),
    (r'\bgh[ps]_[A-Za-z0-9]{36,}\b', 'github_saas_token', 0.95),
    (r'(?:AZURE_CLIENT_SECRET|AZURE_TENANT_SECRET|AZURE_TOKEN)\s*[=:]\s*["\']?[A-Za-z0-9\-_\.~]{20,}["\']?', 'azure_bearer', 0.90),
    # V16.4.7: REMOVED bearer_token_header -  "Authorization: Bearer" in every API tutorial. Extreme noise.
]

# ── Category 12: SaaS Misconfiguration ──
SAAS_MISCONFIG_PATTERNS = [
    (r'\bs3://[\w\-\.]+\b', 's3_bucket_ref', 0.85),
    (r'https?://[\w\-]+\.s3(?:[-\w]*)?\.amazonaws\.com', 's3_public_url', 0.90),
    (r'https?://[\w\-]+\.blob\.core\.windows\.net/[\w\-]+(?!\?)', 'azure_blob_public', 0.88),
    (r'https?://storage\.googleapis\.com/[\w\-]+/', 'gcs_public_bucket', 0.88),
    (r'(?:elasticsearch|kibana|grafana)://[\w\.\-]+:\d+', 'open_analytics_service', 0.85),
    (r'X-Elastic-Product:\s*Elasticsearch', 'elasticsearch_exposed', 0.80),
]

# ── Category 13: Privileged Account Anomaly ──
PRIVACCOUNT_PATTERNS = [
    (r'\b(?:administrator|domain.admin|root|sudo|system)\s*[=:@]\s*[\S]+', 'privileged_credential', 0.88),
    (r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b.*(?:root|admin|billing)', 'aws_root_key', 0.95),
    (r'(?:break.?glass|emergency.?access|privileged.?account).*[=:]\s*[\S]+', 'breakglass_credential', 0.95),
    (r'\bkrbtgt\b', 'golden_ticket_indicator', 0.95),
]

# ── Category 14: Shadow IT Discovery ──
SHADOWIT_PATTERNS = [
    (r'https?://(?:dropbox|drive\.google|onedrive|sharepoint)\.com/s/[A-Za-z0-9\-_]+', 'personal_cloud_share', 0.80),
    (r'(?:ngrok|serveo|localtunnel)\.(?:io|net|dev)/[A-Za-z0-9\-]+', 'dev_tunnel_exposed', 0.90),
    (r'https?://[\w\-]+\.(?:vercel\.app|netlify\.app|herokuapp\.com|ngrok\.io)', 'rogue_dev_endpoint', 0.75),
]

# ── Category 15: Data Exfiltration Evidence ──
# Not DLP. Detects EVIDENCE that exfiltration already happened:
#  - SQL/CSV database dumps in pastes (data already exfiltrated)
#  - Archive commands with sensitive paths (staging for exfil)
#  - File share uploads (data being moved offsite)
#  - Transfer commands to external hosts
DATAEXFIL_PATTERNS = [
    # Transfer/staging commands
    (r'(?:wget|curl|scp|rsync).*(?:https?|ftp)://(?!\b(?:localhost|127\.0\.0\.1)\b)[\w\.\-]+/[\S]+', 'data_transfer_cmd', 0.85),
    (r'tar\s+(?:\-\w+\s+)*[\w\.\-]+\.(?:tar\.gz|tgz|zip)\s+(?:&|\|)', 'archive_and_exfil', 0.80),
    (r'base64\s+(?:\-\w+\s+)?/[\S]+\s*(?:>|>>|&&|\|)', 'base64_exfil', 0.85),
    (r'(?:megaupload|anonfiles|gofile|wetransfer|transfer\.sh)/[\S]+', 'file_share_exfil', 0.88),
    (r'SELECT\s+\*\s+(?:FROM\s+[\w]+\s+){0,2}INTO\s+OUTFILE', 'sql_outfile_exfil', 0.92),
    # SQL database dump signatures (data already out)
    (r'(?:INSERT\s+INTO\s+\w+\s+VALUES\s*\()', 'sql_dump_detected', 0.88),
    (r'(?:--\s*(?:MySQL|MariaDB|PostgreSQL)\s+dump|--\s*Dump(?:ing)?\s+(?:data|database)|pg_dump)', 'sql_dump_header', 0.92),
    (r'(?:CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\w\.]+\s*\()', 'sql_schema_dump', 0.82),
    # CSV/structured data dump signatures (PII columns = exfiltrated records)
    (r'(?:^|\n)[\w\s]*(?:email|username|user_?name)[,\t][\w\s]*(?:password|passwd|pwd|hash)[,\t]', 'csv_credential_dump', 0.90),
    (r'(?:^|\n)[\w\s]*(?:ssn|social.?security|national.?id)[,\t][\w\s]*(?:name|dob|birth)', 'csv_pii_dump', 0.94),
    (r'(?:^|\n)[\w\s]*(?:card.?number|credit.?card|pan)[,\t][\w\s]*(?:cvv|expir|name)', 'csv_financial_dump', 0.94),
    # Archive commands targeting sensitive directories
    (r'(?:7za?\s+a\s+(?:\-p\S*\s+)?|zip\s+(?:\-[re]\s+)?)[\S]*\.(?:7z|zip|rar)\s+[\S]*(?:backup|database|db|export|dump|sql|customer|patient|financial)', 'archive_sensitive_data', 0.88),
]

# ── CVE patterns ──
CVE_PATTERNS = [
    (r'\bCVE-\d{4}-\d{4,7}\b', 'cve_id', 0.99),
]

# ── Crypto ──
CRYPTO_PATTERNS = [
    (r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', 'bitcoin_address', 0.80),
    (r'\b0x[a-fA-F0-9]{40}\b', 'ethereum_address', 0.85),
    (r'\b[A-Za-z0-9]{42,44}\b(?=.*(?:XMR|monero))', 'monero_address', 0.75),
]

ALL_CATEGORIES = [
    # V16.4.5: Ordered specific->generic so NTLM hash isn't eaten by md5,
    # data_transfer_cmd isn't eaten by URL, etc.
    ('stolen_credentials',      CRED_PATTERNS),
    ('api_keys_tokens',         API_KEY_PATTERNS),
    ('oauth_saas_tokens',       OAUTH_PATTERNS),
    ('session_auth_tokens',     SESSION_PATTERNS),
    ('privileged_account',      PRIVACCOUNT_PATTERNS),
    ('data_exfil_anomaly',      DATAEXFIL_PATTERNS),
    ('infra_code_leaks',        INFRA_PATTERNS),
    ('threat_actor_intel',      ACTOR_PATTERNS),
    ('financial_identity',      FINANCIAL_PATTERNS),
    ('saas_misconfiguration',   SAAS_MISCONFIG_PATTERNS),
    ('shadow_it',               SHADOWIT_PATTERNS),
    ('cve',                     CVE_PATTERNS),
    ('crypto',                  CRYPTO_PATTERNS),
    # Generic patterns LAST - so they don't steal specific matches
    ('network_iocs',            NETWORK_PATTERNS),
    ('domain_url_iocs',         DOMAIN_PATTERNS),
    ('email_iocs',              EMAIL_PATTERNS),
    ('file_hash_iocs',          HASH_PATTERNS),
]

# Compiled patterns cache
_COMPILED = None

def _get_compiled():
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = []
        for category, patterns in ALL_CATEGORIES:
            compiled = []
            for pat, ioc_type, confidence in patterns:
                try:
                    compiled.append((re.compile(pat, re.IGNORECASE), ioc_type, confidence))
                except re.error:
                    pass
            _COMPILED.append((category, compiled))
    return _COMPILED

# Private IPs to skip for network IOC noise reduction
_PRIVATE = re.compile(r'^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.)')

def scan_text(text: str, customer_domain: str = "") -> list[IOCMatch]:
    """Scan text for all IOC categories. Returns deduplicated list of matches."""
    if not text:
        return []
    matches = []
    seen = set()
    lines = text.splitlines()

    for line_num, line in enumerate(lines, 1):
        context = line.strip()[:200]
        for category, compiled_patterns in _get_compiled():
            for regex, ioc_type, base_confidence in compiled_patterns:
                for m in regex.finditer(line):
                    val = m.group(0).strip()
                    if not val or len(val) < 4:
                        continue
                    # Skip private IPs for network IOC
                    if ioc_type == 'ipv4' and _PRIVATE.match(val):
                        continue
                    # Skip localhost
                    if val in ('127.0.0.1', 'localhost', '0.0.0.0'):
                        continue
                    key = (category, ioc_type, val)
                    if key in seen:
                        continue
                    seen.add(key)
                    # Boost confidence if customer domain appears nearby
                    conf = base_confidence
                    if customer_domain and customer_domain.lower() in line.lower():
                        conf = min(conf + 0.1, 1.0)
                    matches.append(IOCMatch(
                        category=category,
                        ioc_type=ioc_type,
                        value=val,
                        context=context,
                        confidence=conf,
                        line_number=line_num,
                    ))
    # Sort: highest confidence first
    matches.sort(key=lambda x: -x.confidence)
    return matches
