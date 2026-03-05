"""
Shared Utilities for ArgusWatch v15
=====================================
A) Collector output schema validation
B) eTLD+1 domain normalization (no external dependency)
C) Product alias resolution from product_aliases table
D) Feed confidence scoring
E) Time decay function
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Optional
import math

logger = logging.getLogger("arguswatch.utils")


# ═══════════════════════════════════════════════════════════════════
# A) COLLECTOR OUTPUT SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════

REQUIRED_COLLECTOR_KEYS = {"new", "skipped"}  # At minimum one of these

def validate_collector_output(result: dict, collector_name: str) -> dict:
    """Validate collector output has canonical keys. Fix or log if malformed.
    
    Canonical schema:
    {"new": int, "skipped": int, "total": int}
    or
    {"skipped": True, "reason": str, "new": 0}
    or
    {"error": str, "new": 0}
    """
    if not isinstance(result, dict):
        logger.error(f"Collector {collector_name}: output is not dict ({type(result)})")
        return {"error": f"Invalid output type: {type(result)}", "new": 0, "collector": collector_name}
    
    # Ensure "new" key always exists
    if "new" not in result:
        result["new"] = 0
    
    # Validate types
    if not isinstance(result.get("new"), (int, float)):
        result["new"] = 0
    
    result["collector"] = collector_name
    return result


# ═══════════════════════════════════════════════════════════════════
# B) eTLD+1 DOMAIN NORMALIZATION
# ═══════════════════════════════════════════════════════════════════

# Built-in eTLD list for the most common TLDs
# In production, use publicsuffix2 or tldextract library
MULTI_PART_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw", "com.hk",
    "com.ar", "com.co", "com.eg", "com.pk", "com.ph", "com.tr", "com.ua",
    "org.uk", "org.au", "org.br", "org.cn",
    "net.au", "net.br", "net.cn",
    "ac.uk", "ac.jp", "ac.kr",
    "edu.au", "edu.cn",
    "gov.uk", "gov.au", "gov.br", "gov.cn", "gov.in",
    "ne.jp", "or.jp", "or.kr",
    "me.uk", "ltd.uk",
}

def normalize_domain_etld1(hostname: str) -> str:
    """Extract eTLD+1 (registrable domain) from a hostname.
    
    Examples:
      "mail.hackthebox.com" → "hackthebox.com"
      "api.staging.example.co.uk" → "example.co.uk"
      "hackthebox.com" → "hackthebox.com"
      "10.0.0.1" → "10.0.0.1" (IPs pass through)
    """
    if not hostname:
        return ""
    
    h = hostname.lower().strip()
    
    # Strip protocol, path, port
    if "://" in h:
        h = h.split("://", 1)[1]
    if "/" in h:
        h = h.split("/", 1)[0]
    if ":" in h:
        h = h.split(":", 1)[0]
    if "@" in h:
        h = h.split("@", 1)[1]
    
    # If it's an IP address, return as-is
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', h):
        return h
    
    parts = h.split(".")
    if len(parts) <= 1:
        return h
    
    # Check for multi-part TLDs
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in MULTI_PART_TLDS:
            # eTLD+1 = parts[-3].parts[-2].parts[-1]
            return ".".join(parts[-3:]) if len(parts) >= 3 else h
    
    # Standard: eTLD+1 = last 2 parts
    return ".".join(parts[-2:])


def extract_domain_from_url(url: str) -> str:
    """Extract hostname from URL, then normalize to eTLD+1."""
    if not url:
        return ""
    u = url.lower().strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    if "/" in u:
        u = u.split("/", 1)[0]
    if ":" in u:
        u = u.split(":", 1)[0]
    if "@" in u:
        u = u.split("@", 1)[1]
    return normalize_domain_etld1(u)


# ═══════════════════════════════════════════════════════════════════
# C) PRODUCT ALIAS RESOLUTION
# ═══════════════════════════════════════════════════════════════════

# In-memory alias cache (populated from DB or hardcoded fallback)
_ALIAS_CACHE: dict[str, str] = {}

def _init_alias_cache():
    """Initialize from hardcoded aliases. DB-backed version loads from product_aliases table."""
    global _ALIAS_CACHE
    if _ALIAS_CACHE:
        return
    aliases = {
        "nginx": "nginx", "nginx-plus": "nginx", "openresty": "nginx",
        "apache": "apache_http_server", "httpd": "apache_http_server",
        "apache2": "apache_http_server", "apache http server": "apache_http_server",
        "exchange": "microsoft_exchange", "exchange server": "microsoft_exchange",
        "microsoft exchange": "microsoft_exchange", "owa": "microsoft_exchange",
        "outlook web access": "microsoft_exchange",
        "fortios": "fortios", "fortigate": "fortios", "fortinet": "fortios",
        "confluence": "confluence", "atlassian confluence": "confluence",
        "ivanti": "ivanti_connect_secure", "ivanti connect secure": "ivanti_connect_secure",
        "pulse secure": "ivanti_connect_secure", "pulse connect secure": "ivanti_connect_secure",
        "citrix": "citrix_netscaler", "netscaler": "citrix_netscaler", "citrix adc": "citrix_netscaler",
        "esxi": "vmware_esxi", "vmware esxi": "vmware_esxi",
        "vcenter": "vmware_vcenter", "vmware vcenter": "vmware_vcenter",
        "sharepoint": "sharepoint", "microsoft sharepoint": "sharepoint",
        "openssh": "openssh", "ssh": "openssh",
        "wordpress": "wordpress", "wp": "wordpress",
        "php": "php",
        "moveit": "moveit_transfer", "moveit transfer": "moveit_transfer",
        "panos": "paloalto_panos", "pan-os": "paloalto_panos", "palo alto": "paloalto_panos",
        "solarwinds": "solarwinds_orion", "orion": "solarwinds_orion",
        "jira": "jira", "atlassian jira": "jira",
        "gitlab": "gitlab", "jenkins": "jenkins",
        "tomcat": "apache_tomcat", "apache tomcat": "apache_tomcat",
        "iis": "microsoft_iis", "microsoft-iis": "microsoft_iis",
    }
    _ALIAS_CACHE = aliases


def resolve_product_canonical(product_name: str) -> str:
    """Resolve a product name to its canonical form via alias lookup.
    
    'FortiOS 7.2' → extract 'fortios' → lookup → 'fortios'
    'Microsoft Exchange Server' → extract 'microsoft exchange server' → lookup → 'microsoft_exchange'
    'nginx/1.18.0' → extract 'nginx' → lookup → 'nginx'
    """
    _init_alias_cache()
    
    # Extract product name (strip version)
    p = product_name.lower().strip()
    p = re.split(r"[/:\s]+\d", p)[0].strip()
    
    # Try exact lookup first
    if p in _ALIAS_CACHE:
        return _ALIAS_CACHE[p]
    
    # Try without punctuation
    p_clean = p.replace("-", "").replace("_", "").replace(" ", "")
    for alias, canonical in _ALIAS_CACHE.items():
        a_clean = alias.replace("-", "").replace("_", "").replace(" ", "")
        if p_clean == a_clean:
            return canonical
    
    # Try progressively shorter prefixes ("Microsoft Exchange Server" → "Microsoft Exchange")
    words = p.split()
    for i in range(len(words), 0, -1):
        prefix = " ".join(words[:i])
        if prefix in _ALIAS_CACHE:
            return _ALIAS_CACHE[prefix]
    
    # Try if any alias is a substring of the input ("exchange" in "microsoft exchange server")
    for alias, canonical in _ALIAS_CACHE.items():
        if len(alias) >= 4 and alias in p:
            return canonical
    
    # No alias found - return normalized version
    return p_clean


def products_match_canonical(customer_product: str, cpe_product: str) -> bool:
    """Match products using canonical alias resolution.
    
    'FortiOS 7.2' vs 'fortigate' → both resolve to 'fortios' → MATCH
    'nginx/1.18.0' vs 'Nginx' → both resolve to 'nginx' → MATCH
    'Exchange' vs 'outlook web access' → both → 'microsoft_exchange' → MATCH
    """
    cp = resolve_product_canonical(customer_product)
    pp = resolve_product_canonical(cpe_product)
    if len(cp) < 3 or len(pp) < 3:
        return False
    return cp == pp or cp in pp or pp in cp


# ═══════════════════════════════════════════════════════════════════
# D) FEED CONFIDENCE SCORING
# ═══════════════════════════════════════════════════════════════════

FEED_CONFIDENCE = {
    "cisa_kev": 0.99,      # US government - highest trust
    "nvd": 0.95,            # NIST - very high trust
    "mitre": 0.95,          # MITRE - very high trust
    "feodo": 0.90,          # abuse.ch - well-curated
    "threatfox": 0.85,      # abuse.ch - community-contributed
    "malwarebazaar": 0.85,  # abuse.ch - verified samples
    "openphish": 0.80,      # Curated phishing feed
    "phishtank": 0.85,      # Community-verified phishing
    "urlhaus": 0.85,        # abuse.ch - verified malicious URLs
    "ransomfeed": 0.80,     # Ransomware victim tracking
    "hudsonrock": 0.80,     # Stealer log data
    "spycloud": 0.95,       # Enterprise credential intelligence
    "circl_misp": 0.75,     # CERT feed - good quality
    "otx": 0.65,            # Community-contributed - mixed quality
    "urlscan": 0.70,        # Automated scans - some false positives
    "vxunderground": 0.60,  # Research-focused - not always IOC-grade
    "darksearch": 0.50,     # Dark web search - noisy
    "paste": 0.40,          # Paste sites - very noisy
    "rss": 0.50,            # News feeds - informational
    "grep_app": 0.55,       # GitHub search - needs triage
    "github": 0.55,         # GitHub API - needs triage
    "shodan": 0.75,         # Network scan data - accurate
    "breach": 0.75,         # Breach databases
    "breachdirectory": 0.70,
    "socradar": 0.70,       # Brand monitoring
    "crowdstrike": 0.95,    # Enterprise threat intel
}

def get_feed_confidence(source: str) -> float:
    """Get feed confidence score for a source. Default 0.5 for unknown."""
    return FEED_CONFIDENCE.get(source, 0.5)


# ═══════════════════════════════════════════════════════════════════
# E) TIME DECAY FUNCTION
# ═══════════════════════════════════════════════════════════════════

def time_decay(age_days: float, half_life_days: float = 14.0) -> float:
    """Exponential decay: 1.0 at day 0, 0.5 at half_life_days, approaches 0.
    
    λ = ln(2) / half_life_days
    decay = exp(-λ * age_days)
    
    Default half-life of 14 days:
      Day 0:  1.000
      Day 7:  0.707
      Day 14: 0.500
      Day 28: 0.250
      Day 60: 0.050
    """
    if age_days <= 0:
        return 1.0
    lam = math.log(2) / half_life_days
    return math.exp(-lam * age_days)


def calculate_decayed_score(raw_score: float, feed_confidence: float,
                             created_at: datetime, half_life: float = 14.0) -> float:
    """Combined score with feed confidence and time decay.
    
    normalized_score = raw_score × feed_confidence × decay(age)
    """
    age_days = (datetime.utcnow() - created_at).total_seconds() / 86400
    decay = time_decay(age_days, half_life)
    return raw_score * feed_confidence * decay


# ═══════════════════════════════════════════════════════════════════
# F) JWT / SAML / Bearer Token Body Decoder
# ═══════════════════════════════════════════════════════════════════
# Extracts customer-identifiable info (iss, sub, tid, email, domain)
# from token payloads that pattern_matcher captures but discards.
#
# JWT:  header.PAYLOAD.signature (base64url)
# SAML: base64-encoded XML with Issuer, NameID
# Azure bearer: JWT with 'tid' (tenant ID) and 'upn' (user principal name)

import base64
import json


def decode_jwt_payload(token: str) -> dict:
    """Decode the payload segment of a JWT token.
    
    Returns dict with extracted fields:
      iss: issuer domain (e.g., accounts.google.com, login.microsoftonline.com)
      sub: subject (often a user ID)
      email: user email if present
      tid: Azure tenant ID if present
      upn: Azure user principal name if present
      aud: audience (which service this token is for)
      domains: list of extractable domains from the payload
    """
    result = {"raw_claims": {}, "domains": [], "emails": []}
    
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return result
        
        # Base64url decode the payload (middle segment)
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        
        # Replace URL-safe chars
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        
        payload_bytes = base64.b64decode(payload_b64)
        claims = json.loads(payload_bytes)
        result["raw_claims"] = claims
        
        # Extract domains from known fields
        for field in ("iss", "aud", "azp"):
            val = claims.get(field, "")
            if isinstance(val, str):
                # Extract domain from URL: https://accounts.google.com → accounts.google.com
                domain_match = re.search(r'https?://([^/\s]+)', val)
                if domain_match:
                    result["domains"].append(domain_match.group(1).lower())
                elif "." in val and " " not in val and len(val) < 100:
                    result["domains"].append(val.lower())
        
        # Extract email/upn
        for field in ("email", "upn", "preferred_username", "unique_name", "sub"):
            val = claims.get(field, "")
            if isinstance(val, str) and "@" in val and "." in val:
                result["emails"].append(val.lower())
                # Extract domain from email
                domain = val.split("@")[1].lower()
                if domain not in result["domains"]:
                    result["domains"].append(domain)
        
        # Azure-specific: tenant ID
        if "tid" in claims:
            result["tid"] = claims["tid"]
        
        # Azure-specific: app display name
        if "app_displayname" in claims:
            result["app_name"] = claims["app_displayname"]
        
    except Exception:
        pass  # Malformed token - silently fail
    
    return result


def decode_saml_assertion(assertion_b64: str) -> dict:
    """Decode a base64-encoded SAML assertion to extract issuer and subject.
    
    Returns dict with:
      issuer: SAML issuer (identity provider domain)
      subject: NameID (usually email)
      domains: extractable domains
    """
    result = {"domains": [], "emails": []}
    
    try:
        # Add padding
        padding = 4 - len(assertion_b64) % 4
        if padding != 4:
            assertion_b64 += "=" * padding
        
        xml_bytes = base64.b64decode(assertion_b64)
        xml_text = xml_bytes.decode("utf-8", errors="ignore")
        
        # Extract Issuer
        issuer_match = re.search(r'<(?:saml[2p]*:)?Issuer[^>]*>([^<]+)</(?:saml[2p]*:)?Issuer>', xml_text)
        if issuer_match:
            issuer = issuer_match.group(1).strip()
            result["issuer"] = issuer
            domain_match = re.search(r'https?://([^/\s]+)', issuer)
            if domain_match:
                result["domains"].append(domain_match.group(1).lower())
        
        # Extract NameID (usually email)
        nameid_match = re.search(r'<(?:saml[2p]*:)?NameID[^>]*>([^<]+)</(?:saml[2p]*:)?NameID>', xml_text)
        if nameid_match:
            nameid = nameid_match.group(1).strip()
            if "@" in nameid:
                result["emails"].append(nameid.lower())
                domain = nameid.split("@")[1].lower()
                if domain not in result["domains"]:
                    result["domains"].append(domain)
        
    except Exception:
        pass
    
    return result


def extract_domains_from_token(ioc_type: str, ioc_value: str) -> list[str]:
    """Given an IOC type and value, try to extract customer-identifiable domains.
    
    Works for: jwt_token, jwt_token_alt, saml_assertion, azure_bearer,
    azure_sas_token, kerberos_ccache
    
    Returns list of domains that can be matched against customer assets.
    """
    domains = []
    
    if ioc_type in ("jwt_token", "jwt_token_alt", "azure_bearer", "bearer_token_header"):
        # Strip "Bearer " prefix if present
        token = ioc_value
        if token.lower().startswith("bearer "):
            token = token[7:]
        if token.lower().startswith("authorization: bearer "):
            token = token[22:]
        
        decoded = decode_jwt_payload(token.strip())
        domains.extend(decoded.get("domains", []))
        # Also extract domains from emails
        for email in decoded.get("emails", []):
            if "@" in email:
                d = email.split("@")[1]
                if d not in domains:
                    domains.append(d)
    
    elif ioc_type == "saml_assertion":
        decoded = decode_saml_assertion(ioc_value)
        domains.extend(decoded.get("domains", []))
        for email in decoded.get("emails", []):
            if "@" in email:
                d = email.split("@")[1]
                if d not in domains:
                    domains.append(d)
    
    elif ioc_type == "azure_sas_token":
        # Azure SAS tokens contain the storage account name in the URL
        # https://acmestorage.blob.core.windows.net/container?sig=...
        account_match = re.search(r'(\w+)\.blob\.core\.windows\.net', ioc_value)
        if account_match:
            domains.append(f"{account_match.group(1)}.blob.core.windows.net")
    
    elif ioc_type == "kerberos_ccache":
        # Kerberos ccache filenames sometimes contain realm: krb5cc_1000@ACME.COM
        realm_match = re.search(r'@([A-Z][A-Z0-9\.\-]+)', ioc_value)
        if realm_match:
            domains.append(realm_match.group(1).lower())
    
    return domains
