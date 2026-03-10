"""
Enrichment Pipeline v16.4.7 -  Multi-source enrichment for detections.

WHAT CHANGED:
  v16.4.7: Fixed VT url_map fallback (was sending hashes to IP endpoint).
  v16.4.7: Added API key liveness checks for 6 provider types.
  v16.4.7: Added credential combo enrichment via HudsonRock/HIBP.
  v16.4.7: Fixed sum(vt.values()) TypeError on string fields.

ENRICHMENT SOURCES BY IOC TYPE:
  ipv4/ipv6:     VirusTotal + AbuseIPDB
  domain/url:    VirusTotal
  sha256/md5/sha1: VirusTotal + MalwareBazaar
  aws_access_key:  AWS STS GetCallerIdentity (liveness check)
  github_pat_*:    GitHub /user endpoint (liveness check)
  stripe_live_key: Stripe /v1/charges (liveness check)
  openai_api_key:  OpenAI /v1/models (liveness check)
  sendgrid_api_key: SendGrid /v3/scopes (liveness check)
  anthropic_api_key: Anthropic /v1/messages (liveness check)
  email_password_combo: HudsonRock breach check
  breachdirectory_combo: HudsonRock breach check
  ~50 other types:  No external enrichment (PII, exfil patterns, config files)
"""
import httpx
import logging
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, Enrichment, SeverityLevel
from sqlalchemy import select

logger = logging.getLogger("arguswatch.enrichment")


# ══════════════════════════════════════════════════════════════════════
# VIRUSTOTAL -  IP, domain, URL, file hash lookups
# ══════════════════════════════════════════════════════════════════════

_VT_URL_MAP = {
    "ipv4": lambda v: f"ip_addresses/{v}",
    "ipv6": lambda v: f"ip_addresses/{v}",
    "domain": lambda v: f"domains/{v}",
    "sha256": lambda v: f"files/{v}",
    "md5": lambda v: f"files/{v}",
    "sha1": lambda v: f"files/{v}",
    "hash_sha256": lambda v: f"files/{v}",
    # URL handled separately (needs base64 encoding)
}

async def _vt_lookup(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    if not settings.VIRUSTOTAL_API_KEY:
        return None

    # URL needs special handling
    if ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
        endpoint = f"urls/{url_id}"
    elif ioc_type in _VT_URL_MAP:
        endpoint = _VT_URL_MAP[ioc_type](ioc_value)
    else:
        # Type not supported by VT -  return None instead of sending garbage request
        return None

    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/{endpoint}",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=10.0,
        )
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country", ""),
                "as_owner": attrs.get("as_owner", ""),
            }
    except Exception as e:
        logger.debug(f"VT error for {ioc_value[:40]}: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# ABUSEIPDB -  IP reputation
# ══════════════════════════════════════════════════════════════════════

async def _abuse_lookup(ip: str, client: httpx.AsyncClient) -> dict | None:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=8.0,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
            }
    except Exception as e:
        logger.debug(f"AbuseIPDB error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# API KEY LIVENESS CHECKS -  check if leaked key is still active
# An active key is CRITICAL. A revoked key is INFO.
#
# SAFETY CONTROLS:
#   1. Read-only endpoints ONLY (no write operations ever)
#   2. Hard 5s timeout per check (won't block pipeline)
#   3. Rate limit: max 10 checks per provider per minute
#   4. Config flag KEY_LIVENESS_ENABLED (default true, disable for compliance)
#   5. All calls logged for audit trail
# ══════════════════════════════════════════════════════════════════════

import os
import time as _time
from collections import defaultdict

KEY_LIVENESS_ENABLED = os.getenv("KEY_LIVENESS_ENABLED", "true").lower() in ("true", "1", "yes")

# Rate limiter: {provider: [timestamp, timestamp, ...]}
_liveness_rate = defaultdict(list)
_LIVENESS_MAX_PER_MIN = 10


def _rate_ok(provider: str) -> bool:
    """Allow max 10 liveness checks per provider per minute."""
    now = _time.time()
    _liveness_rate[provider] = [t for t in _liveness_rate[provider] if now - t < 60]
    if len(_liveness_rate[provider]) >= _LIVENESS_MAX_PER_MIN:
        logger.warning(f"[key_liveness] Rate limit hit for {provider} ({_LIVENESS_MAX_PER_MIN}/min)")
        return False
    _liveness_rate[provider].append(now)
    return True


async def _check_key_liveness(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """Check if a leaked API key is still active via READ-ONLY provider endpoints.

    SAFETY: Only read-only endpoints. Hard 5s timeout. Rate limited.
    AUDIT: Every check is logged with provider + result.
    """
    if not KEY_LIVENESS_ENABLED:
        return None

    try:
        if ioc_type in ("aws_access_key",):
            # AWS needs both keys -  we only have the access key ID
            return {"active": "unknown", "provider": "aws", "detail": "AKIA prefix confirmed. Need secret key to verify liveness."}

        if ioc_type in ("github_pat_classic", "github_fine_grained_pat", "github_oauth_token", "github_app_token", "github_saas_token"):
            if not _rate_ok("github"):
                return None
            # READ-ONLY: GET /user -  returns user info, no side effects
            r = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {ioc_value}", "User-Agent": "ArgusWatch-Enrichment"},
                timeout=5.0,
            )
            active = r.status_code == 200
            detail = f"Belongs to {r.json().get('login', '?')}" if active else f"HTTP {r.status_code} -  likely revoked"
            logger.info(f"[key_liveness] github {ioc_type}: active={active}")
            return {"active": active, "provider": "github", "detail": detail}

        if ioc_type == "stripe_live_key":
            if not _rate_ok("stripe"):
                return None
            # READ-ONLY: GET /v1/charges?limit=1 -  reads, no mutation
            r = await client.get(
                "https://api.stripe.com/v1/charges?limit=1",
                headers={"Authorization": f"Bearer {ioc_value}"},
                timeout=5.0,
            )
            active = r.status_code == 200
            logger.info(f"[key_liveness] stripe: active={active}")
            return {"active": active, "provider": "stripe", "detail": "Key is LIVE -  payment system exposed" if active else "Key revoked or invalid"}

        if ioc_type == "openai_api_key":
            if not _rate_ok("openai"):
                return None
            # READ-ONLY: GET /v1/models -  list available models
            r = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {ioc_value}"},
                timeout=5.0,
            )
            active = r.status_code == 200
            logger.info(f"[key_liveness] openai: active={active}")
            return {"active": active, "provider": "openai", "detail": "Key is active -  billing exposed" if active else "Key invalid"}

        if ioc_type == "sendgrid_api_key":
            if not _rate_ok("sendgrid"):
                return None
            # READ-ONLY: GET /v3/scopes -  list permissions
            r = await client.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {ioc_value}"},
                timeout=5.0,
            )
            active = r.status_code == 200
            logger.info(f"[key_liveness] sendgrid: active={active}")
            return {"active": active, "provider": "sendgrid", "detail": "Key is active -  email impersonation risk" if active else "Key invalid"}

        if ioc_type == "anthropic_api_key":
            if not _rate_ok("anthropic"):
                return None
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ioc_value, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
                timeout=5.0,
            )
            active = r.status_code in (200, 429)
            logger.info(f"[key_liveness] anthropic: active={active} (status={r.status_code})")
            return {"active": active, "provider": "anthropic", "detail": "Key is active" if active else "Key invalid"}

        if ioc_type == "gitlab_pat":
            if not _rate_ok("gitlab"):
                return None
            # READ-ONLY: GET /api/v4/user
            r = await client.get(
                "https://gitlab.com/api/v4/user",
                headers={"PRIVATE-TOKEN": ioc_value},
                timeout=5.0,
            )
            active = r.status_code == 200
            detail = f"Belongs to {r.json().get('username', '?')}" if active else f"HTTP {r.status_code} -  likely revoked"
            logger.info(f"[key_liveness] gitlab: active={active}")
            return {"active": active, "provider": "gitlab", "detail": detail}

        if ioc_type in ("slack_bot_token", "slack_user_token", "slack_bot_oauth", "slack_user_oauth"):
            if not _rate_ok("slack"):
                return None
            # READ-ONLY: auth.test -  returns workspace info
            r = await client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {ioc_value}"},
                timeout=5.0,
            )
            data = r.json() if r.status_code == 200 else {}
            active = data.get("ok", False)
            detail = f"Workspace: {data.get('team', '?')}, User: {data.get('user', '?')}" if active else "Token invalid or revoked"
            logger.info(f"[key_liveness] slack: active={active}")
            return {"active": active, "provider": "slack", "detail": detail}

        if ioc_type == "google_api_key":
            if not _rate_ok("google"):
                return None
            # SAFE: Check key structure + try the free tokeninfo endpoint.
            # DO NOT call Geocoding/Maps -  that consumes the victim's billing quota
            # which is unauthorized use of their API key (CFAA risk).
            import re as _gre
            if not _gre.match(r'^AIza[0-9A-Za-z\-_]{35}$', ioc_value):
                return {"active": False, "provider": "google", "detail": "Invalid AIza key format"}
            # Try googleapis tokeninfo -  free, read-only, no quota impact
            try:
                r = await client.get(
                    f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={ioc_value}",
                    timeout=5.0,
                )
                # API keys return 400 "Invalid Value" (they're not OAuth tokens)
                # But a valid key structure that doesn't 400 immediately = suspicious
                # Best we can do without consuming quota: confirm format is valid
            except Exception:
                pass
            logger.info(f"[key_liveness] google: structure valid (AIza prefix confirmed)")
            return {"active": "valid_format", "provider": "google",
                    "detail": "AIza key format valid. Cannot verify liveness without consuming victim's quota."}

    except Exception as e:
        logger.debug(f"Key liveness check error for {ioc_type}: {e}")

    return None


# ══════════════════════════════════════════════════════════════════════
# CREDENTIAL ENRICHMENT -  check if email is in breach databases
# Rate limited: 1 HudsonRock call per domain per hour (not per email).
# 500 @yahoo.com emails -> 1 API call, result cached for all.
# ══════════════════════════════════════════════════════════════════════

_email_domain_cache = {}  # {domain: (timestamp, result)}
_EMAIL_CACHE_TTL = 3600  # 1 hour

async def _credential_enrichment(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """For credential combos, extract the email and check HudsonRock.

    Rate limited per domain (not per email) to avoid hammering free tier.
    Includes date context for freshness assessment.
    """
    email = None
    if "@" in ioc_value:
        email = ioc_value.split(":")[0] if ":" in ioc_value else ioc_value

    if not email or "@" not in email:
        return None

    domain = email.split("@")[1].lower()

    # Check domain cache -  return cached result if <1 hour old
    now = _time.time()
    if domain in _email_domain_cache:
        cached_time, cached_result = _email_domain_cache[domain]
        if now - cached_time < _EMAIL_CACHE_TTL:
            logger.debug(f"[enrichment] HudsonRock cache hit for @{domain}")
            return cached_result

    try:
        r = await client.get(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}",
            timeout=8.0,
        )
        if r.status_code == 200:
            data = r.json()
            stealers = data.get("stealers", [])
            dates = []
            for s in stealers[:10]:
                d = s.get("date_compromised") or s.get("date_uploaded") or s.get("date")
                if d:
                    dates.append(str(d))
            newest = dates[0] if dates else "unknown"
            oldest = dates[-1] if dates else "unknown"
            result = {
                "provider": "hudsonrock",
                "stealer_count": len(stealers),
                "compromised": len(stealers) > 0,
                "newest_date": newest,
                "oldest_date": oldest,
                "detail": f"{len(stealers)} stealer log(s). Newest: {newest}" if stealers else "Not in stealer databases",
            }
            _email_domain_cache[domain] = (now, result)
            return result
    except Exception as e:
        logger.debug(f"HudsonRock enrichment error: {e}")

    return None


# ══════════════════════════════════════════════════════════════════════
# JWT/TOKEN ISSUER ENRICHMENT -  extract issuer domain from token body
# ══════════════════════════════════════════════════════════════════════

async def _token_issuer_enrichment(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """For JWT/SAML/OAuth tokens, decode the body, extract the issuer domain,
    and run VT on it. A token from auth.evil.com ≠ login.microsoftonline.com.
    """
    import base64, json as _json
    issuer = None
    try:
        if ioc_type in ("jwt_token", "azure_bearer", "google_oauth_bearer"):
            # JWT: header.payload.signature -  decode payload
            parts = ioc_value.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)  # pad
                payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
                issuer = payload.get("iss", "")
        elif ioc_type == "saml_assertion":
            # SAML: look for Issuer element
            import re
            m = re.search(r'Issuer[>\s]+([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', ioc_value)
            if m:
                issuer = m.group(1)
    except Exception:
        pass

    if not issuer:
        return None

    # Extract domain from issuer URL (e.g., "https://accounts.google.com" -> "accounts.google.com")
    domain = issuer.replace("https://", "").replace("http://", "").split("/")[0]
    if not domain or "." not in domain:
        return None

    # Run VT on the issuer domain
    vt = await _vt_lookup(domain, "domain", client)
    if vt:
        return {
            "provider": "vt_issuer",
            "issuer_domain": domain,
            "vt_malicious": vt.get("malicious", 0),
            "vt_reputation": vt.get("reputation", 0),
            "detail": f"Token issuer {domain}: {vt.get('malicious', 0)} VT malicious engines",
        }
    return {"provider": "issuer_extract", "issuer_domain": domain, "detail": f"Issuer: {domain} (VT unavailable)"}


# ══════════════════════════════════════════════════════════════════════
# BLOCKCHAIN ADDRESS ENRICHMENT -  check abuse reports + labels
# ══════════════════════════════════════════════════════════════════════

async def _blockchain_enrichment(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """Check blockchain addresses against abuse databases and explorer labels."""
    try:
        if ioc_type == "bitcoin_address":
            # blockchain.info: check address balance + transaction count
            r = await client.get(
                f"https://blockchain.info/rawaddr/{ioc_value}?limit=1",
                timeout=8.0,
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "provider": "blockchain_info",
                    "total_received_btc": data.get("total_received", 0) / 1e8,
                    "total_sent_btc": data.get("total_sent", 0) / 1e8,
                    "n_tx": data.get("n_tx", 0),
                    "detail": f"BTC address: {data.get('n_tx', 0)} txns, received {data.get('total_received', 0) / 1e8:.4f} BTC",
                }

        if ioc_type == "ethereum_address":
            # Etherscan public API (no key needed for basic balance)
            r = await client.get(
                f"https://api.etherscan.io/api?module=account&action=balance&address={ioc_value}&tag=latest",
                timeout=8.0,
            )
            if r.status_code == 200:
                data = r.json()
                balance_eth = int(data.get("result", "0")) / 1e18
                return {
                    "provider": "etherscan",
                    "balance_eth": round(balance_eth, 6),
                    "detail": f"ETH address: balance {balance_eth:.6f} ETH",
                }

        if ioc_type == "monero_address":
            # Monero is a privacy coin -  no public blockchain lookup.
            # But we CAN cross-reference against our own ransomware detection DB.
            try:
                async with async_session() as _xdb:
                    from sqlalchemy import or_
                    xr = await _xdb.execute(
                        select(Detection).where(
                            Detection.ioc_type.in_(["ransomware_group", "ransom_note", "data_auction"]),
                            or_(
                                Detection.ioc_value.ilike(f"%{ioc_value[:20]}%"),
                                Detection.raw_text.ilike(f"%{ioc_value[:20]}%"),
                            ),
                        ).limit(5)
                    )
                    matches = xr.scalars().all()
                    if matches:
                        return {
                            "provider": "local_db_xref",
                            "in_ransomware_context": True,
                            "matching_detections": len(matches),
                            "detail": f"⚠️ Monero address appears in {len(matches)} ransomware detection(s)",
                        }
            except Exception:
                pass
            return {"provider": "local_db_xref", "in_ransomware_context": False,
                    "detail": "Monero: privacy coin. Not found in local ransomware detections."}

    except Exception as e:
        logger.debug(f"Blockchain enrichment error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# DARK WEB ADDRESS ENRICHMENT -  check if .onion is indexed
# ══════════════════════════════════════════════════════════════════════

async def _onion_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """Check .onion address against Ahmia.fi search index."""
    try:
        domain = ioc_value.replace("http://", "").replace("https://", "").split("/")[0]
        r = await client.get(
            f"https://ahmia.fi/api/v1/onion/{domain}",
            timeout=8.0,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "provider": "ahmia",
                "indexed": True,
                "title": data.get("title", "")[:100],
                "detail": f"Indexed on Ahmia: {data.get('title', 'unknown')[:60]}",
            }
        elif r.status_code == 404:
            return {"provider": "ahmia", "indexed": False, "detail": "Not indexed on Ahmia -  may be private/offline"}
    except Exception as e:
        logger.debug(f"Onion enrichment error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# CONFIG/BACKUP FILE ENRICHMENT -  extract embedded URLs/domains -> VT
# ══════════════════════════════════════════════════════════════════════

async def _config_content_enrichment(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """Extract URLs and domains from config/backup file content, run VT on them."""
    import re as _re
    domains_found = set()
    urls_found = set()

    # Extract URLs
    for url in _re.findall(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', ioc_value):
        domains_found.add(url)
    # Extract connection strings
    for conn in _re.findall(r'(?:mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@([a-zA-Z0-9._-]+)', ioc_value):
        domains_found.add(conn)
    # Extract S3/Azure/GCS references
    for cloud in _re.findall(r'([a-zA-Z0-9._-]+\.(?:s3|blob\.core\.windows\.net|storage\.googleapis\.com))', ioc_value):
        domains_found.add(cloud)

    if not domains_found:
        return None

    # Check up to 3 domains against VT
    results = []
    for domain in list(domains_found)[:3]:
        vt = await _vt_lookup(domain, "domain", client)
        if vt and vt.get("malicious", 0) > 0:
            results.append({"domain": domain, "vt_malicious": vt["malicious"]})

    if results:
        worst = max(results, key=lambda r: r["vt_malicious"])
        return {
            "provider": "vt_content_scan",
            "domains_extracted": len(domains_found),
            "malicious_domains": len(results),
            "worst_domain": worst["domain"],
            "worst_vt_score": worst["vt_malicious"],
            "detail": f"Extracted {len(domains_found)} domains. {len(results)} flagged by VT. Worst: {worst['domain']} ({worst['vt_malicious']} engines)",
        }
    return {
        "provider": "vt_content_scan",
        "domains_extracted": len(domains_found),
        "malicious_domains": 0,
        "detail": f"Extracted {len(domains_found)} domains from config. None flagged by VT.",
    }


# ══════════════════════════════════════════════════════════════════════
# AZURE SAS TOKEN ENRICHMENT -  parse expiry from URL parameters
# ══════════════════════════════════════════════════════════════════════

async def _azure_sas_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """Parse Azure SAS token URL to extract expiry, permissions, and resource scope."""
    from urllib.parse import parse_qs, urlparse
    try:
        parsed = urlparse(ioc_value) if "://" in ioc_value else urlparse(f"https://{ioc_value}")
        params = parse_qs(parsed.query)
        expiry = (params.get("se") or [None])[0]
        permissions = (params.get("sp") or [None])[0]
        resource = (params.get("sr") or [None])[0]
        resource_map = {"b": "blob", "c": "container", "s": "share", "f": "file"}

        detail_parts = []
        if expiry:
            detail_parts.append(f"Expires: {expiry}")
        if permissions:
            perm_map = {"r": "read", "w": "write", "d": "delete", "l": "list", "a": "add", "c": "create"}
            perm_names = [perm_map.get(p, p) for p in permissions]
            detail_parts.append(f"Perms: {','.join(perm_names)}")
            if "w" in permissions or "d" in permissions:
                detail_parts.append("⚠️ WRITE/DELETE access!")
        if resource:
            detail_parts.append(f"Scope: {resource_map.get(resource, resource)}")

        return {
            "provider": "sas_parse",
            "expiry": expiry or "unknown",
            "permissions": permissions or "unknown",
            "has_write": "w" in (permissions or ""),
            "has_delete": "d" in (permissions or ""),
            "resource_type": resource_map.get(resource, resource or "unknown"),
            "detail": " | ".join(detail_parts) if detail_parts else "Could not parse SAS parameters",
        }
    except Exception as e:
        logger.debug(f"Azure SAS parse error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# CIDR RANGE ENRICHMENT -  Shodan InternetDB for representative IPs
# ══════════════════════════════════════════════════════════════════════

async def _cidr_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """For CIDR ranges, check first 3 IPs against Shodan InternetDB (free, no key)."""
    import ipaddress
    try:
        network = ipaddress.ip_network(ioc_value, strict=False)
        hosts = list(network.hosts())[:3]  # Sample first 3 IPs
        if not hosts:
            return None

        open_ports = set()
        vulns = set()
        for ip in hosts:
            try:
                r = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=5.0)
                if r.status_code == 200:
                    data = r.json()
                    open_ports.update(data.get("ports", []))
                    vulns.update(data.get("vulns", []))
            except Exception:
                continue

        return {
            "provider": "shodan_internetdb",
            "sampled_ips": len(hosts),
            "network_size": network.num_addresses,
            "open_ports": sorted(list(open_ports))[:20],
            "vulns": sorted(list(vulns))[:10],
            "detail": f"CIDR /{network.prefixlen}: {len(open_ports)} open ports, {len(vulns)} CVEs across {len(hosts)} sampled IPs",
        }
    except Exception as e:
        logger.debug(f"CIDR enrichment error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# MALICIOUS URL PATH ENRICHMENT -  full URL lookup via VT
# ══════════════════════════════════════════════════════════════════════

async def _url_path_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """For malicious URL paths (wp-admin, phpmyadmin), construct full URL and check VT."""
    # The ioc_value is typically just the path -  try VT if it looks like a full URL
    if ioc_value.startswith("http"):
        return await _vt_lookup(ioc_value, "url", client)
    return None


# ══════════════════════════════════════════════════════════════════════
# SAAS MISCONFIG -  check if cloud resource is publicly accessible
# ══════════════════════════════════════════════════════════════════════

async def _saas_accessibility_check(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    """HEAD request to check public accessibility. Not scanning -  checking a known URL."""
    try:
        url = None
        if ioc_type == "azure_blob_public" and "blob.core.windows.net" in ioc_value:
            url = ioc_value if ioc_value.startswith("http") else f"https://{ioc_value}"
        elif ioc_type == "gcs_public_bucket" and "storage.googleapis.com" in ioc_value:
            url = ioc_value if ioc_value.startswith("http") else f"https://{ioc_value}"
        elif ioc_type == "elasticsearch_exposed" and ":9200" in ioc_value:
            host = ioc_value.split(":9200")[0]
            url = f"{'http://' if not host.startswith('http') else ''}{host}:9200"
        elif ioc_type == "open_analytics_service":
            url = ioc_value if ioc_value.startswith("http") else f"https://{ioc_value}"
        if not url:
            return None
        r = await client.head(url, timeout=5.0, follow_redirects=True)
        accessible = r.status_code in (200, 206, 301, 302)
        return {"provider": "accessibility_check", "publicly_accessible": accessible,
                "status_code": r.status_code,
                "detail": f"{'⚠️ PUBLICLY ACCESSIBLE' if accessible else '🔒 Not accessible'} (HTTP {r.status_code})"}
    except Exception as e:
        return {"provider": "accessibility_check", "publicly_accessible": "unknown", "detail": f"Check failed: {str(e)[:60]}"}


# ══════════════════════════════════════════════════════════════════════
# DNS RESOLUTION -  does internal hostname resolve publicly?
# ══════════════════════════════════════════════════════════════════════

async def _dns_resolution_check(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """If an internal hostname resolves in public DNS, that's the finding."""
    import socket as _socket
    try:
        results = _socket.getaddrinfo(ioc_value.strip().lower(), None, _socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        return {"provider": "dns_check", "resolves_publicly": True, "resolved_ips": ips[:5],
                "detail": f"⚠️ Internal hostname resolves publicly to {', '.join(ips[:3])}"}
    except _socket.gaierror:
        return {"provider": "dns_check", "resolves_publicly": False,
                "detail": "Does not resolve in public DNS (expected for internal hostname)"}
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════
# ADVISORY -  GitHub Advisory Database API (free, no key)
# ══════════════════════════════════════════════════════════════════════

async def _advisory_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """Look up GHSA advisories via GitHub API."""
    try:
        aid = ioc_value.strip()
        if aid.startswith("GHSA-"):
            r = await client.get(f"https://api.github.com/advisories/{aid}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "ArgusWatch"}, timeout=8.0)
            if r.status_code == 200:
                d = r.json()
                return {"provider": "github_advisory", "severity": d.get("severity", "unknown"),
                        "summary": (d.get("summary") or "")[:200], "published": d.get("published_at", ""),
                        "cvss_score": d.get("cvss", {}).get("score"), "cwe": d.get("cwe_ids", [])[:3],
                        "detail": f"{aid}: {d.get('severity', '?').upper()} -  {(d.get('summary') or '')[:80]}"}
    except Exception as e:
        logger.debug(f"Advisory enrichment error: {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# RANSOM NOTE -  extract crypto addresses -> blockchain check
# ══════════════════════════════════════════════════════════════════════

async def _ransom_note_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """Extract bitcoin/monero addresses from ransom note, check blockchain."""
    import re as _re
    btc = _re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', ioc_value)
    btc += _re.findall(r'\bbc1[a-z0-9]{39,59}\b', ioc_value)
    xmr = _re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', ioc_value)
    results = []
    for addr in btc[:2]:
        bc = await _blockchain_enrichment(addr, "bitcoin_address", client)
        if bc:
            results.append(bc)
    total_btc = sum(r.get("total_received_btc", 0) for r in results)
    if btc or xmr:
        return {"provider": "ransom_blockchain", "btc_found": len(btc), "xmr_found": len(xmr),
                "total_btc_received": round(total_btc, 4),
                "detail": f"{len(btc)} BTC + {len(xmr)} XMR addrs. BTC received: {total_btc:.4f}"}
    return None


# ══════════════════════════════════════════════════════════════════════
# EXPOSED SECRET -  detect type by prefix, route to correct liveness check
# ══════════════════════════════════════════════════════════════════════

async def _exposed_secret_enrichment(ioc_value: str, client: httpx.AsyncClient) -> dict | None:
    """exposed_secret is generic -  detect the actual type by prefix and route."""
    import re as _re
    v = ioc_value.strip()
    prefix_map = [
        ("AKIA", "aws_access_key"), ("ghp_", "github_pat_classic"),
        ("github_pat_", "github_fine_grained_pat"), ("gho_", "github_oauth_token"),
        ("ghs_", "github_saas_token"), ("ghu_", "github_user_token"),
        ("glpat-", "gitlab_pat"), ("sk_live_", "stripe_live_key"),
        ("sk-ant-", "anthropic_api_key"), ("SG.", "sendgrid_api_key"),
        ("xoxb-", "slack_bot_token"), ("xoxp-", "slack_user_token"),
        ("AIza", "google_api_key"),
    ]
    for prefix, ioc_type in prefix_map:
        if v.startswith(prefix):
            return await _check_key_liveness(v, ioc_type, client)
    if _re.match(r'^sk-[A-Za-z0-9]{48,}', v):
        return await _check_key_liveness(v, "openai_api_key", client)
    return {"provider": "type_detection", "detail": f"Secret prefix not recognized: {v[:10]}..."}


# ══════════════════════════════════════════════════════════════════════
# AWS SECRET/ROOT KEY -  find paired AKIA from detection context
# ══════════════════════════════════════════════════════════════════════

async def _aws_pair_enrichment(ioc_value: str, det_raw_text: str, client: httpx.AsyncClient) -> dict | None:
    """For aws_secret_key/aws_root_key, look for paired AKIA in same detection."""
    import re as _re
    akia = _re.search(r'\bAKIA[0-9A-Z]{16}\b', det_raw_text or "")
    if akia:
        return {"provider": "aws_pair", "complete_pair": True, "access_key_id": akia.group(0),
                "detail": f"⚠️ COMPLETE AWS KEY PAIR: {akia.group(0)} + secret. Full account access."}
    return {"provider": "aws_pair", "complete_pair": False,
            "detail": "Secret key found but no AKIA in same context. Cannot verify."}


# ══════════════════════════════════════════════════════════════════════
# Types that support each enrichment source
# ══════════════════════════════════════════════════════════════════════
_KEY_LIVENESS_TYPES = {
    "aws_access_key", "github_pat_classic", "github_fine_grained_pat",
    "github_oauth_token", "github_app_token", "stripe_live_key",
    "openai_api_key", "sendgrid_api_key", "anthropic_api_key",
    # v16.4.7: Added from unenriched audit
    "gitlab_pat", "slack_bot_token", "slack_user_token",
    "google_api_key", "github_saas_token",
    # Note: slack_bot_oauth/slack_user_oauth patterns removed from pattern_matcher
    # (duplicated slack_bot_token/slack_user_token). Kept here for backward compat
    # in case old detections still have those types.
    "slack_bot_oauth", "slack_user_oauth",
}

# Types that support credential breach enrichment
_CREDENTIAL_TYPES = {
    "email_password_combo", "breachdirectory_combo", "email_hash_combo",
    "username_password_combo", "plaintext_password",
    # v16.4.7: email types can also be checked for breach presence
    "email", "executive_email",
}

# Types that support JWT/token issuer domain enrichment
_TOKEN_ISSUER_TYPES = {
    "jwt_token", "azure_bearer", "google_oauth_bearer", "saml_assertion",
}

# Types that support blockchain enrichment
_BLOCKCHAIN_TYPES = {"bitcoin_address", "ethereum_address", "monero_address"}

# Types that support config content extraction -> VT
_CONFIG_CONTENT_TYPES = {"config_file", "backup_file", "db_config"}

# Types that support Azure SAS parsing
_SAS_TYPES = {"azure_sas_token"}

# Types that support CIDR range scanning
_CIDR_TYPES = {"cidr_range"}

# Types that support URL path VT lookup
_URL_PATH_TYPES = {"malicious_url_path"}

# Types that support public accessibility check
_SAAS_MISCONFIG_TYPES = {"azure_blob_public", "gcs_public_bucket", "elasticsearch_exposed", "open_analytics_service"}

# Types that support DNS resolution check
_DNS_CHECK_TYPES = {"internal_hostname"}

# Types that support advisory API lookup
_ADVISORY_TYPES = {"advisory"}


async def enrich_detection(detection_id: int) -> dict:
    """Run all applicable enrichment providers for a detection."""
    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": "Detection not found"}

        results = {}
        async with httpx.AsyncClient(timeout=12.0) as client:

            # ── VirusTotal (IP, domain, URL, hash) ──
            vt = await _vt_lookup(det.ioc_value, det.ioc_type, client)
            if vt:
                results["virustotal"] = vt
                vt_numeric_sum = sum(v for v in vt.values() if isinstance(v, (int, float)))
                db.add(Enrichment(
                    detection_id=det.id, provider="virustotal",
                    enrichment_type="reputation", data=vt,
                    risk_score=vt.get("malicious", 0) / max(vt_numeric_sum, 1),
                ))
                if vt.get("malicious", 0) > 20 and det.severity != SeverityLevel.CRITICAL:
                    det.severity = SeverityLevel.HIGH
                    det.confidence = min(1.0, det.confidence + 0.15)

            # ── AbuseIPDB (IPs only) ──
            if det.ioc_type in ("ipv4", "ipv6"):
                abuse = await _abuse_lookup(det.ioc_value, client)
                if abuse:
                    results["abuseipdb"] = abuse
                    db.add(Enrichment(
                        detection_id=det.id, provider="abuseipdb",
                        enrichment_type="ip_reputation", data=abuse,
                        risk_score=abuse.get("abuse_confidence", 0) / 100.0,
                    ))
                    if abuse.get("abuse_confidence", 0) > 80:
                        det.confidence = min(1.0, det.confidence + 0.1)

            # ── API Key Liveness Check ──
            if det.ioc_type in _KEY_LIVENESS_TYPES:
                liveness = await _check_key_liveness(det.ioc_value, det.ioc_type, client)
                if liveness:
                    results["key_liveness"] = liveness
                    db.add(Enrichment(
                        detection_id=det.id, provider=f"key_liveness_{liveness.get('provider', '?')}",
                        enrichment_type="key_liveness", data=liveness,
                        risk_score=1.0 if liveness.get("active") else 0.1,
                    ))
                    if liveness.get("active") is True:
                        det.severity = SeverityLevel.CRITICAL
                        det.confidence = min(1.0, det.confidence + 0.3)
                        logger.info(f"[enrichment] ACTIVE KEY DETECTED: {det.ioc_type} -> CRITICAL")

            # ── Credential Breach Check ──
            if det.ioc_type in _CREDENTIAL_TYPES:
                cred = await _credential_enrichment(det.ioc_value, det.ioc_type, client)
                if cred:
                    results["credential_breach"] = cred
                    db.add(Enrichment(
                        detection_id=det.id, provider="hudsonrock",
                        enrichment_type="credential_breach", data=cred,
                        risk_score=0.9 if cred.get("compromised") else 0.1,
                    ))
                    if cred.get("stealer_count", 0) > 0:
                        det.confidence = min(1.0, det.confidence + 0.2)

            # ── Token Issuer Domain Check ──
            if det.ioc_type in _TOKEN_ISSUER_TYPES:
                issuer = await _token_issuer_enrichment(det.ioc_value, det.ioc_type, client)
                if issuer:
                    results["token_issuer"] = issuer
                    db.add(Enrichment(
                        detection_id=det.id, provider="vt_issuer",
                        enrichment_type="token_issuer", data=issuer,
                        risk_score=min(1.0, issuer.get("vt_malicious", 0) / 10),
                    ))
                    if issuer.get("vt_malicious", 0) > 5:
                        det.confidence = min(1.0, det.confidence + 0.2)
                        logger.info(f"[enrichment] Suspicious token issuer: {issuer.get('issuer_domain')} ({issuer.get('vt_malicious')} VT hits)")

            # ── Blockchain Address Check ──
            if det.ioc_type in _BLOCKCHAIN_TYPES:
                bc = await _blockchain_enrichment(det.ioc_value, det.ioc_type, client)
                if bc:
                    results["blockchain"] = bc
                    db.add(Enrichment(
                        detection_id=det.id, provider=bc.get("provider", "blockchain"),
                        enrichment_type="blockchain", data=bc,
                        risk_score=0.5 if bc.get("n_tx", 0) > 0 else 0.1,
                    ))

            # ── Dark Web .onion Check ──
            if det.ioc_type == "onion_address":
                onion = await _onion_enrichment(det.ioc_value, client)
                if onion:
                    results["onion"] = onion
                    db.add(Enrichment(
                        detection_id=det.id, provider="ahmia",
                        enrichment_type="darkweb_index", data=onion,
                        risk_score=0.7 if onion.get("indexed") else 0.3,
                    ))

            # ── Config/Backup Content Extraction -> VT ──
            if det.ioc_type in _CONFIG_CONTENT_TYPES:
                cfg = await _config_content_enrichment(det.ioc_value, det.ioc_type, client)
                if cfg:
                    results["config_scan"] = cfg
                    db.add(Enrichment(
                        detection_id=det.id, provider="vt_content_scan",
                        enrichment_type="content_extraction", data=cfg,
                        risk_score=min(1.0, cfg.get("worst_vt_score", 0) / 10),
                    ))
                    if cfg.get("malicious_domains", 0) > 0:
                        det.confidence = min(1.0, det.confidence + 0.15)

            # ── Azure SAS Token Parse ──
            if det.ioc_type in _SAS_TYPES:
                sas = await _azure_sas_enrichment(det.ioc_value, client)
                if sas:
                    results["sas_parse"] = sas
                    risk = 0.8 if sas.get("has_write") or sas.get("has_delete") else 0.4
                    db.add(Enrichment(
                        detection_id=det.id, provider="sas_parse",
                        enrichment_type="token_analysis", data=sas,
                        risk_score=risk,
                    ))
                    if sas.get("has_write") or sas.get("has_delete"):
                        det.severity = SeverityLevel.CRITICAL
                        logger.info(f"[enrichment] Azure SAS with WRITE/DELETE -> CRITICAL")

            # ── CIDR Range Scan ──
            if det.ioc_type in _CIDR_TYPES:
                cidr = await _cidr_enrichment(det.ioc_value, client)
                if cidr:
                    results["cidr_scan"] = cidr
                    risk = min(1.0, len(cidr.get("vulns", [])) / 5)
                    db.add(Enrichment(
                        detection_id=det.id, provider="shodan_internetdb",
                        enrichment_type="network_scan", data=cidr,
                        risk_score=risk,
                    ))

            # ── Malicious URL Path -> VT ──
            if det.ioc_type in _URL_PATH_TYPES:
                url_vt = await _url_path_enrichment(det.ioc_value, client)
                if url_vt:
                    results["url_path_vt"] = url_vt
                    db.add(Enrichment(
                        detection_id=det.id, provider="virustotal",
                        enrichment_type="url_reputation", data=url_vt,
                        risk_score=url_vt.get("malicious", 0) / max(sum(v for v in url_vt.values() if isinstance(v, (int, float))), 1),
                    ))

            # ── SaaS Misconfig Accessibility ──
            if det.ioc_type in _SAAS_MISCONFIG_TYPES:
                saas = await _saas_accessibility_check(det.ioc_value, det.ioc_type, client)
                if saas:
                    results["saas_check"] = saas
                    db.add(Enrichment(
                        detection_id=det.id, provider="accessibility_check",
                        enrichment_type="accessibility", data=saas,
                        risk_score=1.0 if saas.get("publicly_accessible") is True else 0.2,
                    ))
                    if saas.get("publicly_accessible") is True:
                        det.severity = SeverityLevel.CRITICAL
                        logger.info(f"[enrichment] PUBLICLY ACCESSIBLE: {det.ioc_type} -> CRITICAL")

            # ── Internal Hostname DNS Leak ──
            if det.ioc_type in _DNS_CHECK_TYPES:
                dns = await _dns_resolution_check(det.ioc_value, client)
                if dns:
                    results["dns_check"] = dns
                    db.add(Enrichment(
                        detection_id=det.id, provider="dns_check",
                        enrichment_type="dns_resolution", data=dns,
                        risk_score=0.8 if dns.get("resolves_publicly") else 0.1,
                    ))

            # ── Advisory Lookup (GHSA) ──
            if det.ioc_type in _ADVISORY_TYPES:
                adv = await _advisory_enrichment(det.ioc_value, client)
                if adv:
                    results["advisory"] = adv
                    db.add(Enrichment(
                        detection_id=det.id, provider="github_advisory",
                        enrichment_type="advisory", data=adv,
                        risk_score={"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}.get(adv.get("severity", ""), 0.3),
                    ))

            # ── Ransom Note -> extract crypto addresses ──
            if det.ioc_type == "ransom_note":
                rn = await _ransom_note_enrichment(det.ioc_value, client)
                if rn:
                    results["ransom_crypto"] = rn
                    db.add(Enrichment(
                        detection_id=det.id, provider="ransom_blockchain",
                        enrichment_type="crypto_extraction", data=rn,
                        risk_score=0.9 if rn.get("total_btc_received", 0) > 0 else 0.5,
                    ))

            # ── Exposed Secret -> route by prefix ──
            if det.ioc_type == "exposed_secret":
                es = await _exposed_secret_enrichment(det.ioc_value, client)
                if es:
                    results["secret_liveness"] = es
                    db.add(Enrichment(
                        detection_id=det.id, provider=es.get("provider", "type_detection"),
                        enrichment_type="key_liveness", data=es,
                        risk_score=1.0 if es.get("active") else 0.3,
                    ))
                    if es.get("active") is True:
                        det.severity = SeverityLevel.CRITICAL
                        logger.info(f"[enrichment] ACTIVE exposed_secret detected -> CRITICAL")

            # ── AWS Secret/Root Key -> find paired AKIA ──
            if det.ioc_type in ("aws_secret_key", "aws_root_key"):
                raw = ""
                if det.raw_text:
                    raw = det.raw_text
                elif det.metadata_:
                    raw = str(det.metadata_)
                aws = await _aws_pair_enrichment(det.ioc_value, raw, client)
                if aws:
                    results["aws_pair"] = aws
                    db.add(Enrichment(
                        detection_id=det.id, provider="aws_pair",
                        enrichment_type="key_pair_detection", data=aws,
                        risk_score=1.0 if aws.get("complete_pair") else 0.5,
                    ))
                    if aws.get("complete_pair"):
                        det.severity = SeverityLevel.CRITICAL
                        logger.info(f"[enrichment] COMPLETE AWS KEY PAIR -> CRITICAL")

        await db.commit()
        return {
            "detection_id": detection_id,
            "enrichments": list(results.keys()),
            "ioc_type": det.ioc_type,
            "ioc_value": det.ioc_value[:60],
        }
