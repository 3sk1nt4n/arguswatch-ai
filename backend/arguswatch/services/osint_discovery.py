"""
Free OSINT Asset Discovery - zero API keys required.

Sources:
  1. crt.sh (Certificate Transparency)  → subdomains
  2. DNS resolution (A, MX, NS, TXT)    → IPs, mail servers
  3. RDAP / ipwhois                      → org name, CIDR
  4. HTTP header + HTML meta scraping    → tech stack, emails, exec names
  5. GitHub search (unauthenticated)     → github org, code repos
  6. Smart inference                     → brand name, keywords, cloud assets
"""
import re
import logging
import asyncio
from typing import Optional

import httpx

logger = logging.getLogger("arguswatch.discovery.osint")

TIMEOUT = httpx.Timeout(15.0, connect=8.0)
HEADERS = {"User-Agent": "ArgusWatch-Discovery/1.0"}


# ══════════════════════════════════════════════════════════════════════
# 1. CERTIFICATE TRANSPARENCY (crt.sh) → subdomains
# ══════════════════════════════════════════════════════════════════════

async def _discover_crtsh(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Query crt.sh for certificate transparency logs → subdomains."""
    results = []
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers=HEADERS, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            seen = set()
            for entry in r.json()[:500]:
                name = entry.get("name_value", "").strip().lower()
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and sub != domain and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
                        results.append({
                            "asset_type": "subdomain",
                            "asset_value": sub,
                            "criticality": "medium",
                            "confidence": 0.9,
                        })
            logger.info(f"crt.sh: {len(results)} subdomains for {domain}")
    except Exception as e:
        logger.warning(f"crt.sh failed for {domain}: {e}")
    return results


# ══════════════════════════════════════════════════════════════════════
# 2. DNS RESOLUTION → IPs, mail servers
# ══════════════════════════════════════════════════════════════════════

async def _discover_dns(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Use public DNS-over-HTTPS (Cloudflare) → IPs and mail servers."""
    results = []
    dns_url = "https://cloudflare-dns.com/dns-query"

    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            r = await client.get(
                dns_url, params={"name": domain, "type": rtype},
                headers={"Accept": "application/dns-json", **HEADERS},
                timeout=TIMEOUT,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for ans in data.get("Answer", []):
                val = ans.get("data", "").strip().rstrip(".")

                if rtype in ("A", "AAAA") and val:
                    results.append({
                        "asset_type": "ip",
                        "asset_value": val,
                        "criticality": "high",
                        "confidence": 0.95,
                    })

                elif rtype == "MX" and val:
                    # MX records: "10 mail.example.com."
                    mx_host = val.split()[-1].rstrip(".")
                    if mx_host:
                        results.append({
                            "asset_type": "subdomain",
                            "asset_value": mx_host,
                            "criticality": "medium",
                            "confidence": 0.85,
                        })

                elif rtype == "TXT" and val:
                    # SPF records → extract include domains
                    if "v=spf1" in val:
                        for m in re.findall(r"include:(\S+)", val):
                            results.append({
                                "asset_type": "subdomain",
                                "asset_value": m.rstrip("."),
                                "criticality": "low",
                                "confidence": 0.6,
                            })
                    # Look for cloud services in TXT
                    cloud_patterns = {
                        "google-site-verification": "Google Workspace",
                        "MS=": "Microsoft 365",
                        "atlassian-domain-verification": "Atlassian Cloud",
                        "docusign": "DocuSign",
                        "facebook-domain-verification": "Facebook Business",
                        "apple-domain-verification": "Apple Business",
                    }
                    for pattern, service in cloud_patterns.items():
                        if pattern.lower() in val.lower():
                            results.append({
                                "asset_type": "cloud_asset",
                                "asset_value": service,
                                "criticality": "medium",
                                "confidence": 0.8,
                            })

        except Exception as e:
            logger.debug(f"DNS {rtype} failed for {domain}: {e}")

    logger.info(f"DNS: {len(results)} records for {domain}")
    return results


# ══════════════════════════════════════════════════════════════════════
# 3. RDAP (WHOIS replacement) → org name, CIDR
# ══════════════════════════════════════════════════════════════════════

async def _discover_rdap(client: httpx.AsyncClient, domain: str, ips: list[str]) -> list[dict]:
    """Query RDAP for domain WHOIS + IP network info."""
    results = []

    # Domain WHOIS via RDAP
    try:
        r = await client.get(
            f"https://rdap.org/domain/{domain}",
            headers=HEADERS, timeout=TIMEOUT, follow_redirects=True,
        )
        if r.status_code == 200:
            data = r.json()
            # Extract registrant org
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "org" and len(field) > 3 and field[3]:
                            org = field[3]
                            if isinstance(org, str) and len(org) > 2:
                                results.append({
                                    "asset_type": "org_name",
                                    "asset_value": org,
                                    "criticality": "medium",
                                    "confidence": 0.85,
                                })
                        if field[0] == "fn" and len(field) > 3 and field[3]:
                            fn = field[3]
                            if isinstance(fn, str) and len(fn) > 2 and fn.lower() not in ("redacted", "data protected"):
                                results.append({
                                    "asset_type": "org_name",
                                    "asset_value": fn,
                                    "criticality": "low",
                                    "confidence": 0.6,
                                })
    except Exception as e:
        logger.debug(f"RDAP domain lookup failed: {e}")

    # IP WHOIS → CIDR ranges
    for ip in ips[:3]:
        try:
            r = await client.get(
                f"https://rdap.org/ip/{ip}",
                headers=HEADERS, timeout=TIMEOUT, follow_redirects=True,
            )
            if r.status_code == 200:
                data = r.json()
                cidr_str = data.get("handle", "")
                start = data.get("startAddress", "")
                end = data.get("endAddress", "")
                name = data.get("name", "")
                # Build CIDR from RDAP
                for cidr in data.get("cidr0_cidrs", []):
                    prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
                    length = cidr.get("length")
                    if prefix and length:
                        results.append({
                            "asset_type": "cidr",
                            "asset_value": f"{prefix}/{length}",
                            "criticality": "medium",
                            "confidence": 0.8,
                        })
        except Exception as e:
            logger.debug(f"RDAP IP lookup failed for {ip}: {e}")

    return results


# ══════════════════════════════════════════════════════════════════════
# 4. HTTP SCRAPING → tech stack, emails, exec names
# ══════════════════════════════════════════════════════════════════════

async def _discover_web(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Scrape the website homepage for tech stack, emails, and metadata."""
    results = []
    try:
        r = await client.get(
            f"https://{domain}",
            headers={**HEADERS, "Accept": "text/html"},
            timeout=TIMEOUT, follow_redirects=True,
        )
        if r.status_code != 200:
            return results

        html = r.text[:200_000]
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        # ── Tech stack from headers ──
        tech_signals = {
            "x-powered-by": lambda v: v,
            "server": lambda v: v,
            "x-aspnet-version": lambda v: f"ASP.NET {v}",
            "x-drupal-cache": lambda _: "Drupal",
            "x-generator": lambda v: v,
        }
        for hdr, extractor in tech_signals.items():
            if hdr in headers_lower:
                tech = extractor(headers_lower[hdr])
                if tech and len(tech) > 1:
                    results.append({
                        "asset_type": "tech_stack",
                        "asset_value": tech,
                        "criticality": "medium",
                        "confidence": 0.85,
                    })

        # ── Tech stack from HTML meta/scripts ──
        tech_patterns = [
            (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', "medium"),
            (r'wp-content/|/wp-includes/', "WordPress"),
            (r'shopify\.com|cdn\.shopify', "Shopify"),
            (r'squarespace\.com', "Squarespace"),
            (r'cloudflare', "Cloudflare"),
            (r'akamai', "Akamai CDN"),
            (r'fastly', "Fastly CDN"),
            (r'react', "React"),
            (r'angular', "Angular"),
            (r'vue\.js|vuejs', "Vue.js"),
            (r'next\.js|nextjs|_next/', "Next.js"),
            (r'jquery', "jQuery"),
            (r'bootstrap', "Bootstrap"),
            (r'salesforce\.com', "Salesforce"),
            (r'hubspot', "HubSpot"),
            (r'zendesk', "Zendesk"),
            (r'intercom', "Intercom"),
            (r'segment\.com|analytics\.js', "Segment"),
            (r'stripe\.com|stripe\.js', "Stripe"),
            (r'recaptcha', "reCAPTCHA"),
            (r'google-analytics|gtag|GA-|G-\d', "Google Analytics"),
            (r'googletagmanager', "Google Tag Manager"),
        ]
        seen_tech = set()
        for pattern in tech_patterns:
            if isinstance(pattern, tuple) and len(pattern) == 2:
                pat, name = pattern
                if re.search(pat, html, re.I):
                    m = re.search(pat, html, re.I)
                    val = name if isinstance(name, str) and name != "medium" else m.group(1) if m.groups() else name
                    if val and val not in seen_tech:
                        seen_tech.add(val)
                        results.append({
                            "asset_type": "tech_stack",
                            "asset_value": val,
                            "criticality": "low",
                            "confidence": 0.7,
                        })

        # ── Emails from page ──
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), html))
        for email in list(emails)[:10]:
            results.append({
                "asset_type": "email",
                "asset_value": email.lower(),
                "criticality": "medium",
                "confidence": 0.8,
            })

        # ── Common email patterns inferred ──
        common_emails = [
            f"info@{domain}", f"security@{domain}", f"admin@{domain}",
            f"abuse@{domain}", f"support@{domain}",
        ]
        for e in common_emails:
            if e not in emails:
                results.append({
                    "asset_type": "email",
                    "asset_value": e,
                    "criticality": "low",
                    "confidence": 0.5,
                })

        # ── Title / description for keywords ──
        title_m = re.search(r'<title[^>]*>([^<]+)', html, re.I)
        if title_m:
            title = title_m.group(1).strip()[:100]
            if title and len(title) > 3:
                results.append({
                    "asset_type": "keyword",
                    "asset_value": title,
                    "criticality": "low",
                    "confidence": 0.6,
                })

        # ── OG metadata for exec / leadership ──
        # Check /about or /leadership pages for exec names
        about_paths = ["/about", "/about-us", "/leadership", "/team", "/company"]
        for path in about_paths:
            try:
                r2 = await client.get(
                    f"https://{domain}{path}",
                    headers={**HEADERS, "Accept": "text/html"},
                    timeout=httpx.Timeout(8.0), follow_redirects=True,
                )
                if r2.status_code == 200:
                    about_html = r2.text[:100_000]
                    # Look for structured exec data (common patterns)
                    exec_patterns = [
                        r'(?:CEO|CTO|CISO|CFO|COO|CIO|CPO|VP|President|Founder|Director)[,:\s]+([A-Z][a-z]+ [A-Z][a-z]+)',
                        r'([A-Z][a-z]+ [A-Z][a-z]+)[,\s]+(?:CEO|CTO|CISO|CFO|COO|CIO|CPO|VP|President|Founder|Director)',
                    ]
                    exec_seen = set()
                    for pat in exec_patterns:
                        for m in re.finditer(pat, about_html):
                            name = m.group(1).strip()
                            if name not in exec_seen and len(name) > 4 and len(name) < 50:
                                exec_seen.add(name)
                                results.append({
                                    "asset_type": "exec_name",
                                    "asset_value": name,
                                    "criticality": "medium",
                                    "confidence": 0.65,
                                })
                    if exec_seen:
                        break  # Found execs, no need to try other paths
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Web scraping failed for {domain}: {e}")

    return results


# ══════════════════════════════════════════════════════════════════════
# 5. GITHUB (unauthenticated) → org, repos
# ══════════════════════════════════════════════════════════════════════

async def _discover_github(client: httpx.AsyncClient, domain: str, org_hint: str = "") -> list[dict]:
    """Search GitHub for the org associated with this domain."""
    results = []
    # Derive org guess from domain (e.g., paypal.com → paypal)
    org_guess = org_hint or domain.split(".")[0]

    try:
        # Check if GitHub org exists
        r = await client.get(
            f"https://api.github.com/orgs/{org_guess}",
            headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            org_data = r.json()
            org_name = org_data.get("login", org_guess)
            results.append({
                "asset_type": "github_org",
                "asset_value": org_name,
                "criticality": "high",
                "confidence": 0.85,
            })

            # Get top public repos
            r2 = await client.get(
                f"https://api.github.com/orgs/{org_name}/repos?sort=updated&per_page=10",
                headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                timeout=TIMEOUT,
            )
            if r2.status_code == 200:
                for repo in r2.json()[:10]:
                    full_name = repo.get("full_name", "")
                    if full_name:
                        results.append({
                            "asset_type": "code_repo",
                            "asset_value": full_name,
                            "criticality": "medium",
                            "confidence": 0.8,
                        })

    except Exception as e:
        logger.debug(f"GitHub discovery failed for {org_guess}: {e}")

    return results


# ══════════════════════════════════════════════════════════════════════
# 6. SMART INFERENCE → brand name, keywords, cloud assets
# ══════════════════════════════════════════════════════════════════════

def _infer_assets(domain: str, customer_name: str = "") -> list[dict]:
    """Generate inferred assets from domain and customer name."""
    results = []
    base = domain.split(".")[0]

    # Brand name
    brand = customer_name or base.title()
    results.append({
        "asset_type": "brand_name",
        "asset_value": brand,
        "criticality": "medium",
        "confidence": 0.7,
    })

    # Keywords
    results.append({
        "asset_type": "keyword",
        "asset_value": base,
        "criticality": "low",
        "confidence": 0.6,
    })
    if customer_name and customer_name.lower() != base.lower():
        results.append({
            "asset_type": "keyword",
            "asset_value": customer_name,
            "criticality": "low",
            "confidence": 0.6,
        })

    # Domain itself
    results.append({
        "asset_type": "domain",
        "asset_value": domain,
        "criticality": "critical",
        "confidence": 1.0,
    })

    return results


# ══════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════

async def run_osint_discovery(domain: str, customer_name: str = "") -> list[dict]:
    """
    Run ALL free OSINT discovery sources for a domain.
    Returns list of {"asset_type", "asset_value", "criticality", "confidence"} dicts.
    No API keys required. Falls back to inference-only if network is unavailable.
    """
    logger.info(f"Starting OSINT discovery for {domain}")
    all_results = []
    network_ok = False

    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            # Run crt.sh, DNS, and web scraping in parallel
            crt_task = _discover_crtsh(client, domain)
            dns_task = _discover_dns(client, domain)
            web_task = _discover_web(client, domain)
            github_task = _discover_github(client, domain)

            crt_results, dns_results, web_results, github_results = await asyncio.gather(
                crt_task, dns_task, web_task, github_task,
                return_exceptions=True,
            )

            # Collect non-error results
            for name, res in [("crt.sh", crt_results), ("dns", dns_results),
                              ("web", web_results), ("github", github_results)]:
                if isinstance(res, list) and len(res) > 0:
                    all_results.extend(res)
                    network_ok = True
                elif isinstance(res, Exception):
                    logger.warning(f"{name} discovery failed: {res}")

            # Extract IPs from DNS results for RDAP lookup
            ips = [r["asset_value"] for r in all_results if r.get("asset_type") == "ip"]

            # Run RDAP with discovered IPs
            if ips:
                try:
                    rdap_results = await _discover_rdap(client, domain, ips)
                    all_results.extend(rdap_results)
                except Exception as e:
                    logger.warning(f"RDAP failed: {e}")

    except Exception as e:
        logger.warning(f"Network unavailable for OSINT discovery: {e}")

    # Add inferred assets (always works, no network needed)
    all_results.extend(_infer_assets(domain, customer_name))

    # If network failed, add rich offline inferences
    if not network_ok:
        logger.info(f"Network unavailable - generating offline asset estimates for {domain}")
        all_results.extend(_offline_discovery(domain, customer_name))

    # Deduplicate
    seen = set()
    deduped = []
    for r in all_results:
        key = (r["asset_type"], r["asset_value"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    logger.info(f"OSINT discovery complete for {domain}: {len(deduped)} unique assets ({'' if network_ok else 'offline mode'})")
    return deduped


def _offline_discovery(domain: str, customer_name: str = "") -> list[dict]:
    """Generate reasonable asset estimates when network is unavailable.
    Uses common patterns for well-known domains and general heuristics."""
    results = []
    base = domain.split(".")[0]
    brand = customer_name or base.title()

    # Common subdomains
    common_subs = [
        "www", "mail", "api", "dev", "staging", "cdn", "app",
        "portal", "admin", "docs", "status", "support", "blog",
        "auth", "login", "sso", "vpn", "mx", "ns1", "ns2",
    ]
    for sub in common_subs:
        results.append({
            "asset_type": "subdomain",
            "asset_value": f"{sub}.{domain}",
            "criticality": "low",
            "confidence": 0.3,  # Low confidence - unverified
        })

    # Common email patterns
    for prefix in ["info", "security", "admin", "abuse", "support",
                    "hr", "legal", "privacy", "webmaster", "postmaster"]:
        results.append({
            "asset_type": "email",
            "asset_value": f"{prefix}@{domain}",
            "criticality": "medium" if prefix in ("security", "admin") else "low",
            "confidence": 0.4,
        })

    # Org name from customer
    results.append({
        "asset_type": "org_name",
        "asset_value": brand,
        "criticality": "medium",
        "confidence": 0.7,
    })

    # GitHub org guess
    results.append({
        "asset_type": "github_org",
        "asset_value": base,
        "criticality": "medium",
        "confidence": 0.4,
    })

    # Common cloud services
    for service in ["Google Workspace", "Microsoft 365", "AWS", "Cloudflare"]:
        results.append({
            "asset_type": "cloud_asset",
            "asset_value": f"{service} (estimated)",
            "criticality": "low",
            "confidence": 0.2,
        })

    # Tech stack estimates
    for tech in ["HTTPS/TLS", "DNS", "Email (SMTP)"]:
        results.append({
            "asset_type": "tech_stack",
            "asset_value": tech,
            "criticality": "low",
            "confidence": 0.5,
        })

    return results
