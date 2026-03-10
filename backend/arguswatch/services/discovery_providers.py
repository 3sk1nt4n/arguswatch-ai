"""
Discovery Providers - external asset discovery behind feature flags.

V13 FEATURE 4: Extensible provider interface for automated asset discovery.
Each provider requires an API key configured in settings. If no key -> gracefully disabled.

Providers:
  1. SecurityTrails - subdomain enumeration, DNS history, WHOIS
  (Future: Shodan, Censys, VirusTotal passive DNS, etc.)
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("arguswatch.discovery.providers")


# ═══════════════════════════════════════════════════════════════════════
# PROVIDER INTERFACE
# ═══════════════════════════════════════════════════════════════════════

class DiscoveryProvider(ABC):
    """Base class for external asset discovery providers.
    All providers must implement discover() and is_configured()."""

    name: str = "base"
    description: str = ""
    requires_key: str = ""  # settings attribute name for API key

    @abstractmethod
    async def discover(self, domain: str, **kwargs) -> list[dict]:
        """Discover assets for a domain. Returns list of
        {"asset_type": str, "asset_value": str, "criticality": str, "confidence": float}"""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if this provider has its API key configured."""
        ...

    def get_key(self) -> str:
        """Get the API key from settings."""
        try:
            from arguswatch.config import settings
            return getattr(settings, self.requires_key, "") or ""
        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════════════
# PROVIDER 1: SECURITYTRAILS
# ═══════════════════════════════════════════════════════════════════════

class SecurityTrailsProvider(DiscoveryProvider):
    """SecurityTrails API - subdomain enumeration, DNS history, associated domains.
    Requires SECURITYTRAILS_API_KEY in settings."""

    name = "securitytrails"
    description = "Subdomain enumeration, DNS history, WHOIS data"
    requires_key = "SECURITYTRAILS_API_KEY"
    base_url = "https://api.securitytrails.com/v1"

    def is_configured(self) -> bool:
        return bool(self.get_key())

    async def discover(self, domain: str, **kwargs) -> list[dict]:
        """Discover subdomains and related data for a domain via SecurityTrails."""
        key = self.get_key()
        if not key:
            return []

        import httpx
        headers = {"APIKEY": key, "Accept": "application/json"}
        results = []

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # 1. Subdomain enumeration
                resp = await client.get(
                    f"{self.base_url}/domain/{domain}/subdomains",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for sub in data.get("subdomains", []):
                        fqdn = f"{sub}.{domain}"
                        results.append({
                            "asset_type": "subdomain",
                            "asset_value": fqdn,
                            "criticality": "medium",
                            "confidence": 0.9,
                        })

                # 2. DNS records (A, MX, NS)
                resp2 = await client.get(
                    f"{self.base_url}/domain/{domain}",
                    headers=headers,
                )
                if resp2.status_code == 200:
                    data2 = resp2.json()
                    current_dns = data2.get("current_dns", {})

                    # A records -> IPs
                    for a_rec in current_dns.get("a", {}).get("values", []):
                        ip = a_rec.get("ip", "")
                        if ip:
                            results.append({
                                "asset_type": "ip",
                                "asset_value": ip,
                                "criticality": "high",
                                "confidence": 0.95,
                            })

                    # MX records -> mail servers
                    for mx in current_dns.get("mx", {}).get("values", []):
                        host = mx.get("hostname", "").rstrip(".")
                        if host:
                            results.append({
                                "asset_type": "subdomain",
                                "asset_value": host,
                                "criticality": "medium",
                                "confidence": 0.85,
                            })

                    # NS records -> nameservers
                    for ns in current_dns.get("ns", {}).get("values", []):
                        host = ns.get("nameserver", "").rstrip(".")
                        if host:
                            results.append({
                                "asset_type": "subdomain",
                                "asset_value": host,
                                "criticality": "low",
                                "confidence": 0.7,
                            })

                # 3. Associated domains (same registrant)
                resp3 = await client.get(
                    f"{self.base_url}/domain/{domain}/associated",
                    headers=headers,
                )
                if resp3.status_code == 200:
                    data3 = resp3.json()
                    for rec in data3.get("records", [])[:20]:
                        assoc = rec.get("hostname", "")
                        if assoc and assoc != domain:
                            results.append({
                                "asset_type": "domain",
                                "asset_value": assoc,
                                "criticality": "medium",
                                "confidence": 0.6,
                            })

        except Exception as e:
            logger.warning(f"SecurityTrails discovery failed for {domain}: {e}")

        return results


# ═══════════════════════════════════════════════════════════════════════
# PROVIDER 2: FREE OSINT (no API key required)
# ═══════════════════════════════════════════════════════════════════════

class OSINTFreeProvider(DiscoveryProvider):
    """Free OSINT discovery - crt.sh, DNS, RDAP, web scraping, GitHub.
    No API key required. Always available."""

    name = "osint_free"
    description = "Certificate Transparency, DNS, RDAP/WHOIS, web scraping, GitHub (no API key needed)"
    requires_key = ""  # No key required

    def is_configured(self) -> bool:
        return True  # Always available

    async def discover(self, domain: str, **kwargs) -> list[dict]:
        from arguswatch.services.osint_discovery import run_osint_discovery
        customer_name = kwargs.get("customer_name", "")
        return await run_osint_discovery(domain, customer_name)


# ═══════════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY
# ═══════════════════════════════════════════════════════════════════════

DISCOVERY_PROVIDERS: dict[str, DiscoveryProvider] = {
    "osint_free": OSINTFreeProvider(),
    "securitytrails": SecurityTrailsProvider(),
}


def get_configured_providers() -> list[dict]:
    """Return list of providers with their configuration status."""
    return [
        {
            "name": p.name,
            "description": p.description,
            "configured": p.is_configured(),
            "requires_key": p.requires_key,
        }
        for p in DISCOVERY_PROVIDERS.values()
    ]


async def run_discovery(domain: str, provider_name: str = "", customer_name: str = "") -> list[dict]:
    """Run discovery against one or all configured providers."""
    results = []

    if provider_name:
        p = DISCOVERY_PROVIDERS.get(provider_name)
        if not p:
            return [{"error": f"Unknown provider: {provider_name}"}]
        if not p.is_configured():
            return [{"error": f"Provider '{provider_name}' not configured. "
                     f"Set {p.requires_key} in settings."}]
        results = await p.discover(domain, customer_name=customer_name)
    else:
        # Run all configured providers
        for p in DISCOVERY_PROVIDERS.values():
            if p.is_configured():
                try:
                    r = await p.discover(domain, customer_name=customer_name)
                    results.extend(r)
                except Exception as e:
                    logger.warning(f"Provider {p.name} failed: {e}")

    return results
