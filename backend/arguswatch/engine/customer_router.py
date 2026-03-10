"""Customer Router - Routes IOC matches to customers via 13 asset types.

V10 additions over V9:
- 5 new asset types: subdomain, tech_stack, brand_name, exec_name, cloud_asset

V11 additions:
- code_repo: matches GitHub PAT leaks, exposed repos, supply chain IOCs
- correlation_type recorded on every match (exact_domain, subdomain, ip_range, etc.)
- Levenshtein-style typosquat detection for brand_name assets
- Tech stack matching: "FortiOS 7.2" asset matches CVE description containing "fortiOS"
- Exec name matching: "John Smith CEO" asset matches pastes containing that name
"""
import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class CustomerAssetRecord:
    customer_id: int
    customer_name: str
    asset_type: str
    asset_value: str
    criticality: str = "medium"


@dataclass
class RoutedDetection:
    customer_id: int
    customer_name: str
    matched_asset_type: str
    matched_asset_value: str
    ioc_value: str
    criticality: str
    correlation_type: str = "keyword"  # V10: how it matched


def _simple_edit_distance(a: str, b: str) -> int:
    """Simplified edit distance for typosquat detection (no numpy required)."""
    if len(a) > 30 or len(b) > 30:
        return 999  # Skip very long strings - not domain names
    if abs(len(a) - len(b)) > 3:
        return 999
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i-1] == b[j-1]:
                dp[j] = prev[j-1]
            else:
                dp[j] = 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]


def _extract_domain_from_ioc(ioc_value: str, ioc_type: str) -> str | None:
    """Pull the domain portion from a URL, email, connection string, or domain IOC."""
    if ioc_type in ("domain", "fqdn", "hostname"):
        return ioc_value.lower()
    if ioc_type == "email":
        parts = ioc_value.split("@")
        return parts[-1].lower() if len(parts) == 2 else None
    if ioc_type in ("url", "uri"):
        m = re.search(r"https?://([^/?\s:]+)", ioc_value)
        if m:
            return m.group(1).lower()
    # V16.4.7: Extract hostname from connection strings (postgresql://user:pass@host:port/db)
    if ioc_type in ("db_connection_string", "remote_credential", "dev_tunnel_exposed"):
        # Strip scheme, then take everything after the last @ (handles passwords with @)
        no_scheme = re.sub(r'^[a-z]+://', '', ioc_value)
        if '@' in no_scheme:
            after_at = no_scheme.rsplit('@', 1)[1]  # rsplit: last @ only
        else:
            after_at = no_scheme
        m = re.match(r'([^/:?\s]+)', after_at)
        if m:
            host = m.group(1).lower()
            if host not in ("localhost", "127.0.0.1", "0.0.0.0") and not host.startswith("192.168.") and not host.startswith("10."):
                return host
    return None


def route_to_customers(
    ioc_value: str,
    ioc_type: str,
    assets: list[CustomerAssetRecord],
) -> list[RoutedDetection]:
    """Match an IOC against all customer assets. Returns all matches with correlation_type."""
    results = []
    ioc_lower = ioc_value.lower()
    ioc_domain = _extract_domain_from_ioc(ioc_value, ioc_type)

    # V16.4.5: IOC types that carry their own domain identity.
    # These should ONLY match on domain/subdomain/ip assets, NEVER on keyword/brand.
    # Before this fix: "github" keyword matched ANY URL found in a GitHub Gist,
    # causing hostingmalaya.com, almagems.com, googleapis.com etc. to route to GitHub.
    DOMAIN_ONLY_IOC_TYPES = {"url", "uri", "domain", "fqdn", "hostname", "email",
                             "subdomain", "malicious_url_path", "s3_public_url"}
    DOMAIN_ONLY_ASSET_TYPES = {"domain", "subdomain", "ip", "cidr", "email",
                               "email_domain", "cloud_asset", "code_repo", "github_org",
                               "brand_name"}  # brand_name has its own domain-only logic

    for asset in assets:
        av = asset.asset_value.lower()
        matched = False
        corr_type = "keyword"

        atype = asset.asset_type

        # Skip keyword/brand/org matching entirely for URL-like IOCs
        if ioc_type in DOMAIN_ONLY_IOC_TYPES and atype not in DOMAIN_ONLY_ASSET_TYPES:
            continue

        # ── domain ──────────────────────────────────────────────────────────
        if atype == "domain":
            if ioc_domain:
                if ioc_domain == av:
                    matched, corr_type = True, "exact_domain"
                elif ioc_domain.endswith("." + av):
                    matched, corr_type = True, "subdomain"
            # V16.4.5: Removed dangerous `elif av in ioc_lower` fallback.
            # It caused ANY IOC text containing "github.com" to match GitHub.
            # Domain matching must ONLY work on extracted domain portions.

        # ── subdomain ────────────────────────────────────────────────────────
        elif atype == "subdomain":
            # V16.4.5: Only match on domain-level, never raw text substring.
            # Before: av in ioc_lower matched ANY text mentioning the subdomain.
            # After: only match if extracted domain matches the subdomain.
            if ioc_domain and (ioc_domain == av or ioc_domain.endswith("." + av)):
                matched, corr_type = True, "subdomain"
            elif ioc_domain and av.endswith(ioc_domain):
                # IOC domain is parent of this subdomain
                matched, corr_type = True, "subdomain"

        # ── ip ───────────────────────────────────────────────────────────────
        elif atype == "ip":
            if av == ioc_lower:
                matched, corr_type = True, "exact_ip"

        # ── cidr ─────────────────────────────────────────────────────────────
        elif atype == "cidr":
            try:
                matched = ipaddress.ip_address(ioc_value) in ipaddress.ip_network(
                    asset.asset_value, strict=False
                )
                if matched:
                    corr_type = "ip_range"
            except ValueError:
                pass

        # ── email ─────────────────────────────────────────────────────────────
        elif atype == "email":
            if ioc_type == "email":
                if av == ioc_lower:
                    matched, corr_type = True, "exact_email"
                elif "@" in av and ioc_lower.endswith("@" + av.split("@")[-1]):
                    matched, corr_type = True, "email_pattern"
            elif ioc_lower.endswith("@" + av.lstrip("*@")):
                matched, corr_type = True, "email_pattern"

        # ── keyword ───────────────────────────────────────────────────────────
        elif atype == "keyword":
            # V16.4.5b: For URL/domain IOCs, keyword must appear in the DOMAIN portion only.
            # Before: "github" keyword matched any URL from a gist mentioning github.
            # After: "github" only matches URLs where github is in the domain.
            if ioc_type in ("url", "uri", "domain", "fqdn"):
                # Only match keyword against the domain portion of the URL
                if ioc_domain and len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_domain):
                    matched, corr_type = True, "keyword"
            else:
                # Non-URL IOCs: word boundary match on full value
                if len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_lower):
                    matched, corr_type = True, "keyword"

        # ── org_name ──────────────────────────────────────────────────────────
        elif atype == "org_name":
            if ioc_type in ("url", "uri", "domain", "fqdn"):
                if ioc_domain and len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_domain):
                    matched, corr_type = True, "keyword"
            else:
                if len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_lower):
                    matched, corr_type = True, "keyword"

        # ── github_org ────────────────────────────────────────────────────────
        elif atype == "github_org":
            # V16.4.5: Must match in a github URL context, not just substring
            if "github.com/" + av in ioc_lower or "github.com/orgs/" + av in ioc_lower:
                matched, corr_type = True, "code_repo"

        # ── tech_stack (V10) ──────────────────────────────────────────────────
        # "FortiOS 7.2" matches CVE description "affects FortiOS versions..."
        elif atype == "tech_stack":
            # Extract product name (first word or two before version)
            product = re.split(r"\s+\d", av)[0].lower()  # "fortiOS" from "FortiOS 7.2"
            if len(product) >= 4 and re.search(r'\b' + re.escape(product) + r'\b', ioc_lower):
                matched, corr_type = True, "tech_stack"

        # ── brand_name (V10) ──────────────────────────────────────────────────
        # "AcmePay" -> match exact + typosquat variants
        elif atype == "brand_name":
            # V16.4.5b: For URL IOCs, only match brand in domain portion
            if ioc_type in ("url", "uri", "domain", "fqdn"):
                if ioc_domain and len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_domain):
                    matched, corr_type = True, "keyword"
                elif ioc_domain:
                    # Check typosquat: is the IOC domain 1-2 edits from the brand?
                    brand_clean = re.sub(r"[^a-z0-9]", "", av)
                    ioc_clean = re.sub(r"[^a-z0-9]", "", ioc_domain.split(".")[0])
                    if len(brand_clean) >= 4 and _simple_edit_distance(brand_clean, ioc_clean) <= 2:
                        matched, corr_type = True, "typosquat"
            else:
                if len(av) >= 4 and re.search(r'\b' + re.escape(av) + r'\b', ioc_lower):
                    matched, corr_type = True, "keyword"
                elif ioc_domain:
                    brand_clean = re.sub(r"[^a-z0-9]", "", av)
                    ioc_clean = re.sub(r"[^a-z0-9]", "", ioc_domain.split(".")[0])
                    if len(brand_clean) >= 4 and _simple_edit_distance(brand_clean, ioc_clean) <= 2:
                        matched, corr_type = True, "typosquat"

        # ── exec_name (V10) ───────────────────────────────────────────────────
        # "John Smith CEO" - match if any 2-word substring of the name is in the IOC
        elif atype == "exec_name":
            name_parts = av.split()
            # Try full name first, then first+last
            if av in ioc_lower:
                matched, corr_type = True, "exec_name"
            elif len(name_parts) >= 2:
                first_last = f"{name_parts[0]} {name_parts[1]}"
                if first_last in ioc_lower:
                    matched, corr_type = True, "exec_name"

        # ── cloud_asset (V10) ─────────────────────────────────────────────────
        elif atype == "cloud_asset":
            if av in ioc_lower or ioc_lower in av:
                matched, corr_type = True, "cloud_asset"

        # ── code_repo (V11) ───────────────────────────────────────────────────
        # "github.com/acme-corp" matches leaked PATs, exposed repo IOCs
        # Also matches org name in GitHub URLs and package names
        elif atype == "code_repo":
            # Extract org/repo from asset: "github.com/acme-corp" -> "acme-corp"
            repo_clean = av.replace("github.com/", "").replace("gitlab.com/", "").strip("/")
            if repo_clean and (repo_clean in ioc_lower or av in ioc_lower):
                matched, corr_type = True, "code_repo"
            # Also match if asset is just an org name and it appears in a GitHub URL
            elif "github.com" in ioc_lower and repo_clean in ioc_lower:
                matched, corr_type = True, "code_repo"

        if matched:
            results.append(RoutedDetection(
                customer_id=asset.customer_id,
                customer_name=asset.customer_name,
                matched_asset_type=atype,
                matched_asset_value=asset.asset_value,
                ioc_value=ioc_value,
                criticality=asset.criticality,
                correlation_type=corr_type,
            ))

    return results
