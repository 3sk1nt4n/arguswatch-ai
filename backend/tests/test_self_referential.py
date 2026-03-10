"""v16.4.7 onboarding + routing safety tests."""
import re
import pytest

# ── Self-referential exclusion logic (mirrors correlation_engine.py) ──

_COLLECTOR_PLATFORMS = {
    "github_gist":  {"github.com", "gist.github.com", "githubusercontent.com"},
    "grep_app":     {"github.com", "gist.github.com", "githubusercontent.com"},
    "paste":        {"pastebin.com", "dpaste.org", "rentry.co"},
}

def _is_self_referential(ioc_value, ioc_type, source, customer_domains):
    """Should this IOC be excluded from routing to this customer?"""
    if ioc_type not in ("url", "uri", "domain", "fqdn", "hostname"):
        return False
    src_platforms = _COLLECTOR_PLATFORMS.get(source, set())
    if not src_platforms:
        return False
    m = re.search(r'https?://([^/?\s:]+)', ioc_value.lower())
    ioc_dom = m.group(1) if m else ioc_value.lower()
    on_platform = any(ioc_dom == p or ioc_dom.endswith("." + p) for p in src_platforms)
    if not on_platform:
        return False
    return any(p == cd or p.endswith("." + cd) for p in src_platforms for cd in customer_domains)


class TestSelfReferentialExclusion:
    """IOCs found ON a platform must not route back TO that platform as victim."""

    def test_gist_url_skipped_for_github(self):
        assert _is_self_referential(
            "https://gist.github.com/user/abc123", "url", "github_gist", {"github.com"})

    def test_raw_githubusercontent_skipped(self):
        assert _is_self_referential(
            "https://raw.githubusercontent.com/evil/malware/main/x.py", "url", "github_gist", {"github.com"})

    def test_grep_app_github_skipped(self):
        assert _is_self_referential(
            "https://gist.github.com/test/keys", "url", "grep_app", {"github.com"})

    def test_phishing_url_kept(self):
        """Phishing URL targeting GitHub from openphish -  real threat, keep it."""
        assert not _is_self_referential(
            "https://evil-phishing.com/github-login", "url", "openphish", {"github.com"})

    def test_gist_url_kept_for_yahoo(self):
        """Gist URL found for Yahoo customer -  Yahoo doesn't own GitHub."""
        assert not _is_self_referential(
            "https://gist.github.com/hacker/creds", "url", "github_gist", {"yahoo.com"})

    def test_ip_ioc_never_self_referential(self):
        assert not _is_self_referential("185.220.101.42", "ipv4", "feodo", {"github.com"})

    def test_cve_never_self_referential(self):
        assert not _is_self_referential("CVE-2024-1234", "cve_id", "nvd", {"github.com"})

    def test_paypal_url_from_gist_not_self_ref(self):
        """PayPal URL found in gist -  PayPal doesn't own GitHub."""
        assert not _is_self_referential(
            "https://paypal.com/help", "url", "github_gist", {"paypal.com"})

    def test_pastebin_url_skipped_for_pastebin(self):
        assert _is_self_referential(
            "https://pastebin.com/raw/abc123", "url", "paste", {"pastebin.com"})
