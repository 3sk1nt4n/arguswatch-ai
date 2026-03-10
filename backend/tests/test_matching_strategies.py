"""v16.4.7 MATCHING STRATEGY AUDIT -  tests every routing strategy with
TRUE POSITIVE (must match) and FALSE POSITIVE (must NOT match) cases.

If any FALSE POSITIVE test fails, the matching engine has a bug that will
route junk to customers.
"""
import pytest
from arguswatch.engine.customer_router import (
    route_to_customers, CustomerAssetRecord, _simple_edit_distance
)

# ── Helper to build asset lists ──────────────────────────────────────────

def _asset(customer_id, name, atype, value, crit="critical"):
    return CustomerAssetRecord(customer_id=customer_id, customer_name=name,
                               asset_type=atype, asset_value=value, criticality=crit)

YAHOO_ASSETS = [
    _asset(1, "Yahoo", "domain", "yahoo.com"),
    _asset(1, "Yahoo", "subdomain", "mail.yahoo.com"),
    _asset(1, "Yahoo", "subdomain", "login.yahoo.com"),
    _asset(1, "Yahoo", "keyword", "yahoo"),
    _asset(1, "Yahoo", "brand_name", "Yahoo"),
]

GITHUB_ASSETS = [
    _asset(2, "GitHub", "domain", "github.com"),
    _asset(2, "GitHub", "keyword", "github"),
    _asset(2, "GitHub", "brand_name", "GitHub"),
]

UBER_ASSETS = [
    _asset(3, "Uber", "domain", "uber.com"),
    _asset(3, "Uber", "keyword", "uber"),
    _asset(3, "Uber", "brand_name", "Uber"),
    _asset(3, "Uber", "exec_name", "dara khosrowshahi"),
    _asset(3, "Uber", "tech_stack", "Kubernetes 1.24"),
    _asset(3, "Uber", "cloud_asset", "uber-prod-bucket.s3.amazonaws.com"),
]

ALL_ASSETS = YAHOO_ASSETS + GITHUB_ASSETS + UBER_ASSETS


def _match_types(ioc_value, ioc_type, assets=None):
    """Returns set of (customer_name, correlation_type) tuples."""
    results = route_to_customers(ioc_value, ioc_type, assets or ALL_ASSETS)
    return {(r.customer_name, r.correlation_type) for r in results}

def _matched_customers(ioc_value, ioc_type, assets=None):
    """Returns set of customer names that matched."""
    results = route_to_customers(ioc_value, ioc_type, assets or ALL_ASSETS)
    return {r.customer_name for r in results}


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 1: EXACT DOMAIN
# ══════════════════════════════════════════════════════════════════════════

class TestExactDomain:
    def test_tp_exact_domain(self):
        """yahoo.com domain IOC -> matches Yahoo"""
        assert ("Yahoo", "exact_domain") in _match_types("yahoo.com", "domain")

    def test_tp_url_with_domain(self):
        """URL containing yahoo.com -> matches Yahoo via exact_domain"""
        assert ("Yahoo", "exact_domain") in _match_types("https://yahoo.com/login", "url")

    def test_fp_similar_domain_not_exact(self):
        """yahooo.com is NOT yahoo.com -  should not match as exact_domain"""
        matches = _match_types("yahooo.com", "domain")
        assert ("Yahoo", "exact_domain") not in matches

    def test_fp_domain_substring(self):
        """notyahoo.com contains 'yahoo' but is a different domain"""
        matches = _match_types("notyahoo.com", "domain")
        # Should NOT match as exact_domain
        assert ("Yahoo", "exact_domain") not in matches


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 2: SUBDOMAIN
# ══════════════════════════════════════════════════════════════════════════

class TestSubdomain:
    def test_tp_subdomain_of_customer(self):
        """phishing.yahoo.com is a subdomain of yahoo.com"""
        assert "Yahoo" in _matched_customers("phishing.yahoo.com", "domain")

    def test_tp_deep_subdomain(self):
        """a.b.yahoo.com still ends with .yahoo.com"""
        assert "Yahoo" in _matched_customers("a.b.yahoo.com", "domain")

    def test_tp_phishing_subdomain_pattern(self):
        """yahoo.com.evil.com IS a phishing domain targeting Yahoo -  should match via brand"""
        assert "Yahoo" in _matched_customers("yahoo.com.evil.com", "domain")

    def test_fp_truly_unrelated_domain(self):
        """totallyunrelated.xyz has no connection to Yahoo"""
        assert "Yahoo" not in _matched_customers("totallyunrelated.xyz", "domain")

    def test_fp_partial_overlap(self):
        """fakeyahoo.com ends with yahoo.com but no dot separator"""
        assert ("Yahoo", "exact_domain") not in _match_types("fakeyahoo.com", "domain")


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 3: DOMAIN_ONLY GUARD (critical FP defense)
# ══════════════════════════════════════════════════════════════════════════

class TestDomainOnlyGuard:
    """URLs and domains must ONLY match on domain/subdomain assets,
    NEVER on keyword or brand_name. This was the #1 source of FPs before v16.4.5."""

    def test_fp_url_must_not_match_keyword(self):
        """A URL from a github gist about cooking should NOT match GitHub
        just because 'github' is a keyword."""
        # This URL is hosted on example.com, not github.com
        matches = _matched_customers("https://example.com/recipe?ref=github", "url")
        assert "GitHub" not in matches

    def test_fp_url_from_gist_random_domain(self):
        """hostingmalaya.com URL found in a github gist must NOT route to GitHub"""
        matches = _matched_customers("https://hostingmalaya.com/admin", "url")
        assert "GitHub" not in matches

    def test_fp_domain_must_not_match_brand(self):
        """ubereats-promo.com domain: 'uber' brand is substring but domain doesn't match"""
        matches = _match_types("ubereats-promo-discount-codes.com", "domain")
        # Should NOT match as keyword. Might match as typosquat if edit distance ≤ 2
        assert ("Uber", "keyword") not in matches

    def test_tp_url_on_actual_domain(self):
        """URL on the actual customer domain SHOULD match"""
        assert "Yahoo" in _matched_customers("https://yahoo.com/hacked", "url")

    def test_tp_url_on_subdomain(self):
        """URL on customer subdomain SHOULD match"""
        assert "Yahoo" in _matched_customers("https://mail.yahoo.com/inbox", "url")


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 4: KEYWORD (word boundary)
# ══════════════════════════════════════════════════════════════════════════

class TestKeyword:
    def test_tp_keyword_in_credential(self):
        """admin@yahoo.com:password -> keyword 'yahoo' in email, not a URL"""
        # email_password_combo is not in DOMAIN_ONLY_IOC_TYPES
        matches = _matched_customers("admin@yahoo.com:password123", "email_password_combo")
        assert "Yahoo" in matches

    def test_tp_keyword_in_hash_context(self):
        """CVE description mentioning 'uber' -> keyword match for non-URL type"""
        matches = _matched_customers("uber driver credentials leaked", "data_leak")
        assert "Uber" in matches

    def test_fp_keyword_too_short(self):
        """Keywords under 4 chars should be skipped (too many false positives)"""
        short_assets = [_asset(99, "Test", "keyword", "aws")]
        matches = route_to_customers("aws credentials found", "data_leak", short_assets)
        assert len(matches) == 0

    def test_fp_keyword_partial_word(self):
        """'uber' should NOT match 'ubermensch' or 'tuberous' via word boundary"""
        matches = _matched_customers("tuberous plant found", "data_leak")
        assert "Uber" not in matches

    def test_fp_url_keyword_not_in_domain(self):
        """URL with 'yahoo' in the PATH but not domain should NOT match"""
        matches = _matched_customers("https://evil.com/yahoo-phish", "url")
        assert "Yahoo" not in matches


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 5: BRAND + TYPOSQUAT
# ══════════════════════════════════════════════════════════════════════════

class TestBrandTyposquat:
    def test_tp_typosquat_1_edit(self):
        """yaho0.com is 1 edit from yahoo -> typosquat"""
        matches = _match_types("yaho0.com", "domain")
        assert ("Yahoo", "typosquat") in matches

    def test_tp_typosquat_2_edits(self):
        """yah00.com is 2 edits from yahoo -> typosquat"""
        matches = _match_types("yah00.com", "domain")
        assert ("Yahoo", "typosquat") in matches

    def test_fp_typosquat_3_edits(self):
        """ya000.com is 3 edits from yahoo -> should NOT match"""
        matches = _match_types("ya000.com", "domain")
        assert ("Yahoo", "typosquat") not in matches

    def test_fp_completely_different_domain(self):
        """google.com should not typosquat-match yahoo"""
        matches = _match_types("google.com", "domain")
        assert "Yahoo" not in _matched_customers("google.com", "domain")

    def test_edit_distance_basic(self):
        assert _simple_edit_distance("yahoo", "yaho0") == 1
        assert _simple_edit_distance("yahoo", "yah00") == 2
        assert _simple_edit_distance("yahoo", "google") >= 4


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 6: TECH_STACK
# ══════════════════════════════════════════════════════════════════════════

class TestTechStack:
    def test_tp_product_in_cve_text(self):
        """CVE mentioning 'kubernetes' matches Uber's tech_stack 'Kubernetes 1.24'"""
        matches = _matched_customers(
            "kubernetes api server allows privilege escalation", "cve_id",
            UBER_ASSETS
        )
        assert "Uber" in matches

    def test_fp_short_product_name(self):
        """Product name < 4 chars should not match (too generic)"""
        short_assets = [_asset(99, "Test", "tech_stack", "Go 1.21")]
        matches = route_to_customers("memory corruption in golang", "cve_id", short_assets)
        # "go" is only 2 chars, should be skipped
        assert len(matches) == 0

    def test_fp_product_substring_in_unrelated(self):
        """'redis' should not match 'redistribution' via substring"""
        redis_assets = [_asset(99, "Test", "tech_stack", "Redis 7.0")]
        matches = route_to_customers("redistribution of copyrighted material", "advisory", redis_assets)
        assert len(matches) == 0


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 7: EXEC_NAME
# ══════════════════════════════════════════════════════════════════════════

class TestExecName:
    def test_tp_full_name(self):
        """Full exec name in leak text"""
        matches = _matched_customers(
            "credentials for dara khosrowshahi leaked", "credential_combo",
            UBER_ASSETS
        )
        assert "Uber" in matches

    def test_fp_partial_first_name_only(self):
        """Just 'dara' should NOT match -  too common"""
        matches = _matched_customers("dara is a common name", "data_leak", UBER_ASSETS)
        # exec_name splits to ["dara", "khosrowshahi"], tries "dara khosrowshahi"
        # Just "dara" alone should not trigger exec_name match
        assert ("Uber", "exec_name") not in _match_types("dara is a common name", "data_leak", UBER_ASSETS)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 8: CLOUD_ASSET
# ══════════════════════════════════════════════════════════════════════════

class TestCloudAsset:
    def test_tp_exact_bucket(self):
        """Exact S3 bucket URL match"""
        matches = _matched_customers(
            "uber-prod-bucket.s3.amazonaws.com", "url",
            UBER_ASSETS
        )
        assert "Uber" in matches

    def test_fp_different_bucket(self):
        """A different S3 bucket should NOT match Uber's cloud asset"""
        matches = _matched_customers(
            "random-bucket.s3.amazonaws.com", "url",
            UBER_ASSETS
        )
        assert "Uber" not in matches


# ══════════════════════════════════════════════════════════════════════════
# CROSS-CUSTOMER ISOLATION
# ══════════════════════════════════════════════════════════════════════════

class TestCrossCustomerIsolation:
    """IOCs must route to the CORRECT customer only, not multiple."""

    def test_yahoo_ioc_only_matches_yahoo(self):
        """yahoo.com IOC should match Yahoo, not GitHub or Uber"""
        customers = _matched_customers("yahoo.com", "domain")
        assert customers == {"Yahoo"}

    def test_github_url_only_matches_github(self):
        """github.com URL should match GitHub, not Yahoo or Uber"""
        customers = _matched_customers("https://github.com/exploit", "url")
        assert customers == {"GitHub"}

    def test_random_ioc_matches_nobody(self):
        """Completely unrelated IOC should match zero customers"""
        customers = _matched_customers("185.220.101.42", "ipv4")
        assert len(customers) == 0

    def test_random_domain_matches_nobody(self):
        """Unrelated domain should match zero customers"""
        customers = _matched_customers("totallyunrelated.xyz", "domain")
        assert len(customers) == 0
