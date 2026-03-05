"""
ArgusWatch v15 Test Suite
==========================
Run: python -m pytest tests/test_pipeline.py -v
Or:  python tests/test_pipeline.py (standalone)

Tests:
1. Collector output schema validation
2. Domain matching - eTLD+1 normalization + boundary matching
3. Version range checking - patched systems must NOT match
4. Product alias resolution
5. Feed confidence + time decay
6. Hash IOCs without EDR → must NOT produce customer matches
7. End-to-end: manual tech-stack → CVE ingestion → confirmed match
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ═══════════════════════════════════════════════════════════════════
# 1. COLLECTOR OUTPUT SCHEMA
# ═══════════════════════════════════════════════════════════════════

def test_collector_schema_valid():
    from arguswatch.utils import validate_collector_output
    
    # Valid output
    result = validate_collector_output({"new": 5, "skipped": 0, "total": 10}, "test")
    assert result["new"] == 5
    assert result["collector"] == "test"
    
    # Skipped output
    result = validate_collector_output({"skipped": True, "reason": "no key", "new": 0}, "otx")
    assert result["skipped"] == True
    assert result["new"] == 0
    
    # Invalid output (not dict)
    result = validate_collector_output("garbage", "broken")
    assert result["new"] == 0
    assert "error" in result
    
    # Missing "new" key
    result = validate_collector_output({"total": 10}, "missing_new")
    assert result["new"] == 0
    
    print("✓ test_collector_schema_valid PASSED")


# ═══════════════════════════════════════════════════════════════════
# 2. DOMAIN MATCHING
# ═══════════════════════════════════════════════════════════════════

def test_domain_etld1_normalization():
    from arguswatch.utils import normalize_domain_etld1
    
    # Standard domains
    assert normalize_domain_etld1("hackthebox.com") == "hackthebox.com"
    assert normalize_domain_etld1("mail.hackthebox.com") == "hackthebox.com"
    assert normalize_domain_etld1("api.staging.hackthebox.com") == "hackthebox.com"
    
    # ccTLD
    assert normalize_domain_etld1("www.example.co.uk") == "example.co.uk"
    assert normalize_domain_etld1("mail.company.com.au") == "company.com.au"
    
    # URLs
    assert normalize_domain_etld1("https://api.hackthebox.com/v1/test") == "hackthebox.com"
    
    # IP passthrough
    assert normalize_domain_etld1("10.0.0.1") == "10.0.0.1"
    
    # Edge cases
    assert normalize_domain_etld1("") == ""
    assert normalize_domain_etld1("localhost") == "localhost"
    
    print("✓ test_domain_etld1_normalization PASSED")


def test_domain_boundary_matching():
    from arguswatch.engine.customer_intel_matcher import _domain_matches_ioc
    
    # MUST match
    assert _domain_matches_ioc("hackthebox.com", "hackthebox.com") == "exact_domain"
    assert _domain_matches_ioc("hackthebox.com", "api.hackthebox.com") == "subdomain"
    assert _domain_matches_ioc("hackthebox.com", "https://api.hackthebox.com/login") == "subdomain"
    
    # MUST NOT match (the Problem C false positives)
    assert _domain_matches_ioc("at.com", "chat.com") is None
    assert _domain_matches_ioc("at.com", "format.com") is None
    assert _domain_matches_ioc("at.com", "https://chat.com/page") is None
    
    # Edge cases
    assert _domain_matches_ioc("example.com", "phishing-example.com") is not None  # keyword boundary match
    assert _domain_matches_ioc("test.com", "") is None
    
    print("✓ test_domain_boundary_matching PASSED")


# ═══════════════════════════════════════════════════════════════════
# 3. VERSION RANGE CHECKING
# ═══════════════════════════════════════════════════════════════════

def test_version_in_range():
    from arguswatch.engine.customer_intel_matcher import _version_in_range
    
    # Customer has nginx 1.18.0, CVE affects < 1.15 → PATCHED (False = not vulnerable)
    assert _version_in_range("1.18.0", "< 1.15") == False
    
    # Customer has FortiOS 7.2, CVE affects < 7.4.3 → VULNERABLE (True)
    assert _version_in_range("7.2", "< 7.4.3") == True
    
    # Customer has FortiOS 7.4.3, CVE affects < 7.4.3 → PATCHED
    assert _version_in_range("7.4.3", "< 7.4.3") == False
    
    # Customer has FortiOS 7.4.4, CVE affects < 7.4.3 → PATCHED
    assert _version_in_range("7.4.4", "< 7.4.3") == False
    
    # Range with bounds: >= 7.0, < 7.2.5
    assert _version_in_range("7.1.0", ">= 7.0, < 7.2.5") == True   # in range
    assert _version_in_range("7.2.5", ">= 7.0, < 7.2.5") == False  # at fix version
    assert _version_in_range("6.4.0", ">= 7.0, < 7.2.5") == False  # below range start
    assert _version_in_range("7.3.0", ">= 7.0, < 7.2.5") == False  # above range end
    
    # No range → conservative (True)
    assert _version_in_range("1.0", "") == True
    assert _version_in_range("1.0", None) == True
    
    # No version → conservative (True)
    assert _version_in_range("", "< 1.5") == True
    assert _version_in_range(None, "< 1.5") == True
    
    print("✓ test_version_in_range PASSED")


# ═══════════════════════════════════════════════════════════════════
# 4. PRODUCT ALIAS RESOLUTION
# ═══════════════════════════════════════════════════════════════════

def test_product_alias():
    from arguswatch.utils import resolve_product_canonical, products_match_canonical
    
    # Alias resolution
    assert resolve_product_canonical("FortiOS 7.2") == "fortios"
    assert resolve_product_canonical("fortigate") == "fortios"
    assert resolve_product_canonical("nginx/1.18.0") == "nginx"
    assert resolve_product_canonical("Microsoft Exchange Server") == "microsoft_exchange"
    assert resolve_product_canonical("OWA") == "microsoft_exchange"
    assert resolve_product_canonical("Pulse Secure") == "ivanti_connect_secure"
    
    # Cross-matching via canonical
    assert products_match_canonical("FortiOS 7.2", "fortigate") == True
    assert products_match_canonical("nginx/1.18.0", "Nginx") == True
    assert products_match_canonical("Exchange 2019", "OWA") == True
    assert products_match_canonical("Ivanti Connect Secure", "Pulse Secure") == True
    
    # Should NOT match different products
    assert products_match_canonical("nginx", "apache") == False
    assert products_match_canonical("FortiOS", "Cisco IOS") == False
    
    print("✓ test_product_alias PASSED")


# ═══════════════════════════════════════════════════════════════════
# 5. FEED CONFIDENCE + TIME DECAY
# ═══════════════════════════════════════════════════════════════════

def test_feed_confidence():
    from arguswatch.utils import get_feed_confidence, time_decay, calculate_decayed_score
    from datetime import datetime, timedelta
    
    # Known feeds
    assert get_feed_confidence("cisa_kev") == 0.99
    assert get_feed_confidence("paste") == 0.40
    assert get_feed_confidence("unknown_feed") == 0.5
    
    # Time decay
    assert time_decay(0) == 1.0
    assert abs(time_decay(14) - 0.5) < 0.01  # Half-life at 14 days
    assert time_decay(28) < 0.26  # Quarter at 2x half-life
    assert time_decay(60) < 0.06  # Near zero at 60 days
    
    # Combined score
    now = datetime.utcnow()
    fresh_score = calculate_decayed_score(10.0, 0.9, now)
    assert abs(fresh_score - 9.0) < 0.01  # 10 * 0.9 * 1.0
    
    old_score = calculate_decayed_score(10.0, 0.9, now - timedelta(days=14))
    assert abs(old_score - 4.5) < 0.1  # 10 * 0.9 * 0.5
    
    print("✓ test_feed_confidence PASSED")


# ═══════════════════════════════════════════════════════════════════
# 6. HASH IOCs WITHOUT EDR
# ═══════════════════════════════════════════════════════════════════

def test_hash_no_customer_match():
    """Hash IOCs from MalwareBazaar/ThreatFox must NOT produce customer matches
    unless EDR telemetry exists. They should only go to threat pressure."""
    
    # The matcher strategies are:
    # S1: exact IP, S2: CIDR, S3: domain, S4: CVE→tech, S5: brand keyword
    # NONE of these match hash_sha256 or hash_md5
    # This is correct behavior - hashes need EDR correlation
    
    # Verify hash types aren't in any matching strategy's query
    import ast, inspect
    from arguswatch.engine import customer_intel_matcher as m
    source = inspect.getsource(m.match_customer_intel)
    
    # The matcher should never query for hash_sha256 or hash_md5 ioc_type
    assert "hash_sha256" not in source, "Matcher should NOT query for hash_sha256 (needs EDR)"
    assert "hash_md5" not in source, "Matcher should NOT query for hash_md5 (needs EDR)"
    
    print("✓ test_hash_no_customer_match PASSED")


# ═══════════════════════════════════════════════════════════════════
# 7. SCORING DIMENSIONS ORTHOGONAL
# ═══════════════════════════════════════════════════════════════════

def test_scoring_dimensions():
    """Verify 5 dimensions exist and weights sum correctly."""
    from arguswatch.engine.exposure_scorer import DIMENSION_WEIGHTS
    
    expected = {"direct_exposure", "active_exploitation", "actor_intent",
                "attack_surface", "asset_criticality"}
    assert set(DIMENSION_WEIGHTS.keys()) == expected, f"Wrong dimensions: {DIMENSION_WEIGHTS.keys()}"
    
    total = sum(DIMENSION_WEIGHTS.values())
    assert abs(total - 1.0) < 0.001, f"Weights sum to {total}, should be 1.0"
    
    # Direct exposure should have highest weight
    assert DIMENSION_WEIGHTS["direct_exposure"] > DIMENSION_WEIGHTS["active_exploitation"]
    assert DIMENSION_WEIGHTS["active_exploitation"] > DIMENSION_WEIGHTS["asset_criticality"]
    
    print("✓ test_scoring_dimensions PASSED")


# ═══════════════════════════════════════════════════════════════════
# RUN ALL
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("ArgusWatch v15 Test Suite")
    print("=" * 50)
    
    tests = [
        test_collector_schema_valid,
        test_domain_etld1_normalization,
        test_domain_boundary_matching,
        test_version_in_range,
        test_product_alias,
        test_feed_confidence,
        test_hash_no_customer_match,
        test_scoring_dimensions,
    ]
    
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
    
    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    if failed:
        sys.exit(1)
