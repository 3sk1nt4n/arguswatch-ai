"""Tests for pattern_matcher.py - IOC regex extraction across 15 categories."""
import pytest
from arguswatch.engine.pattern_matcher import scan_text, IOCMatch


class TestScanText:
    def test_returns_list(self):
        assert isinstance(scan_text("nothing"), list)

    def test_empty_string(self):
        assert scan_text("") == []

    def test_extract_email_password(self):
        results = scan_text("admin@acme.com:P@ssw0rd123!")
        types = [r.ioc_type for r in results]
        assert any("email" in t or "combo" in t or "password" in t for t in types)

    def test_extract_aws_key(self):
        # Using clearly fake test key pattern
        results = scan_text("AKIA" + "TEST" + "FAKE" + "KEY12345" + " is the key")
        types = [r.ioc_type for r in results]
        assert any("aws" in t for t in types)

    def test_extract_github_pat(self):
        # Using clearly fake test token pattern
        test_token = "ghp_" + "X" * 36
        results = scan_text("token = " + test_token)
        types = [r.ioc_type for r in results]
        assert any("github" in t for t in types)

    def test_extract_ipv4(self):
        results = scan_text("callback to 185.220.101.42")
        values = [r.value for r in results]
        assert any("185.220.101.42" in v for v in values)

    def test_extract_sha256(self):
        h = "a" * 64
        results = scan_text(f"Hash: {h}")
        values = [r.value for r in results]
        assert any(h in v for v in values)

    def test_extract_cve(self):
        results = scan_text("Exploit CVE-2024-12345 found")
        values = [r.value for r in results]
        assert any("CVE-2024-12345" in v for v in values)

    def test_extract_private_key(self):
        results = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        types = [r.ioc_type for r in results]
        assert any("key" in t.lower() for t in types)

    def test_result_is_iocmatch(self):
        results = scan_text("admin@evil.com:password123")
        if results:
            assert isinstance(results[0], IOCMatch)
            assert results[0].value
            assert results[0].confidence > 0

    def test_no_fp_normal_text(self):
        assert len(scan_text("The quick brown fox jumped over the lazy dog")) == 0


class TestIOCMatch:
    def test_fields(self):
        m = IOCMatch(category="c1", ioc_type="ip", value="1.2.3.4", context="", confidence=0.9)
        assert m.category == "c1"
        assert m.confidence == 0.9
        assert m.line_number == 0
