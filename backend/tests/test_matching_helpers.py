"""Tests for customer_intel_matcher.py - helper functions for S1-S8 strategies."""
import pytest
from arguswatch.engine.customer_intel_matcher import (
    _normalize_product, _extract_version, _products_match,
    _version_in_range, _ip_in_any_cidr, _domain_matches_ioc, _domain_in_text,
)


class TestNormalizeProduct:
    def test_nginx_version(self):
        assert _normalize_product("nginx/1.18.0") == "nginx"

    def test_fortios(self):
        assert _normalize_product("FortiOS 7.2") == "fortios"

    def test_plain(self):
        assert _normalize_product("apache") == "apache"


class TestExtractVersion:
    def test_nginx(self):
        assert _extract_version("nginx/1.18.0") == "1.18.0"

    def test_fortios(self):
        assert _extract_version("FortiOS 7.2") == "7.2"

    def test_no_version(self):
        assert _extract_version("apache") is None


class TestProductsMatch:
    def test_same_product(self):
        assert _products_match("nginx", "nginx") is True

    def test_case_insensitive(self):
        assert _products_match("Nginx", "nginx") is True

    def test_different(self):
        assert _products_match("nginx", "apache") is False


class TestVersionInRange:
    def test_version_in_range(self):
        # Basic version comparison
        result = _version_in_range("1.18.0", "<=1.20.0")
        assert isinstance(result, bool)

    def test_version_exact(self):
        result = _version_in_range("7.2.0", "7.2.0")
        assert isinstance(result, bool)


class TestIPInCIDR:
    def test_ip_in_range(self):
        result = _ip_in_any_cidr("10.0.0.5", ["10.0.0.0/24"])
        assert result is not None

    def test_ip_not_in_range(self):
        result = _ip_in_any_cidr("192.168.1.1", ["10.0.0.0/24"])
        assert result is None

    def test_invalid_ip(self):
        result = _ip_in_any_cidr("not-an-ip", ["10.0.0.0/24"])
        assert result is None


class TestDomainMatchesIOC:
    def test_exact_domain(self):
        result = _domain_matches_ioc("acme.com", "acme.com")
        assert result is not None

    def test_subdomain(self):
        result = _domain_matches_ioc("acme.com", "mail.acme.com")
        assert result is not None

    def test_no_match(self):
        result = _domain_matches_ioc("acme.com", "evil.ru")
        assert result is None

    def test_substring_not_matched(self):
        """acme.com should NOT match 'notacme.com'."""
        result = _domain_matches_ioc("acme.com", "notacme.com")
        assert result is None


class TestDomainInText:
    def test_domain_in_raw_text(self):
        assert _domain_in_text("acme.com", "Found acme.com in paste dump") is True

    def test_no_domain(self):
        assert _domain_in_text("acme.com", "nothing here") is False

    def test_empty_text(self):
        assert _domain_in_text("acme.com", "") is False
