"""Tests for stix_exporter.py - STIX 2.1 bundle generation."""
import pytest
import json
from arguswatch.engine.stix_exporter import (
    _stix_pattern, _indicator_type, export_detection_to_stix, bundle_to_json,
)


class TestSTIXPattern:
    def test_ip_pattern(self):
        p = _stix_pattern("ip_address", "1.2.3.4")
        assert "1.2.3.4" in p
        assert "ipv4-addr" in p.lower() or "ip" in p.lower()

    def test_domain_pattern(self):
        p = _stix_pattern("domain", "evil.com")
        assert "evil.com" in p

    def test_hash_pattern(self):
        p = _stix_pattern("hash_sha256", "a" * 64)
        assert "a" * 64 in p


class TestIndicatorType:
    def test_ip(self):
        assert "ipv4" in _indicator_type("ip_address").lower() or "network" in _indicator_type("ip_address").lower()

    def test_domain(self):
        assert "domain" in _indicator_type("domain").lower()


class TestExportDetection:
    def test_export_returns_dict(self):
        det = type("D", (), {
            "id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip_address",
            "source": "threatfox", "confidence": 0.9, "severity": "high",
            "raw_context": "test", "collected_at": None,
        })()
        result = export_detection_to_stix(det)
        assert isinstance(result, dict)
        assert "type" in result or "objects" in result

    def test_bundle_to_json(self):
        det = type("D", (), {
            "id": 2, "ioc_value": "evil.com", "ioc_type": "domain",
            "source": "openphish", "confidence": 0.8, "severity": "medium",
            "raw_context": "", "collected_at": None,
        })()
        d = export_detection_to_stix(det)
        j = bundle_to_json(d)
        assert isinstance(j, str)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)
