"""Tests for severity_scorer.py - SLA tiers and auto-override."""
import pytest
from arguswatch.engine.severity_scorer import score, ScoredResult, IOC_SLA_MAP


class TestIOCSLAMap:
    def test_has_entries(self):
        assert len(IOC_SLA_MAP) >= 20

    def test_aws_key_is_critical(self):
        sev, hours, _ = IOC_SLA_MAP["aws_access_key"]
        assert sev == "CRITICAL"
        assert hours <= 4

    def test_stripe_live_is_critical(self):
        sev, hours, _ = IOC_SLA_MAP["stripe_live_key"]
        assert sev == "CRITICAL"


class TestScore:
    def test_returns_scored_result(self):
        result = score(category="cat3", ioc_type="ip_address", confidence=0.9)
        assert isinstance(result, ScoredResult)
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert result.sla_hours > 0

    def test_kev_actively_exploited_upgrades(self):
        result = score(category="cat3", ioc_type="ip_address",
                       confidence=0.95, kev_actively_exploited=True)
        assert result.severity in ("CRITICAL", "HIGH")

    def test_low_confidence(self):
        result = score(category="cat3", ioc_type="domain", confidence=0.15)
        assert result.severity in ("LOW", "MEDIUM")

    def test_api_key_maps_correctly(self):
        result = score(category="cat2", ioc_type="aws_access_key", confidence=0.99)
        assert result.severity == "CRITICAL"
