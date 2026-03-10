"""Tests for models.py - verify all 25 ORM models."""
import pytest
from sqlalchemy import inspect
from arguswatch.models import (
    Base, Detection, Customer, CustomerAsset, ThreatActor, Finding,
    CustomerExposure, DarkWebMention, CollectorRun, Enrichment, Campaign,
    CampaignFinding, ActorIOC, RemediationAction, FPPattern, SectorAdvisory,
    ProductAlias, EdrTelemetry,
)


class TestModelDefinitions:
    """Verify all models have correct tablenames and required columns."""

    EXPECTED_TABLES = [
        "detections", "customers", "customer_assets", "threat_actors",
        "findings", "customer_exposure", "dark_web_mentions", "collector_runs",
        "enrichments", "campaigns", "campaign_findings", "actor_iocs",
        "ai_analysis_log", "agent_tool_log", "ai_provider_state",
        "escalation_log", "remediation_actions", "sla_tracking",
        "exposure_snapshots", "fp_patterns", "sector_advisories",
        "alert_log", "ingest_log", "product_aliases", "edr_telemetry",
    ]

    def test_all_25_tables_registered(self):
        """Base.metadata must know about all 25 tables."""
        table_names = set(Base.metadata.tables.keys())
        for t in self.EXPECTED_TABLES:
            assert t in table_names, f"Table '{t}' missing from Base.metadata"

    def test_total_table_count(self):
        assert len(Base.metadata.tables) >= 25

    def test_detection_has_ioc_fields(self):
        cols = {c.name for c in Detection.__table__.columns}
        assert "ioc_value" in cols
        assert "ioc_type" in cols
        assert "source" in cols
        assert "severity" in cols
        assert "confidence" in cols

    def test_customer_has_required_fields(self):
        cols = {c.name for c in Customer.__table__.columns}
        assert "name" in cols
        assert "primary_domain" in cols
        assert "industry" in cols
        assert "tier" in cols

    def test_finding_has_match_fields(self):
        cols = {c.name for c in Finding.__table__.columns}
        assert "detection_id" in cols
        assert "customer_id" in cols
        assert "match_strategy" in cols
        assert "confidence" in cols
        assert "ai_narrative" in cols
        assert "match_proof" in cols

    def test_product_alias_fields(self):
        cols = {c.name for c in ProductAlias.__table__.columns}
        assert "alias" in cols
        assert "canonical" in cols
        assert "vendor" in cols

    def test_edr_telemetry_fields(self):
        cols = {c.name for c in EdrTelemetry.__table__.columns}
        assert "customer_id" in cols
        assert "hash_sha256" in cols
        assert "hash_md5" in cols
        assert "hostname" in cols
        assert "process_name" in cols

    def test_exposure_has_d1_through_d5(self):
        cols = {c.name for c in CustomerExposure.__table__.columns}
        for d in ["d1_actor_threat", "d2_target_value", "d3_sector_risk",
                   "d4_darkweb_presence", "d5_surface_exposure"]:
            assert d in cols, f"Exposure dimension '{d}' missing"

    def test_campaign_fields(self):
        cols = {c.name for c in Campaign.__table__.columns}
        assert "name" in cols
        assert "severity" in cols
        assert "narrative" in cols

    def test_sector_advisory_fields(self):
        cols = {c.name for c in SectorAdvisory.__table__.columns}
        assert "affected_customer_count" in cols
        assert "ai_narrative" in cols
        assert "classification" in cols

    def test_fp_pattern_fields(self):
        cols = {c.name for c in FPPattern.__table__.columns}
        assert "pattern_hash" in cols
        assert "auto_close_count" in cols
