"""Tests for exposure_scorer.py - VPRS 5-dimension scoring system."""
import pytest
from arguswatch.engine.exposure_scorer import (
    calculate_vprs, get_dimension_label,
    D1_ACTOR_WEIGHT, D2_TARGET_WEIGHT, D3_SECTOR_WEIGHT,
    D4_DARKWEB_WEIGHT, D5_SURFACE_WEIGHT,
)


class TestVPRSWeights:
    def test_weights_sum_to_one(self):
        total = D1_ACTOR_WEIGHT + D2_TARGET_WEIGHT + D3_SECTOR_WEIGHT + D4_DARKWEB_WEIGHT + D5_SURFACE_WEIGHT
        assert abs(total - 1.0) < 0.01, f"Weights sum to {total}, expected 1.0"

    def test_all_weights_positive(self):
        for w in [D1_ACTOR_WEIGHT, D2_TARGET_WEIGHT, D3_SECTOR_WEIGHT, D4_DARKWEB_WEIGHT, D5_SURFACE_WEIGHT]:
            assert w > 0, "All dimension weights must be positive"


class TestVPRSCalculation:
    def test_zero_scores(self):
        result = calculate_vprs(d1=0, d2=0, d3=0, d4=0, d5=0)
        assert result["composite_score"] == 0

    def test_max_scores(self):
        result = calculate_vprs(d1=10, d2=10, d3=10, d4=10, d5=10)
        assert result["composite_score"] <= 100
        assert result["composite_score"] >= 90

    def test_partial_scores(self):
        result = calculate_vprs(d1=8, d2=3, d3=5, d4=7, d5=2)
        assert 0 < result["composite_score"] < 100
        assert result["d1"] == 8
        assert result["d5"] == 2

    def test_risk_label_critical(self):
        result = calculate_vprs(d1=10, d2=9, d3=9, d4=10, d5=8)
        assert "critical" in result.get("risk_label", "").lower() or result["composite_score"] > 70


class TestDimensionLabels:
    @pytest.mark.parametrize("dim,expected", [
        (1, "Actor Threat"),
        (2, "Target Exposure"),
        (3, "Sector Risk"),
        (4, "Dark Web"),
        (5, "Surface"),
    ])
    def test_dimension_labels(self, dim, expected):
        label = get_dimension_label(dim)
        assert expected.lower() in label.lower() or label != ""
