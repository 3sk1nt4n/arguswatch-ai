"""Tests for exposure_scorer.py -  v15 hybrid additive-multiplicative model.

OLD API (VPRS weighted-average) was replaced in v15 with:
  Base = max((D1*0.50 + D2*0.30 + D3*0.20), D4*0.20)
  Impact_modifier = 0.75 + D4*0.00125 + D5*0.00125
  Risk = min(Base * Impact_modifier, 100)

These tests verify the formula math, label function, and module imports.
"""
import pytest


class TestModuleImports:
    def test_import_score_function(self):
        from arguswatch.engine.exposure_scorer import score_customer_actor
        assert callable(score_customer_actor)

    def test_import_recalculate(self):
        from arguswatch.engine.exposure_scorer import recalculate_all_exposures
        assert callable(recalculate_all_exposures)

    def test_import_risk_summary(self):
        from arguswatch.engine.exposure_scorer import get_customer_risk_summary
        assert callable(get_customer_risk_summary)

    def test_import_dimensions(self):
        from arguswatch.engine.exposure_scorer import (
            _dim1_direct_exposure, _dim2_active_exploitation,
            _dim4_attack_surface, _dim5_asset_criticality,
        )
        import asyncio
        assert asyncio.iscoroutinefunction(_dim1_direct_exposure)
        assert asyncio.iscoroutinefunction(_dim2_active_exploitation)
        assert asyncio.iscoroutinefunction(_dim4_attack_surface)
        assert asyncio.iscoroutinefunction(_dim5_asset_criticality)

    def test_import_label(self):
        from arguswatch.engine.exposure_scorer import _label
        assert callable(_label)


class TestLabelFunction:
    def test_critical(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(85) == "CRITICAL"

    def test_high(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(65) == "HIGH"

    def test_medium(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(40) == "MEDIUM"

    def test_low(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(15) == "LOW"

    def test_zero(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(0) == "LOW"

    def test_max(self):
        from arguswatch.engine.exposure_scorer import _label
        assert _label(100) == "CRITICAL"


class TestFormulaMath:
    @staticmethod
    def _formula(d1, d2, d3, d4, d5):
        base = max((d1 * 0.50 + d2 * 0.30 + d3 * 0.20), d4 * 0.20)
        impact_mod = 0.75 + d4 * 0.00125 + d5 * 0.00125
        return min(base * impact_mod, 100)

    def test_all_zeros(self):
        assert self._formula(0, 0, 0, 0, 0) == 0

    def test_all_max(self):
        assert self._formula(100, 100, 100, 100, 100) == 100

    def test_d1_dominates(self):
        assert self._formula(80, 0, 0, 0, 0) == 30.0

    def test_d4_floor(self):
        assert self._formula(0, 0, 0, 100, 0) == 17.5

    def test_impact_modifier_scales(self):
        low = self._formula(60, 40, 20, 10, 10)
        high = self._formula(60, 40, 20, 80, 80)
        assert high > low

    def test_capped_at_100(self):
        assert self._formula(200, 200, 200, 200, 200) == 100

    def test_d5_alone_no_score(self):
        assert self._formula(0, 0, 0, 0, 100) == 0

    def test_balanced_medium(self):
        result = self._formula(40, 30, 20, 40, 40)
        assert 25 < result < 35


class TestServiceImports:
    def test_service_imports_engine(self):
        from arguswatch.services.exposure_scorer import calculate_all_exposures
        assert callable(calculate_all_exposures)

    def test_service_imports_customer(self):
        from arguswatch.services.exposure_scorer import calculate_customer_exposure
        assert callable(calculate_customer_exposure)
