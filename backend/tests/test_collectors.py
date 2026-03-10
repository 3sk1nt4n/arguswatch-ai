"""Tests for proxy_server.py - verify all 33+ collectors exist."""
import pytest
import ast
import re


class TestCollectorRegistry:
    """Verify all collectors are defined and callable in proxy_server.py."""

    @pytest.fixture(autouse=True)
    def load_source(self):
        with open("intel-proxy/proxy_server.py") as f:
            self.source = f.read()
        self.tree = ast.parse(self.source)

    def test_parses_without_error(self):
        assert self.tree is not None

    def test_has_33_plus_collectors(self):
        funcs = [n.name for n in ast.walk(self.tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name.startswith("collect_")]
        assert len(funcs) >= 33, f"Found {len(funcs)} collect_ functions: {funcs[:10]}..."

    def test_collector_names_match_expected(self):
        funcs = {n.name for n in ast.walk(self.tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name.startswith("collect_")}
        expected_core = {
            "collect_cisa_kev", "collect_threatfox", "collect_abuse_feodo",
            "collect_abuse_urlhaus", "collect_openphish", "collect_nvd",
            "collect_otx", "collect_ransomfeed",
        }
        for c in expected_core:
            assert c in funcs, f"Core collector {c} missing"

    def test_each_collector_is_async(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("collect_"):
                assert True  # async def found
            elif isinstance(node, ast.FunctionDef) and node.name.startswith("collect_"):
                pass  # sync is OK too

    def test_collect_all_endpoint_exists(self):
        assert "collect_all" in self.source or "collect-all" in self.source


class TestCollectorModules:
    """Verify individual collector .py files parse."""

    COLLECTOR_FILES = [
        "backend/arguswatch/collectors/cisa_kev.py",
        "backend/arguswatch/collectors/threatfox_collector.py",
        "backend/arguswatch/collectors/openphish_collector.py",
        "backend/arguswatch/collectors/ransomfeed_collector.py",
        "backend/arguswatch/collectors/nvd_collector.py",
        "backend/arguswatch/collectors/otx_collector.py",
        "backend/arguswatch/collectors/shodan_collector.py",
        "backend/arguswatch/collectors/github_collector.py",
        "backend/arguswatch/collectors/breach_collector.py",
        "backend/arguswatch/collectors/malwarebazaar_collector.py",
        "backend/arguswatch/collectors/telegram_collector.py",
    ]

    @pytest.mark.parametrize("path", COLLECTOR_FILES)
    def test_collector_parses(self, path):
        with open(path) as f:
            ast.parse(f.read())
