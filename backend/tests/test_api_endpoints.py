"""Tests for main.py API endpoints - verify routing, status codes, auth."""
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["AUTH_DISABLED"] = "true"

from arguswatch.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


class TestHealthEndpoints:
    def test_root_returns_dashboard(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_health_endpoint(self):
        with patch("arguswatch.main.get_db") as mock:
            db = AsyncMock()
            db.execute = AsyncMock()
            mock.return_value = db
            r = client.get("/health")
            assert r.status_code == 200
            assert "status" in r.json()


class TestAuthEndpoints:
    def test_login_invalid_creds(self):
        r = client.post("/api/auth/login", json={"username": "bad", "password": "bad"})
        assert r.status_code == 401

    def test_login_valid_creds(self):
        r = client.post("/api/auth/login", json={
            "username": os.environ.get("ADMIN_USER", "admin"),
            "password": os.environ.get("ADMIN_PASSWORD", "arguswatch-admin-changeme")
        })
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["role"] == "admin"

    def test_me_with_token(self):
        login = client.post("/api/auth/login", json={
            "username": "admin", "password": "arguswatch-admin-changeme"
        })
        token = login.json()["access_token"]
        r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    def test_me_without_token_auth_disabled(self):
        """AUTH_DISABLED=true should return dev-admin."""
        r = client.get("/api/auth/me")
        assert r.status_code == 200
        assert r.json()["auth_disabled"] is True


class TestStatsEndpoints:
    """Stats endpoints should not error even with empty DB."""

    @pytest.mark.parametrize("path", [
        "/api/stats", "/api/stats/sources", "/api/stats/ioc-types",
        "/api/stats/timeline", "/api/threat-pressure", "/api/metrics",
    ])
    def test_stats_endpoints_exist(self, path):
        """Each stats endpoint should return 200 or 500 (DB not connected), never 404."""
        r = client.get(path)
        assert r.status_code != 404, f"{path} returned 404 - endpoint not registered"


class TestCRUDEndpoints:
    """Verify critical CRUD endpoints are registered."""

    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/findings"),
        ("GET", "/api/actors"),
        ("GET", "/api/campaigns"),
        ("GET", "/api/darkweb"),
        ("GET", "/api/darkweb/stats"),
        ("GET", "/api/exposure/leaderboard"),
        ("GET", "/api/collectors/status"),
        ("GET", "/api/enterprise/status"),
        ("GET", "/api/settings/ai"),
        ("GET", "/api/fp-patterns"),
        ("GET", "/api/sla/breaches"),
        ("GET", "/api/unattributed-intel"),
        ("GET", "/api/sector/advisories"),
    ])
    def test_read_endpoints_registered(self, method, path):
        r = client.request(method, path)
        assert r.status_code != 404, f"{method} {path} returned 404"

    @pytest.mark.parametrize("path", [
        "/api/collect-all",
        "/api/match-intel-all",
        "/api/exposure/recalculate",
        "/api/scan",
    ])
    def test_write_endpoints_registered(self, path):
        r = client.post(path)
        assert r.status_code != 404, f"POST {path} returned 404"


class TestEndpointCount:
    def test_minimum_endpoint_count(self):
        """Architecture promises 90+ endpoints. Verify at least 80 exist."""
        routes = [r.path for r in app.routes if hasattr(r, 'methods')]
        api_routes = [r for r in routes if r.startswith("/api/")]
        assert len(api_routes) >= 80, f"Only {len(api_routes)} API routes found, expected 80+"
