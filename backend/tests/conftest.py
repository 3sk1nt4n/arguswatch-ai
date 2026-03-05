"""
ArgusWatch Test Suite - Shared Fixtures
Run: cd backend && pytest tests/ -v
"""
import os
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Force test database and auth disabled
os.environ["AUTH_DISABLED"] = "true"
os.environ["POSTGRES_HOST"] = "localhost"
os.environ["POSTGRES_DB"] = "arguswatch_test"

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db():
    """Mock async database session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.close = AsyncMock()
    db.refresh = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def sample_customer():
    return {
        "id": 1,
        "name": "Acme Corp",
        "primary_domain": "acme.com",
        "industry": "technology",
        "tier": "premium",
        "contact_email": "security@acme.com",
        "onboarding_state": "active",
    }


@pytest.fixture
def sample_detection():
    return {
        "id": 1,
        "ioc_value": "185.220.101.42",
        "ioc_type": "ip_address",
        "source": "threatfox",
        "confidence": 0.85,
        "severity": "high",
        "raw_context": "ThreatFox: Cobalt Strike C2",
        "customer_id": None,
    }


@pytest.fixture
def sample_finding():
    return {
        "id": 1,
        "detection_id": 1,
        "customer_id": 1,
        "ioc_value": "185.220.101.42",
        "ioc_type": "ip_address",
        "severity": "high",
        "source": "threatfox",
        "match_strategy": "S1",
        "confidence": 0.85,
        "status": "open",
        "customer_name": "Acme Corp",
    }


@pytest.fixture
def sample_actor():
    return {
        "id": 1,
        "name": "APT29",
        "country": "Russia",
        "country_flag": "🇷🇺",
        "motivations": "espionage",
        "aliases": "Cozy Bear, The Dukes",
        "description": "Russian state-sponsored APT group",
        "ioc_count": 42,
    }
