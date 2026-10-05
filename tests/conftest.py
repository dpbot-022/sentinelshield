import pytest
from starlette.testclient import TestClient
from sentinelshield.main import app
from sentinelshield.auth.jwt_handler import create_access_token


@pytest.fixture
def admin_token():
    return create_access_token({"sub": "admin", "username": "admin", "role": "admin", "tier": "admin"})


@pytest.fixture
def tier2_token():
    return create_access_token({"sub": "developer", "username": "developer", "role": "developer", "tier": "tier-2"})


@pytest.fixture
def tier1_token():
    return create_access_token({"sub": "client_app", "username": "client_app", "role": "service", "tier": "tier-1"})


@pytest.fixture
def guest_token():
    return create_access_token({"sub": "guest", "username": "guest", "role": "guest", "tier": "guest"})


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
