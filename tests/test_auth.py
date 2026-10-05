import pytest
from sentinelshield.auth.jwt_handler import decode_access_token, require_tier
from fastapi import HTTPException


def test_auth_login_success(client):
    response = client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": "SentinelAdmin2026!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user_info"]["role"] == "admin"
    assert data["user_info"]["tier"] == "admin"

    payload = decode_access_token(data["access_token"])
    assert payload["sub"] == "admin"


def test_auth_login_invalid_password(client):
    response = client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


def test_quick_token_generation(client):
    response = client.post(
        "/api/v1/auth/quick-token",
        json={"username": "qa_tester", "role": "developer", "tier": "tier-2"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user_info"]["tier"] == "tier-2"


@pytest.mark.asyncio
async def test_tier_hierarchy_enforcement():
    checker = require_tier("tier-2")
    # Tier-1 user attempting tier-2 operation
    tier1_user = {"sub": "u1", "tier": "tier-1"}
    with pytest.raises(HTTPException) as exc_info:
        await checker(tier1_user)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["error"] == "InsufficientTierPrivilege"

    # Tier-2 user attempting tier-2 operation -> allowed
    tier2_user = {"sub": "u2", "tier": "tier-2"}
    res = await checker(tier2_user)
    assert res["tier"] == "tier-2"

    # Admin user attempting tier-2 operation -> allowed
    admin_user = {"sub": "u3", "tier": "admin"}
    res_admin = await checker(admin_user)
    assert res_admin["tier"] == "admin"
