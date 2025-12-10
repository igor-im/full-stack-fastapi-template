from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.config import settings
from tests.utils.utils import create_test_token, get_superuser_token_headers


def test_verify_token_valid(client: TestClient) -> None:
    """Test that a valid token returns the token payload."""
    headers = get_superuser_token_headers()
    r = client.post(
        f"{settings.API_V1_STR}/login/verify-token",
        headers=headers,
    )
    result = r.json()
    assert r.status_code == 200
    assert result["sub"] == "admin-user-id"
    assert result["email"] == "admin@example.com"
    assert "admin" in result["roles"]
    assert "admin:*" in result["permissions"]


def test_verify_token_with_permissions(client: TestClient) -> None:
    """Test that permissions are correctly extracted from token."""
    token = create_test_token(
        sub="user-123",
        email="user@example.com",
        permissions=["read:items", "write:items"],
        roles=["user"],
    )
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(
        f"{settings.API_V1_STR}/login/verify-token",
        headers=headers,
    )
    result = r.json()
    assert r.status_code == 200
    assert result["sub"] == "user-123"
    assert "read:items" in result["permissions"]
    assert "write:items" in result["permissions"]
    assert "user" in result["roles"]


def test_verify_token_expired(client: TestClient) -> None:
    """Test that an expired token returns 401."""
    token = create_test_token(
        sub="user-123",
        expires_delta=timedelta(hours=-1),  # Already expired
    )
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(
        f"{settings.API_V1_STR}/login/verify-token",
        headers=headers,
    )
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()


def test_verify_token_invalid(client: TestClient) -> None:
    """Test that an invalid token returns 401."""
    headers = {"Authorization": "Bearer invalid-token"}

    r = client.post(
        f"{settings.API_V1_STR}/login/verify-token",
        headers=headers,
    )
    assert r.status_code == 401


def test_verify_token_missing(client: TestClient) -> None:
    """Test that missing token returns 403."""
    r = client.post(f"{settings.API_V1_STR}/login/verify-token")
    assert r.status_code == 403
