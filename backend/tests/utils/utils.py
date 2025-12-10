import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def random_lower_string() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=32))


def random_email() -> str:
    return f"{random_lower_string()}@{random_lower_string()}.com"


# Generate RSA key pair for testing
_test_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
_test_public_key = _test_private_key.public_key()

# Get PEM encoded keys
TEST_PRIVATE_KEY_PEM = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

TEST_PUBLIC_KEY_PEM = _test_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def create_test_token(
    sub: str,
    email: str | None = None,
    permissions: list[str] | None = None,
    roles: list[str] | None = None,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a test JWT token signed with the test private key.

    Args:
        sub: Subject (user identifier)
        email: User email
        permissions: List of permissions
        roles: List of roles
        expires_delta: Token expiration time delta
        extra_claims: Additional claims to include

    Returns:
        Signed JWT token
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=1)

    expire = datetime.now(timezone.utc) + expires_delta

    payload: dict[str, Any] = {
        "sub": sub,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    if email:
        payload["email"] = email
    if permissions:
        payload["permissions"] = permissions
    if roles:
        payload["roles"] = roles
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, TEST_PRIVATE_KEY_PEM, algorithm="RS256")


def get_test_token_headers(
    sub: str = "test-user-id",
    email: str | None = None,
    permissions: list[str] | None = None,
    roles: list[str] | None = None,
) -> dict[str, str]:
    """Get authorization headers with a test token."""
    token = create_test_token(
        sub=sub,
        email=email,
        permissions=permissions,
        roles=roles,
    )
    return {"Authorization": f"Bearer {token}"}


def get_superuser_token_headers() -> dict[str, str]:
    """Get authorization headers with admin permissions."""
    return get_test_token_headers(
        sub="admin-user-id",
        email="admin@example.com",
        permissions=["admin:*"],
        roles=["admin"],
    )


def get_normal_user_token_headers(
    email: str = "user@example.com",
) -> dict[str, str]:
    """Get authorization headers for a normal user."""
    return get_test_token_headers(
        sub="normal-user-id",
        email=email,
        permissions=["read", "write"],
        roles=["user"],
    )
