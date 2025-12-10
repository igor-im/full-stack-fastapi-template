import time
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKClientError
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class JWKSClient:
    """JWKS client with caching for RS256 token verification."""

    def __init__(self, jwks_url: str, cache_ttl: int = 3600):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self._jwks_client: PyJWKClient | None = None
        self._cache_time: float = 0

    def _get_client(self) -> PyJWKClient:
        """Get or create JWKS client, refreshing if cache expired."""
        current_time = time.time()
        if (
            self._jwks_client is None
            or (current_time - self._cache_time) > self.cache_ttl
        ):
            self._jwks_client = PyJWKClient(self.jwks_url)
            self._cache_time = current_time
        return self._jwks_client

    def get_signing_key(self, token: str) -> Any:
        """Get the signing key for a token from JWKS."""
        client = self._get_client()
        try:
            return client.get_signing_key_from_jwt(token)
        except PyJWKClientError as e:
            # Force refresh on error and retry once
            self._jwks_client = None
            client = self._get_client()
            return client.get_signing_key_from_jwt(token)


# Global JWKS client instance
_jwks_client: JWKSClient | None = None


def get_jwks_client() -> JWKSClient:
    """Get or create the global JWKS client."""
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = JWKSClient(
            jwks_url=settings.JWKS_URL,
            cache_ttl=settings.JWKS_CACHE_TTL,
        )
    return _jwks_client


def verify_token(token: str) -> dict[str, Any]:
    """
    Verify a JWT token using RS256 and JWKS.

    Args:
        token: The JWT token to verify

    Returns:
        The decoded token payload

    Raises:
        InvalidTokenError: If token is invalid, expired, or verification fails
    """
    jwks_client = get_jwks_client()

    try:
        signing_key = jwks_client.get_signing_key(token)
    except (PyJWKClientError, InvalidTokenError) as e:
        raise InvalidTokenError(f"Could not get signing key: {e}")

    # Build verification options
    options: dict[str, Any] = {}
    if settings.JWT_AUDIENCE:
        options["audience"] = settings.JWT_AUDIENCE
    if settings.JWT_ISSUER:
        options["issuer"] = settings.JWT_ISSUER

    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=[settings.JWT_ALGORITHM],
            **options,
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidAudienceError:
        raise InvalidTokenError("Invalid audience")
    except jwt.InvalidIssuerError:
        raise InvalidTokenError("Invalid issuer")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {e}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
