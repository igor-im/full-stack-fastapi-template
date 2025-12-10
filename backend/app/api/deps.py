from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.db import engine
from app.models import TokenPayload

# Use HTTPBearer for external IdP tokens
bearer_scheme = HTTPBearer(auto_error=True)


def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_token_payload(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> TokenPayload:
    """
    Verify JWT token and extract payload with permissions.

    The token is verified using RS256 algorithm against the JWKS from the IdP.
    Permissions and roles are extracted from the token claims.
    """
    token = credentials.credentials
    try:
        payload = security.verify_token(token)
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract permissions from common claim locations
    # Different IdPs use different claim names
    permissions = (
        payload.get("permissions")
        or payload.get("scope", "").split()
        or payload.get("scp", [])
        or []
    )
    if isinstance(permissions, str):
        permissions = permissions.split()

    # Extract roles from common claim locations
    roles = (
        payload.get("roles")
        or payload.get("groups")
        or payload.get("realm_access", {}).get("roles", [])  # Keycloak
        or payload.get("cognito:groups", [])  # AWS Cognito
        or []
    )
    if isinstance(roles, str):
        roles = [roles]

    try:
        token_data = TokenPayload(
            sub=payload.get("sub", ""),
            email=payload.get("email"),
            permissions=permissions,
            roles=roles,
        )
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


# Dependency for getting the current token payload
CurrentToken = Annotated[TokenPayload, Depends(get_token_payload)]


def require_permission(permission: str):
    """
    Dependency factory for requiring a specific permission.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_permission("admin:read"))])
    """

    def check_permission(token: CurrentToken) -> TokenPayload:
        if not token.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )
        return token

    return check_permission


def require_role(role: str):
    """
    Dependency factory for requiring a specific role.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    """

    def check_role(token: CurrentToken) -> TokenPayload:
        if not token.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required role: {role}",
            )
        return token

    return check_role


def get_current_admin(token: CurrentToken) -> TokenPayload:
    """Require admin role/permission."""
    if not token.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return token


# Dependency for requiring admin access
CurrentAdmin = Annotated[TokenPayload, Depends(get_current_admin)]
