from typing import Any

from fastapi import APIRouter

from app.api.deps import CurrentToken
from app.models import TokenPayload

router = APIRouter(tags=["login"])


@router.post("/login/verify-token", response_model=TokenPayload)
def verify_token(token: CurrentToken) -> Any:
    """
    Verify access token and return token payload.

    This endpoint validates the JWT token from the external IdP
    and returns the decoded payload including permissions and roles.
    """
    return token
