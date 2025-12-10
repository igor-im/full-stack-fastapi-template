from fastapi import APIRouter, Depends

from app.api.deps import get_token_payload
from app.api.routes import items, login, private, users, utils
from app.core.config import settings

# Public router - no authentication required
public_router = APIRouter()
public_router.include_router(login.router)
public_router.include_router(utils.router)

# Protected router - JWT authentication required for all routes
protected_router = APIRouter(dependencies=[Depends(get_token_payload)])
protected_router.include_router(users.router)
protected_router.include_router(items.router)

# Main API router
api_router = APIRouter()
api_router.include_router(public_router)
api_router.include_router(protected_router)

if settings.ENVIRONMENT == "local":
    api_router.include_router(private.router)
