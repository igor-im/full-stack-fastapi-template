from collections.abc import Generator
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, delete

from app.core.db import engine, init_db
from app.main import app
from app.models import Item, User
from tests.utils.utils import (
    TEST_PUBLIC_KEY_PEM,
    get_normal_user_token_headers,
    get_superuser_token_headers,
)


def _mock_verify_token(token: str) -> dict:
    """Mock token verification using test public key."""
    return jwt.decode(token, TEST_PUBLIC_KEY_PEM, algorithms=["RS256"])


@pytest.fixture(scope="session", autouse=True)
def mock_jwks():
    """Mock the JWKS client for all tests."""
    with patch("app.core.security.verify_token", side_effect=_mock_verify_token):
        yield


@pytest.fixture(scope="session", autouse=True)
def db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        init_db(session)
        yield session
        statement = delete(Item)
        session.execute(statement)
        statement = delete(User)
        session.execute(statement)
        session.commit()


@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def superuser_token_headers() -> dict[str, str]:
    return get_superuser_token_headers()


@pytest.fixture(scope="module")
def normal_user_token_headers() -> dict[str, str]:
    return get_normal_user_token_headers()
