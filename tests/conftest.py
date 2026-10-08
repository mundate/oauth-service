from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from src.database import get_session
from src.main import app


@pytest.fixture
def session() -> Generator[Session]:
    # StaticPool keeps one connection, so every session sees the same in-memory database.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def client(session: Session) -> Generator[TestClient]:
    app.dependency_overrides[get_session] = lambda: session
    # Not used as a context manager, so the lifespan doesn't create ./oauth.db.
    yield TestClient(app, follow_redirects=False)
    app.dependency_overrides.clear()
