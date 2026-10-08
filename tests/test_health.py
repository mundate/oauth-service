from fastapi.testclient import TestClient

from src.database import get_session
from src.main import app


def test_liveness(client: TestClient):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness(client: TestClient):
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_readiness_when_database_unreachable(client: TestClient):
    class BrokenSession:
        def connection(self):
            raise ConnectionError("database down")

    app.dependency_overrides[get_session] = lambda: BrokenSession()

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"status": "unavailable", "database": "unreachable"}
    }
