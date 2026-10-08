from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from src.database import SessionDep

health_router = APIRouter()


@health_router.get("")
def liveness():
    """The process is up and serving requests."""
    return {"status": "ok"}


@health_router.get("/ready")
def readiness(session: SessionDep):
    """The service can reach its database."""
    try:
        session.connection().execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "unavailable", "database": "unreachable"},
        )
    return {"status": "ok", "database": "ok"}
