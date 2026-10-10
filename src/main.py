from contextlib import asynccontextmanager

from fastapi import FastAPI

from src import models  # noqa: F401  registers tables with SQLModel.metadata
from src.database import create_db_and_tables
from src.router.health import health_router
from src.router.oauth import oauth_router
from src.router.register import register_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)
# app.include_router(router)
app.include_router(register_router)
app.include_router(oauth_router)
app.include_router(health_router, prefix="/health", tags=["health"])
