import uuid

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from src.database import SessionDep

authorize_pages_router = APIRouter()


@authorize_pages_router.get("/login", response_class=HTMLResponse)
def present_login(request: Request, request_id: uuid.UUID, session: SessionDep):
    raise NotImplementedError


@authorize_pages_router.get("/consent", response_class=HTMLResponse)
def present_scope_consent(request: Request, request_id: uuid.UUID, session: SessionDep):
    raise NotImplementedError
