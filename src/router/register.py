from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from pydantic import EmailStr, SecretStr
from pydantic_core import ValidationError

from src.database import SessionDep
from src.models import User
from src.schemas import AuthorizeRequest, RegisterRequest, RegisterResponse, TokenRequest, TokenResponse
from src.service import register as regiser_service

register_router = APIRouter()

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@register_router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse(request, "register.html")


@register_router.post("/register", response_class=HTMLResponse)
def register_user(
    request: Request,
    session: SessionDep,
    email: Annotated[EmailStr, Form()],
    password: Annotated[SecretStr, Form()],
):
    def show_error(message: str, code: int):
        return templates.TemplateResponse(
            request, "register.html", {"error": message, "email": email}, status_code=code
        )

    try:
        data = RegisterRequest(email=email, password=password)
    except ValidationError:
        return show_error("Enter a valid email and a password of at least 12 characters.", 400)

    regiser_service.register_user(data, session)

    return RedirectResponse("/verify", status_code=status.HTTP_303_SEE_OTHER)


# @register_router.get("/verify/{}", )