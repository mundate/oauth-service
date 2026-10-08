from typing import Literal

from pydantic import BaseModel, EmailStr, SecretStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: SecretStr


class RegisterResponse(BaseModel):
    id: int
    email: EmailStr
    verified: bool
    disabled: bool
    created_at: str


class AuthorizeRequest(BaseModel):
    response_type: Literal["code"]
    client_id: str
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: str
    code_challenge_method: Literal["S256"] = "S256"


class TokenRequest(BaseModel):
    grant_type: Literal["authorization_code", "refresh_token", "client_credentials"]
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None
