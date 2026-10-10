from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, EmailStr, Field, SecretStr

from src.util import validate_password

Password = Annotated[SecretStr, AfterValidator(validate_password)]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: Password


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
    # An S256 challenge is always 43 base64url characters.
    code_challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    # Required: RFC 7636 treats a missing method as "plain", which this service rejects.
    code_challenge_method: Literal["S256"]


class AuthorizeSuccess(BaseModel):
    code: str
    state: str | None = None
    iss: str


AuthorizeErrorCode = Literal[
    "invalid_request", "unauthorized_client", "access_denied",
    "unsupported_response_type", "invalid_scope",
    "server_error", "temporarily_unavailable",
]


class AuthorizeError(BaseModel):
    error: AuthorizeErrorCode
    error_description: str | None = None
    state: str | None = None
    iss: str


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
