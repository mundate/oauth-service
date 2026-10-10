import hashlib
import secrets
from datetime import UTC, datetime, timedelta
import uuid

from pwdlib import PasswordHash
from pydantic import SecretStr
from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

password_hash = PasswordHash.recommended()
DUMMY_SECRET = " secret that gets hashed"

PENDING_AUTHORIZATION_LIFETIME = timedelta(minutes=10)
AUTHORIZATION_CODE_LIFETIME = timedelta(minutes=1)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)


def hash_token(token: str) -> str:
    """Hash a random server-issued token for storage and lookup.

    SHA-256 is enough here because the token is long and random, so it can't be guessed.
    It also makes the same token produce the same hash every time, so a stored token can be looked up by its hash.
    """
    return hashlib.sha256(token.encode()).hexdigest()


class User(SQLModel, table=True):
    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False
    )
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str = Field(default="", min_length=10)
    verified: bool = False
    disabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def set_password(self, password: SecretStr) -> None:
        self.hashed_password = password_hash.hash(password.get_secret_value())

    def verify_password(self, password: SecretStr) -> bool:
        return password_hash.verify(password.get_secret_value(), self.hashed_password)


class Client(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    client_id: str = Field(default_factory=lambda: secrets.token_urlsafe(16), unique=True, index=True)
    client_name: str
    hashed_client_secret: str | None = None  # None = public client (SPA, mobile, CLI)
    redirect_uris: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    grant_types: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    scope: str = ""  # the most this client may ask for
    disabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_public(self) -> bool:
        return self.hashed_client_secret is None

    def generate_secret(self) -> str:
        """Set a new random secret and return it. Only the hash is stored, so show it to the caller once."""
        secret = secrets.token_urlsafe(32)
        self.hashed_client_secret = password_hash.hash(secret)
        return secret

    def verify_secret(self, secret: SecretStr) -> bool:
        if self.hashed_client_secret is None:
            return False
        return password_hash.verify(secret.get_secret_value(), self.hashed_client_secret)


class PendingAuthorization(SQLModel, table=True):
    """A validated /authorize request, held while the user logs in and approves it."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    client_id: uuid.UUID = Field(foreign_key="client.id")
    redirect_uri: str
    scope: str = ""
    state: str | None = None
    code_challenge: str
    code_challenge_method: str = "S256"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + PENDING_AUTHORIZATION_LIFETIME)


class AuthorizationCode(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    code_hash: str = Field(unique=True, index=True)
    code_challenge: str
    code_challenge_method: str = "S256"
    client_id: uuid.UUID = Field(foreign_key="client.id")
    user_id: uuid.UUID = Field(foreign_key="user.id")
    redirect_uri: str
    scope: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + AUTHORIZATION_CODE_LIFETIME)
    used_at: datetime | None = None  # kept after use so a second exchange can be detected

    def generate_code(self) -> str:
        """Set a new random code and return it. Only the hash is stored, so send it to the client once."""
        code = secrets.token_urlsafe(32)
        self.code_hash = hash_token(code)
        return code


class RefreshToken(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    token_hash: str = Field(unique=True, index=True)
    # Shared by every token in one rotation chain, so reuse of an old token can revoke the whole chain.
    family_id: uuid.UUID = Field(default_factory=uuid.uuid4, index=True)
    client_id: uuid.UUID = Field(foreign_key="client.id")
    user_id: uuid.UUID = Field(foreign_key="user.id")
    scope: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + REFRESH_TOKEN_LIFETIME)
    revoked_at: datetime | None = None

    def generate_token(self) -> str:
        """Set a new random token and return it. Only the hash is stored, so send it to the client once."""
        token = secrets.token_urlsafe(32)
        self.token_hash = hash_token(token)
        return token
