import secrets
from datetime import UTC, datetime
import uuid

from pwdlib import PasswordHash
from pydantic import SecretStr
from sqlmodel import Field, SQLModel

password_hash = PasswordHash.recommended()
# TODO: Change this string (openssl rand hex 32)
RANDOM_STRING = b'8b22613ccaa100a7f12410a93c89f65c262f641f391894d2df2498a8dfcdfe20'


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
        self.hashed_password = password_hash.hash(password.get_secret_value(), salt=RANDOM_STRING)

    def verify_password(self, password: SecretStr) -> bool:
        hashed_input = password_hash.hash(password.get_secret_value(), salt=RANDOM_STRING)
        return password_hash.verify(hashed_input, self.hashed_password)


class ClientCredentials(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    client_id: str = Field(
        default_factory=lambda: secrets.token_urlsafe(16), unique=True, index=True
    )
    hashed_client_secret: str
    client_name: str
    scope: str = ""
    disabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def generate_secret(self) -> str:
        """Set a new random secret and return it. Only the hash is stored, so show it to the caller once."""
        secret = secrets.token_urlsafe(32)
        self.hashed_client_secret = password_hash.hash(secret)
        return secret

    def verify_secret(self, secret: str) -> bool:
        return password_hash.verify(secret, self.hashed_client_secret)


class AuthorizationCode(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    code: str = Field(unique=True, index=True)
    client_id: str
    user_id: int | None = None
    redirect_uri: str
    scope: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

class RefreshToken(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True)
    client_id: str
    user_id: int | None = None
    scope: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
