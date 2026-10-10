from datetime import UTC, datetime

from pydantic import SecretStr
from sqlmodel import Session

from src.models import AuthorizationCode, Client, RefreshToken, User, hash_token


def test_set_password_does_not_store_plaintext():
    user = User(username="a@example.com", email="a@example.com")

    user.set_password(SecretStr("correct horse battery"))

    assert user.hashed_password
    assert "correct horse battery" not in user.hashed_password


def test_verify_password_accepts_correct_password():
    user = User(username="a@example.com", email="a@example.com")
    user.set_password(SecretStr("correct horse battery"))

    assert user.verify_password(SecretStr("correct horse battery"))


def test_verify_password_rejects_wrong_password():
    user = User(username="a@example.com", email="a@example.com")
    user.set_password(SecretStr("correct horse battery"))

    assert not user.verify_password(SecretStr("wrong password"))


def test_client_secret_round_trip():
    client = Client(client_name="test")

    secret = client.generate_secret()

    assert not client.is_public
    assert secret not in client.hashed_client_secret
    assert client.verify_secret(SecretStr(secret))
    assert not client.verify_secret(SecretStr("not-the-secret"))


def test_public_client_rejects_any_secret():
    client = Client(client_name="spa")

    assert client.is_public
    assert not client.verify_secret(SecretStr(""))


def test_client_ids_are_unique():
    first = Client(client_name="a")
    second = Client(client_name="b")

    assert first.client_id != second.client_id


def test_client_lists_round_trip_through_database(session: Session):
    client = Client(
        client_name="web",
        redirect_uris=["https://app.example.com/callback"],
        grant_types=["authorization_code", "refresh_token"],
    )
    session.add(client)
    session.commit()
    session.expire_all()

    stored = session.get(Client, client.id)

    assert stored.redirect_uris == ["https://app.example.com/callback"]
    assert stored.grant_types == ["authorization_code", "refresh_token"]


def test_authorization_code_stores_only_hash():
    auth_code = AuthorizationCode(
        code_challenge="challenge", redirect_uri="https://app.example.com/callback"
    )

    code = auth_code.generate_code()

    assert auth_code.code_hash == hash_token(code)
    assert code not in auth_code.code_hash


def test_authorization_code_defaults():
    auth_code = AuthorizationCode(
        code_challenge="challenge", redirect_uri="https://app.example.com/callback"
    )

    assert auth_code.code_challenge_method == "S256"
    assert auth_code.used_at is None
    assert auth_code.created_at < auth_code.expires_at
    assert auth_code.expires_at > datetime.now(UTC)


def test_refresh_token_stores_only_hash():
    refresh_token = RefreshToken()

    token = refresh_token.generate_token()

    assert refresh_token.token_hash == hash_token(token)
    assert refresh_token.revoked_at is None
    assert refresh_token.expires_at > datetime.now(UTC)


def test_new_refresh_tokens_start_their_own_family():
    assert RefreshToken().family_id != RefreshToken().family_id
