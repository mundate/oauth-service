from pydantic import SecretStr

from src.models import ClientCredentials, User


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
    client = ClientCredentials(client_name="test", hashed_client_secret="")

    secret = client.generate_secret()

    assert secret not in client.hashed_client_secret
    assert client.verify_secret(secret)
    assert not client.verify_secret("not-the-secret")


def test_client_ids_are_unique():
    first = ClientCredentials(client_name="a", hashed_client_secret="")
    second = ClientCredentials(client_name="b", hashed_client_secret="")

    assert first.client_id != second.client_id
