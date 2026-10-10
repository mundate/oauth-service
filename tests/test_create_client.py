import pytest
from pydantic import SecretStr
from sqlmodel import Session, select

from scripts.create_client import main
from src.models import Client


@pytest.fixture(autouse=True)
def use_test_database(monkeypatch: pytest.MonkeyPatch, session: Session):
    monkeypatch.setattr("src.database.engine", session.get_bind())


def output_value(output: str, label: str) -> str:
    line = next(line for line in output.splitlines() if line.startswith(f"{label}:"))
    return line.split(":", 1)[1].strip()


def test_creates_confidential_client(session: Session, capsys: pytest.CaptureFixture[str]):
    main([
        "--name", "Web App",
        "--redirect-uri", "https://app.example.com/callback",
        "--scope", "read write",
        "--confidential",
    ])

    output = capsys.readouterr().out
    client = session.exec(select(Client)).one()
    assert client.client_id == output_value(output, "client_id")
    assert client.client_name == "Web App"
    assert client.redirect_uris == ["https://app.example.com/callback"]
    assert client.grant_types == ["authorization_code", "refresh_token"]
    assert client.scope == "read write"
    assert client.verify_secret(SecretStr(output_value(output, "client_secret")))


def test_creates_public_client(session: Session, capsys: pytest.CaptureFixture[str]):
    main(["--name", "CLI", "--redirect-uri", "http://127.0.0.1:8765/callback"])

    client = session.exec(select(Client)).one()
    assert client.is_public
    assert "client_secret" not in capsys.readouterr().out


def test_accepts_several_redirect_uris(session: Session):
    main([
        "--name", "Web App",
        "--redirect-uri", "https://app.example.com/callback",
        "--redirect-uri", "https://staging.example.com/callback",
    ])

    assert session.exec(select(Client)).one().redirect_uris == [
        "https://app.example.com/callback",
        "https://staging.example.com/callback",
    ]


@pytest.mark.parametrize(
    "args",
    [
        ["--redirect-uri", "http://app.example.com/callback"],
        ["--redirect-uri", "http://localhost:8765/callback"],
        ["--redirect-uri", "https://app.example.com/callback#section"],
        ["--redirect-uri", "app.example.com/callback"],
        [],  # authorization_code needs a redirect URI
        ["--grant-type", "client_credentials"],  # needs --confidential
        ["--redirect-uri", "https://app.example.com/callback", "--grant-type", "password"],
    ],
)
def test_rejects_invalid_arguments(session: Session, args: list[str]):
    with pytest.raises(SystemExit):
        main(["--name", "App", *args])

    assert session.exec(select(Client)).all() == []


def test_client_credentials_only_client_needs_no_redirect_uri(session: Session):
    main(["--name", "Worker", "--grant-type", "client_credentials", "--confidential"])

    client = session.exec(select(Client)).one()
    assert client.grant_types == ["client_credentials"]
    assert client.redirect_uris == []
