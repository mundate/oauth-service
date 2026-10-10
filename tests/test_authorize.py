import base64
import hashlib
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.config import settings
from src.models import Client, PendingAuthorization
from src.schemas import AuthorizeError, AuthorizeSuccess
from src.service.authorize import generate_redirect_url

REDIRECT_URI = "https://app.example.com/callback"
CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(CODE_VERIFIER.encode()).digest()).rstrip(b"=").decode()


@pytest.fixture
def oauth_client(session: Session) -> Client:
    client = Client(
        client_name="Test App",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        scope="read write",
    )
    session.add(client)
    session.commit()
    return client


def authorize_params(client: Client, **overrides: str | None) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "read",
        "state": "xyz123",
        "code_challenge": CODE_CHALLENGE,
        "code_challenge_method": "S256",
    } | overrides
    return {key: value for key, value in params.items() if value is not None}


def redirect_query(response) -> dict[str, str]:
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT_URI
    return {key: values[0] for key, values in parse_qs(location.query).items()}


# Successful requests


def test_valid_request_saves_it_and_redirects_to_login(
    client: TestClient, session: Session, oauth_client: Client
):
    response = client.get("/authorize", params=authorize_params(oauth_client))

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/login"

    pending = session.exec(select(PendingAuthorization)).one()
    assert parse_qs(location.query) == {"request_id": [str(pending.id)]}
    assert pending.client_id == oauth_client.id
    assert pending.redirect_uri == REDIRECT_URI
    assert pending.scope == "read"
    assert pending.state == "xyz123"
    assert pending.code_challenge == CODE_CHALLENGE
    assert pending.code_challenge_method == "S256"


def test_redirect_uri_can_be_omitted_when_client_has_one(
    client: TestClient, session: Session, oauth_client: Client
):
    response = client.get("/authorize", params=authorize_params(oauth_client, redirect_uri=None))

    assert response.status_code == 302
    assert session.exec(select(PendingAuthorization)).one().redirect_uri == REDIRECT_URI


# Errors shown as a page, never redirected


def assert_error_page(response, session: Session, message: str):
    assert response.status_code == 400
    assert "location" not in response.headers
    assert message in response.text
    assert session.exec(select(PendingAuthorization)).all() == []


def test_unknown_client_shows_error_page(client: TestClient, session: Session, oauth_client: Client):
    response = client.get("/authorize", params=authorize_params(oauth_client, client_id="nope"))

    assert_error_page(response, session, "Unknown client.")


def test_missing_client_id_shows_error_page(client: TestClient, session: Session, oauth_client: Client):
    response = client.get("/authorize", params=authorize_params(oauth_client, client_id=None))

    assert_error_page(response, session, "exactly one client_id")


def test_disabled_client_shows_error_page(client: TestClient, session: Session, oauth_client: Client):
    oauth_client.disabled = True
    session.commit()

    response = client.get("/authorize", params=authorize_params(oauth_client))

    assert_error_page(response, session, "Unknown client.")


def test_unregistered_redirect_uri_shows_error_page(
    client: TestClient, session: Session, oauth_client: Client
):
    response = client.get(
        "/authorize", params=authorize_params(oauth_client, redirect_uri="https://evil.example.com/callback")
    )

    assert_error_page(response, session, "not registered")


def test_redirect_uri_required_when_client_has_several(
    client: TestClient, session: Session, oauth_client: Client
):
    oauth_client.redirect_uris = [REDIRECT_URI, "https://app.example.com/other"]
    session.commit()

    response = client.get("/authorize", params=authorize_params(oauth_client, redirect_uri=None))

    assert_error_page(response, session, "must include a redirect_uri")


def test_repeated_redirect_uri_shows_error_page(
    client: TestClient, session: Session, oauth_client: Client
):
    params = list(authorize_params(oauth_client).items()) + [("redirect_uri", REDIRECT_URI)]

    response = client.get("/authorize", params=params)

    assert_error_page(response, session, "more than once")


def test_bad_client_is_reported_before_bad_parameters(
    client: TestClient, session: Session, oauth_client: Client
):
    response = client.get(
        "/authorize", params=authorize_params(oauth_client, client_id="nope", code_challenge=None)
    )

    assert_error_page(response, session, "Unknown client.")


# Errors redirected back to the client


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"response_type": None}, "invalid_request"),
        ({"code_challenge": None}, "invalid_request"),
        ({"code_challenge": "too-short"}, "invalid_request"),
        ({"code_challenge_method": None}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"scope": "read admin"}, "invalid_scope"),
        ({"scope": None}, "invalid_scope"),
        ({"scope": ""}, "invalid_scope"),
        ({"scope": "   "}, "invalid_scope"),
    ],
)
def test_invalid_request_redirects_with_error(
    client: TestClient, session: Session, oauth_client: Client, overrides: dict, error: str
):
    response = client.get("/authorize", params=authorize_params(oauth_client, **overrides))

    query = redirect_query(response)
    assert query["error"] == error
    assert query["error_description"]
    assert query["state"] == "xyz123"
    assert query["iss"] == settings.ISSUER
    assert session.exec(select(PendingAuthorization)).all() == []


def test_client_without_authorization_code_grant_is_redirected_with_error(
    client: TestClient, session: Session, oauth_client: Client
):
    oauth_client.grant_types = ["client_credentials"]
    session.commit()

    response = client.get("/authorize", params=authorize_params(oauth_client))

    assert redirect_query(response)["error"] == "unauthorized_client"


def test_repeated_parameter_is_redirected_with_error(client: TestClient, oauth_client: Client):
    params = list(authorize_params(oauth_client).items()) + [("scope", "write")]

    response = client.get("/authorize", params=params)

    assert redirect_query(response)["error"] == "invalid_request"


def test_error_redirect_leaves_out_state_when_not_sent(client: TestClient, oauth_client: Client):
    response = client.get(
        "/authorize", params=authorize_params(oauth_client, state=None, response_type="token")
    )

    assert "state" not in redirect_query(response)


# generate_redirect_url


def test_generate_redirect_url_adds_query_string():
    url = generate_redirect_url(
        REDIRECT_URI, AuthorizeSuccess(code="abc", state="xyz", iss=settings.ISSUER)
    )

    assert url == f"{REDIRECT_URI}?code=abc&state=xyz&{urlencode({'iss': settings.ISSUER})}"


def test_generate_redirect_url_keeps_existing_query_string():
    url = generate_redirect_url(
        "https://app.example.com/callback?tenant=acme",
        AuthorizeError(error="access_denied", iss=settings.ISSUER),
    )

    assert url.startswith("https://app.example.com/callback?tenant=acme&error=access_denied&")
