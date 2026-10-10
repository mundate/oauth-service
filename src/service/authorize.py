import uuid
from urllib.parse import urlencode, urlsplit

from pydantic import SecretStr, ValidationError
from sqlmodel import select

from src.database import SessionDep
from src.models import Client, PendingAuthorization, User
from src.schemas import AuthorizeError, AuthorizeErrorCode, AuthorizeRequest, AuthorizeSuccess


class InvalidClientError(Exception):
    """Unknown or disabled client, or a bad redirect_uri. Show an error page, never redirect."""


class AuthorizeRedirectError(Exception):
    """Send the user back to the client's redirect_uri with this OAuth error."""

    def __init__(self, error: AuthorizeErrorCode, description: str):
        super().__init__(description)
        self.error: AuthorizeErrorCode = error
        self.description = description


def validate_client(
    client_ids: list[str], redirect_uris: list[str], session: SessionDep
) -> tuple[Client, str]:
    """Find the client and the redirect_uri to use.

    Runs before anything else, because until both are known to be valid it isn't safe to redirect.
    """
    if len(client_ids) != 1:
        raise InvalidClientError("The request must include exactly one client_id.")
    if len(redirect_uris) > 1:
        raise InvalidClientError("The request included redirect_uri more than once.")

    client = session.exec(select(Client).where(Client.client_id == client_ids[0])).first()
    if not client or client.disabled:
        raise InvalidClientError("Unknown client.")

    if not redirect_uris:
        # OAuth 2.1 lets the client leave redirect_uri out only when it has a single registered URI.
        if len(client.redirect_uris) != 1:
            raise InvalidClientError("The request must include a redirect_uri.")
        return client, client.redirect_uris[0]

    if redirect_uris[0] not in client.redirect_uris:
        raise InvalidClientError("The redirect_uri is not registered for this client.")
    return client, redirect_uris[0]


def validate_authorize_request(params: list[tuple[str, str]], client: Client) -> AuthorizeRequest:
    """Check the rest of the request. Call only after validate_client has passed."""
    values: dict[str, str] = {}
    for key, value in params:
        if key in values:
            raise AuthorizeRedirectError("invalid_request", f"{key} was sent more than once.")
        values[key] = value

    try:
        request = AuthorizeRequest.model_validate(values)
    except ValidationError as e:
        error = e.errors()[0]
        field = ".".join(str(part) for part in error["loc"])
        if field == "response_type" and error["type"] != "missing":
            raise AuthorizeRedirectError("unsupported_response_type", "Only response_type=code is supported.")
        raise AuthorizeRedirectError("invalid_request", f"{field}: {error['msg']}")

    if "authorization_code" not in client.grant_types:
        raise AuthorizeRedirectError(
            "unauthorized_client", "This client may not use the authorization code flow."
        )

    requested_scopes = set((request.scope or "").split())
    # No default scope: the client must ask for what it needs.
    if not requested_scopes:
        raise AuthorizeRedirectError("invalid_scope", "The request must include a scope.")
    if not requested_scopes <= set(client.scope.split()):
        raise AuthorizeRedirectError("invalid_scope", "The requested scope is not allowed for this client.")

    return request


def save_pending_authorize_request(
    request: AuthorizeRequest, client: Client, redirect_uri: str, session: SessionDep
) -> uuid.UUID:
    pending = PendingAuthorization(
        client_id=client.id,
        redirect_uri=redirect_uri,
        scope=request.scope or "",
        state=request.state,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method,
    )
    session.add(pending)
    session.commit()
    return pending.id


def load_authorize_request(request_id: uuid.UUID, session: SessionDep) -> PendingAuthorization:
    # load the saved request for the login and consent pages; reject it if expired
    raise NotImplementedError

def verify_login(email: str, password: SecretStr, session: SessionDep) -> User | None:
    raise NotImplementedError

def create_auth_code(pending: PendingAuthorization, user: User, session: SessionDep) -> str:
    raise NotImplementedError


def generate_redirect_url(redirect_uri: str, params: AuthorizeSuccess | AuthorizeError) -> str:
    query = urlencode(params.model_dump(exclude_none=True))
    # A registered redirect_uri may already have its own query string, which must be kept.
    separator = "&" if urlsplit(redirect_uri).query else "?"
    return f"{redirect_uri}{separator}{query}"
