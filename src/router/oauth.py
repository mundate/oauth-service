from pathlib import Path

from fastapi import Request, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
from fastapi.templating import Jinja2Templates

from src.config import settings
from src.database import SessionDep
from src.schemas import AuthorizeError
from src.service import authorize as authorize_service
from src.service.authorize import AuthorizeRedirectError, InvalidClientError

oauth_router = APIRouter()

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@oauth_router.get("/authorize")
def authorize(request: Request, session: SessionDep):
    params = request.query_params

    try:
        client, redirect_uri = authorize_service.validate_client(
            params.getlist("client_id"), params.getlist("redirect_uri"), session
        )
    except InvalidClientError as e:
        return templates.TemplateResponse(
            request, "authorize_error.html", {"error": str(e)}, status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        auth_request = authorize_service.validate_authorize_request(params.multi_items(), client)
    except AuthorizeRedirectError as e:
        states = params.getlist("state")
        error = AuthorizeError(
            error=e.error,
            error_description=e.description,
            state=states[0] if len(states) == 1 else None,
            iss=settings.ISSUER,
        )
        return RedirectResponse(
            authorize_service.generate_redirect_url(redirect_uri, error), status_code=status.HTTP_302_FOUND
        )

    request_id = authorize_service.save_pending_authorize_request(auth_request, client, redirect_uri, session)
    return RedirectResponse(f"/login?request_id={request_id}", status_code=status.HTTP_302_FOUND)

@oauth_router.get("/token")
def token():
    pass
