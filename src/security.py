from fastapi.security import OAuth2AuthorizationCodeBearer

oauth2__scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/authorize",
    tokenUrl="/token",
    refreshUrl="/token",
)
