"""Register an OAuth client.

Usage:
    uv run python -m scripts.create_client --name "My Web App" \
        --redirect-uri https://app.example.com/callback \
        --grant-type authorization_code --grant-type refresh_token \
        --scope "read write" --confidential
"""

import argparse
import sys
from urllib.parse import urlsplit

from sqlmodel import Session

from src import database
from src.models import Client

GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"]
# OAuth 2.1 recommends the loopback IP over "localhost", which can resolve to something else.
LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


def validate_redirect_uri(uri: str) -> str:
    parts = urlsplit(uri)
    if parts.fragment:
        raise argparse.ArgumentTypeError(f"{uri}: redirect URIs can't contain a #fragment")
    if parts.scheme == "https" and parts.netloc:
        return uri
    # OAuth 2.1 allows plain http only for loopback, for desktop and CLI apps.
    if parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS:
        return uri
    raise argparse.ArgumentTypeError(f"{uri}: must be https, or http on a loopback address")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Register an OAuth client.")
    parser.add_argument("--name", required=True, help="Name shown to users on the consent page")
    parser.add_argument(
        "--redirect-uri", action="append", default=[], type=validate_redirect_uri, dest="redirect_uris",
        help="Exact URI the user is sent back to. Repeat for several.",
    )
    parser.add_argument(
        "--grant-type", action="append", choices=GRANT_TYPES, dest="grant_types",
        help="Grant this client may use. Repeat for several. Default: authorization_code and refresh_token.",
    )
    parser.add_argument("--scope", default="", help="Space-separated scopes this client may request")
    parser.add_argument(
        "--confidential", action="store_true",
        help="Issue a client secret. Leave out for public clients (SPAs, mobile and CLI apps).",
    )
    args = parser.parse_args(argv)

    args.grant_types = sorted(set(args.grant_types or ["authorization_code", "refresh_token"]))
    if "authorization_code" in args.grant_types and not args.redirect_uris:
        parser.error("the authorization_code grant needs at least one --redirect-uri")
    if "client_credentials" in args.grant_types and not args.confidential:
        parser.error("the client_credentials grant needs a secret, so add --confidential")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    database.create_db_and_tables()
    client = Client(
        client_name=args.name,
        redirect_uris=args.redirect_uris,
        grant_types=args.grant_types,
        scope=args.scope,
    )
    secret = client.generate_secret() if args.confidential else None

    with Session(database.engine) as session:
        session.add(client)
        session.commit()
        client_id = client.client_id  # read before the session closes and detaches the client

    print(f"client_id:     {client_id}")
    if secret:
        print(f"client_secret: {secret}")
        print("Save the secret now. Only its hash is stored, so it can't be shown again.")
    else:
        print("Public client: no secret issued.")


if __name__ == "__main__":
    main()
