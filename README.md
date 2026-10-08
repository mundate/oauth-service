# oauth-service
OAuth Service is a repo meant to implement OAuth 2.1.

## Getting Started
WIP

## OAuth 2.1 Flows

OAuth 2.1 defines three grant types. These are the values a client sends as `grant_type` to the `/token` endpoint.

| Flow | `grant_type` | Used for |
|---|---|---|
| Authorization code with PKCE | `authorization_code` | An app acting on behalf of a user: web, mobile, desktop or single-page apps |
| Client credentials | `client_credentials` | A service calling an API as itself, with no user involved |
| Refresh token | `refresh_token` | Getting a new access token without the user logging in again. Only issued in the authorization code flow. |

Client credentials clients don't get refresh tokens. When a token expires, the client requests a new one with its `client_id` and `client_secret`.

### Removed from OAuth 2.0

| Flow | Why it was removed | Use instead |
|---|---|---|
| Implicit (`response_type=token`) | Returned the access token in the redirect URL, where it could leak through browser history, logs and referrer headers | Authorization code with PKCE |
| Resource owner password (`grant_type=password`) | The app collects the user's password directly, and it can't support multi-factor authentication | Authorization code with PKCE, or the device flow |

This service rejects both.

### Extension grants

Other specs define additional grant types that OAuth 2.1 servers can support:

| Flow | Spec | Used for |
|---|---|---|
| Device authorization | RFC 8628 | CLIs, TVs and other devices without a usable browser |
| Token exchange | RFC 8693 | Swapping one token for another, such as a token for a downstream API |
| JWT bearer | RFC 7523 | Authenticating with a signed JWT instead of a client secret |
| CIBA | OpenID Connect | Approving a login on a separate device, such as a phone notification |

## PKCE

PKCE (Proof Key for Code Exchange, RFC 7636) proves that the app exchanging an authorization code is the same app that requested it. Without it, an attacker who intercepts the code from the redirect can exchange it for tokens.

OAuth 2.1 requires PKCE for public clients (apps without a client secret), and confidential clients are expected to use it too. **This service requires PKCE from every client** and accepts only the `S256` method.

### How it works

1. **The app creates a `code_verifier`.** This is a random string of 43 to 128 characters, kept secret by the app.
2. **The app derives a `code_challenge` from it:**
   ```
   code_challenge = BASE64URL(SHA256(code_verifier))   # no "=" padding
   ```
3. **The app sends the challenge to `/authorize`:**
   ```
   GET /authorize?response_type=code&client_id=...&redirect_uri=...
       &code_challenge=<challenge>&code_challenge_method=S256&state=...
   ```
   The server stores the challenge with the authorization code it issues.
4. **The app sends the verifier to `/token`:**
   ```
   POST /token
   grant_type=authorization_code&code=...&redirect_uri=...
   &client_id=...&code_verifier=<verifier>
   ```
5. **The server checks it.** It hashes the `code_verifier` the same way and compares the result to the stored challenge. If they don't match, the request is rejected.

An attacker who intercepts the code doesn't have the verifier, and the verifier can't be worked out from the challenge, so the stolen code is useless.

The `plain` method, where the challenge is just the verifier, isn't accepted because it protects nothing if the challenge is intercepted.

### `state` and `nonce`

These are separate from PKCE, and the service handles them differently:

- **`state`** is a random value the app sends to `/authorize`. The server returns it unchanged on the redirect, and the app checks it to prevent cross-site request forgery. The server doesn't store it.
- **`nonce`** is part of OpenID Connect and only matters when the server issues ID tokens. The server stores it with the authorization code and copies it into the ID token, and the app checks that it matches.
