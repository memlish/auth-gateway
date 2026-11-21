# auth-gateway

An edge gateway that introspects access tokens on behalf of downstream
services. Downstream services forward a presented access token to this gateway
instead of verifying it themselves; the gateway checks the signature against its
configured HMAC key and reports the claims (or rejects the token).

Tokens may be presented either as a compact JWS (`header.payload.signature`) or
as a JWS in JSON serialization, which some batch clients emit.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe (service name and environment). |
| `GET` | `/services` | List the downstream services this gateway fronts. |
| `POST` | `/introspect` | Verify an access token and return its claims. |
| `POST` | `/authorize` | Decide whether a token may reach a named downstream service. |

`POST /introspect` takes a JSON body `{"token": "...", "token_type_hint": null}`
and returns `{"active": true, "sub": ..., "role": ..., "iss": ..., "claims": {...}}`.
A token that fails verification is rejected with `401`.

`POST /authorize` takes `{"token": "...", "service": "...", "required_role": "..."}`
and returns an allow decision, `403` if the role is insufficient, or `404` for an
unknown service.

## Configuration

All settings come from the environment, with development defaults:

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_SERVICE_NAME` | `auth-gateway` | Name reported on `/health`. |
| `GATEWAY_ENV` | `development` | Environment label. |
| `GATEWAY_SIGNING_KEY` | `dev-only-change-me` | HMAC key used to verify tokens. Override in every real tier. |
| `GATEWAY_ALLOWED_ALGS` | `HS256` | Comma-separated signature algorithms to accept. |
| `GATEWAY_DOWNSTREAMS` | `billing=api.billing,reports=api.reports` | `name=audience` pairs for fronted services. |
| `GATEWAY_ISSUER` | _(empty)_ | Expected token issuer; empty disables the issuer check. |

## Running

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn auth_gateway.app:app --app-dir src --reload
```

## Tests

```sh
python -m pytest tests/ -q
```

The suite uses FastAPI's `TestClient`, so it runs fully offline without starting
a server.
