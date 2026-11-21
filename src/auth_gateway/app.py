"""Edge gateway for access-token introspection.

Downstream services do not verify tokens themselves; they call this gateway,
which checks the signature on a presented access token and reports the claims.

Tokens may arrive in two shapes:

* a compact JWS (the usual ``header.payload.signature`` form), or
* a JWS in JSON serialization, which some of our batch clients emit.

Both are verified against the configured HMAC key before the gateway trusts
any claim inside them.
"""
import json
from typing import Any, Dict, List, Optional

from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .config import get_settings

settings = get_settings()
jws = JsonWebSignature(algorithms=settings.allowed_algorithms)

app = FastAPI(
    title=settings.service_name,
    version=__version__,
    description="Edge gateway that introspects access tokens for downstream services.",
)


class IntrospectionRequest(BaseModel):
    """RFC 7662-style introspection request."""

    token: str = Field(..., description="The access token to introspect.")
    token_type_hint: Optional[str] = Field(
        default=None, description="Optional hint; only access tokens are supported."
    )


class IntrospectionResponse(BaseModel):
    """Subset of the RFC 7662 response the gateway returns to callers."""

    active: bool
    sub: Optional[str] = None
    role: Optional[str] = None
    iss: Optional[str] = None
    claims: Dict[str, Any] = Field(default_factory=dict)


class AuthorizationRequest(BaseModel):
    """Ask whether a token is allowed to reach a named downstream service."""

    token: str
    service: str
    required_role: Optional[str] = None


def _verify_token(token: str) -> Dict[str, Any]:
    """Verify a presented access token and return its claim set.

    A token that begins with ``{`` is a JWS in JSON serialization and is
    handed to the JSON deserializer; anything else is treated as a compact
    JWS. A bad signature or malformed token raises ``JoseError``.
    """
    token = token.strip()
    if token.startswith("{"):
        verified = jws.deserialize_json(token, settings.signing_key)
    else:
        verified = jws.deserialize_compact(token, settings.signing_key)
    claims = json.loads(verified.payload)
    if not isinstance(claims, dict):
        raise JoseError(description="payload is not a claim set")
    return claims


def _check_issuer(claims: Dict[str, Any]) -> None:
    """Reject a token whose issuer does not match the configured one."""
    if settings.expected_issuer and claims.get("iss") != settings.expected_issuer:
        raise HTTPException(status_code=401, detail="untrusted issuer")


@app.get("/health")
def health() -> Dict[str, str]:
    """Liveness probe used by the load balancer."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "environment": settings.environment,
    }


@app.get("/services")
def services() -> Dict[str, List[str]]:
    """List the downstream services this gateway fronts."""
    return {"services": sorted(settings.downstreams)}


@app.post("/introspect", response_model=IntrospectionResponse)
def introspect(request: IntrospectionRequest) -> IntrospectionResponse:
    """Verify an access token and return its claims.

    Unlike the RFC's ``{"active": false}`` convention, a token the gateway
    cannot verify is rejected outright with 401 so downstream services never
    see an unverified identity.
    """
    try:
        claims = _verify_token(request.token)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    _check_issuer(claims)
    return IntrospectionResponse(
        active=True,
        sub=claims.get("sub"),
        role=claims.get("role"),
        iss=claims.get("iss"),
        claims=claims,
    )


@app.post("/authorize")
def authorize(request: AuthorizationRequest) -> Dict[str, Any]:
    """Decide whether a token may reach a named downstream service."""
    if request.service not in settings.downstreams:
        raise HTTPException(status_code=404, detail="unknown service")
    try:
        claims = _verify_token(request.token)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    _check_issuer(claims)
    if request.required_role and claims.get("role") != request.required_role:
        raise HTTPException(status_code=403, detail="insufficient role")
    return {
        "allow": True,
        "service": request.service,
        "audience": settings.downstreams[request.service],
        "sub": claims.get("sub"),
    }
