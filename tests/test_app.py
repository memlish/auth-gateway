"""Tests for the auth-gateway edge service, exercised through FastAPI's TestClient."""
import json

from authlib.jose import JsonWebSignature
from fastapi.testclient import TestClient

from auth_gateway.app import app
from auth_gateway.config import get_settings

settings = get_settings()
jws = JsonWebSignature(algorithms=settings.allowed_algorithms)
client = TestClient(app)


def compact_token(**claims):
    """A valid compact JWS signed with the gateway's key."""
    payload = json.dumps(claims).encode()
    return jws.serialize_compact({"alg": "HS256"}, payload, settings.signing_key).decode()


def json_token(**claims):
    """A valid JWS in general JSON serialization, with a real signature."""
    token = jws.serialize_json(
        [{"protected": {"alg": "HS256"}, "header": {"kid": "demo"}}],
        claims,
        settings.signing_key,
    )
    return json.dumps(token)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_services_lists_downstreams():
    r = client.get("/services")
    assert r.status_code == 200
    assert "billing" in r.json()["services"]


def test_introspect_compact_token():
    r = client.post("/introspect", json={"token": compact_token(sub="alice", role="user")})
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["sub"] == "alice"
    assert body["role"] == "user"


def test_introspect_json_token():
    r = client.post("/introspect", json={"token": json_token(sub="bob", role="user")})
    assert r.status_code == 200
    assert r.json()["sub"] == "bob"


def test_introspect_rejects_garbage():
    r = client.post("/introspect", json={"token": "not-a-real-token"})
    assert r.status_code == 401


def test_introspect_rejects_tampered_signature():
    token = compact_token(sub="mallory", role="admin")
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    r = client.post("/introspect", json={"token": tampered})
    assert r.status_code == 401


def test_authorize_allows_matching_role():
    token = compact_token(sub="alice", role="admin")
    r = client.post(
        "/authorize",
        json={"token": token, "service": "billing", "required_role": "admin"},
    )
    assert r.status_code == 200
    assert r.json()["allow"] is True


def test_authorize_denies_wrong_role():
    token = compact_token(sub="alice", role="user")
    r = client.post(
        "/authorize",
        json={"token": token, "service": "billing", "required_role": "admin"},
    )
    assert r.status_code == 403


def test_authorize_unknown_service():
    token = compact_token(sub="alice", role="user")
    r = client.post("/authorize", json={"token": token, "service": "nope"})
    assert r.status_code == 404
