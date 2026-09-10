"""Testes de OpenAPISpec.infer_auth_header() (Fase 9: autenticação configurável por spec)."""
from __future__ import annotations

from agent.openapi_parser import OpenAPISpec


def _spec_with_schemes(security_schemes: dict) -> OpenAPISpec:
    return OpenAPISpec(base_url="http://x", endpoints=[], security_schemes=security_schemes, title="t")


def test_infers_api_key_header_scheme():
    spec = _spec_with_schemes(
        {"AuthToken": {"type": "apiKey", "in": "header", "name": "Authorization-Token"}}
    )
    assert spec.infer_auth_header() == ("Authorization-Token", "{token}")


def test_infers_http_bearer_scheme():
    spec = _spec_with_schemes({"BearerAuth": {"type": "http", "scheme": "bearer"}})
    assert spec.infer_auth_header() == ("Authorization", "Bearer {token}")


def test_unrecognized_scheme_returns_none():
    spec = _spec_with_schemes({"OAuth2": {"type": "oauth2", "flows": {}}})
    assert spec.infer_auth_header() is None


def test_no_security_schemes_returns_none():
    spec = _spec_with_schemes({})
    assert spec.infer_auth_header() is None


def test_api_key_in_query_is_not_inferred():
    """Só apiKey EM HEADER é suportado — apiKey em query exigiria mudanças em http_client.py, fora de escopo."""
    spec = _spec_with_schemes({"ApiKeyQuery": {"type": "apiKey", "in": "query", "name": "api_key"}})
    assert spec.infer_auth_header() is None
