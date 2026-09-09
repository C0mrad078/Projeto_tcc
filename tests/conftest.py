"""
Fixtures compartilhadas.

DECISÃO DE DESIGN: nenhum teste desta suíte chama o Gemini de verdade —
`patch_genai_success`/`patch_genai_error` substituem `google.genai.Client`
por um dublê controlado pelo teste. Isso é o que permite rodar a suíte sem
GOOGLE_API_KEY configurada (ver test_no_llm_calls_without_api_key.py) e sem
depender de rede — requisito explícito da Fase 14 da refatoração.

`relation_inference.py`/`classifier.py` fazem `from google import genai`
DENTRO das funções (import tardio, para não exigir o pacote instalado em
quem só usa o modo heurístico) — mas isso não atrapalha o monkeypatch,
porque o import tardio resolve `genai.Client` no mesmo objeto de módulo
`google.genai` que o teste também substitui via
`monkeypatch.setattr("google.genai.Client", ...)`.
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import pytest

from agent.config import Identity
from agent.executor import ExecutionResult
from agent.http_client import HttpExchange
from agent.openapi_parser import Endpoint, OpenAPISpec, Parameter
from agent.test_generator import TestCase


def make_endpoint(
    method: str,
    path: str,
    *,
    requires_auth: bool = True,
    parameters: Optional[List[Parameter]] = None,
) -> Endpoint:
    return Endpoint(
        method=method,
        path=path,
        operation_id=None,
        parameters=parameters or [],
        requires_auth=requires_auth,
    )


@pytest.fixture
def api1_endpoint() -> Endpoint:
    return make_endpoint(
        "GET",
        "/api1/user/{api1_id}",
        parameters=[Parameter(name="api1_id", location="path", required=True, schema_type="string")],
    )


@pytest.fixture
def api1_put_endpoint() -> Endpoint:
    return make_endpoint(
        "PUT",
        "/api1/user/{api1_id}",
        parameters=[
            Parameter(name="api1_id", location="path", required=True, schema_type="string"),
            Parameter(name="name", location="body", required=False, schema_type="string"),
        ],
    )


@pytest.fixture
def ambiguous_endpoint() -> Endpoint:
    """
    Parâmetro que BATE no regex de identificador (".*_id"), mas com
    localização "body" — score = LOCATION_WEIGHT["body"] (0.4) *
    METHOD_WEIGHT["GET"] (1.0) = 0.4, entre REJECT_THRESHOLD (0.3) e
    CONFIRM_THRESHOLD (0.7): a heurística sozinha não confirma nem rejeita.
    """
    return make_endpoint(
        "GET",
        "/api1/comment",
        parameters=[Parameter(name="record_id", location="body", required=False, schema_type="string")],
    )


@pytest.fixture
def unrelated_endpoint() -> Endpoint:
    """Parâmetro que NÃO bate no regex de identificador — nem chega a virar candidato."""
    return make_endpoint(
        "GET",
        "/api3/comment",
        parameters=[Parameter(name="category", location="query", required=False, schema_type="string")],
    )


@pytest.fixture
def synthetic_spec(api1_endpoint: Endpoint, api1_put_endpoint: Endpoint) -> OpenAPISpec:
    return OpenAPISpec(
        base_url="http://localhost:8000/vapi",
        endpoints=[api1_endpoint, api1_put_endpoint],
        security_schemes={},
        title="vAPI (teste)",
    )


@pytest.fixture
def identity_a() -> Identity:
    return Identity(label="A", username="usera", password="pwda", resource_id="1", token="dG9rZW4tYQ==")


@pytest.fixture
def identity_b() -> Identity:
    return Identity(label="B", username="userb", password="pwdb", resource_id="2", token="dG9rZW4tYg==")


def make_exchange(status_code: Optional[int], body: Any, *, error: Optional[str] = None) -> HttpExchange:
    return HttpExchange(
        exchange_id="fake",
        method="GET",
        url="http://localhost:8000/vapi/api1/user/1",
        request_headers={},
        request_body=None,
        status_code=status_code,
        response_headers={},
        response_body=body,
        latency_ms=1.0,
        error=error,
    )


def make_execution_result(
    *,
    endpoint: Endpoint,
    attacker: Identity,
    victim: Identity,
    attack_status: Optional[int],
    attack_body: Any,
    baseline_status: Optional[int] = None,
    baseline_body: Any = None,
    verification_status: Optional[int] = None,
    verification_body: Any = None,
    attack_error: Optional[str] = None,
) -> ExecutionResult:
    test_case = TestCase(
        case_id="test-case",
        endpoint=endpoint,
        target_parameter=endpoint.path_params[0].name if endpoint.path_params else "id",
        attacker=attacker,
        victim=victim,
        path_substitutions={p.name: victim.resource_id for p in endpoint.path_params},
    )
    return ExecutionResult(
        test_case=test_case,
        attack_exchange=make_exchange(attack_status, attack_body, error=attack_error),
        baseline_exchange=(
            make_exchange(baseline_status, baseline_body) if baseline_status is not None else None
        ),
        verification_exchange=(
            make_exchange(verification_status, verification_body) if verification_status is not None else None
        ),
    )


# --------------------------------------------------------------------------
# Dublê (fake) do cliente google-genai
# --------------------------------------------------------------------------


@dataclass
class FakeUsage:
    total_input_tokens: int = 42
    total_output_tokens: int = 17
    total_tokens: int = 59


@dataclass
class FakeInteraction:
    output_text: str
    usage: Optional[FakeUsage] = None


class FakeInteractionsNamespace:
    def __init__(self, handler: Callable[..., FakeInteraction]) -> None:
        self._handler = handler

    def create(self, **kwargs: Any) -> FakeInteraction:
        return self._handler(**kwargs)


class FakeGenaiClient:
    """
    Substitui google.genai.Client inteiro. `handler` decide o que
    `client.interactions.create(...)` retorna (ou levanta) para cada teste.
    """

    def __init__(self, handler: Callable[..., FakeInteraction], *args: Any, **kwargs: Any) -> None:
        self.interactions = FakeInteractionsNamespace(handler)


def _make_client_factory(handler: Callable[..., FakeInteraction]):
    def factory(*args: Any, **kwargs: Any) -> FakeGenaiClient:
        return FakeGenaiClient(handler, *args, **kwargs)

    return factory


@pytest.fixture
def patch_genai_success(monkeypatch: pytest.MonkeyPatch):
    """
    Uso: `patch_genai_success(monkeypatch, {"decisions": [...]})` — devolve
    um objeto JSON fixo como se fosse a resposta estruturada do Gemini, com
    telemetria de tokens simulada (valores fixos e conhecidos, para testar
    que a telemetria realmente captura o que a "API" retornou).
    """

    def _apply(response_payload: Dict[str, Any], usage: Optional[FakeUsage] = None) -> None:
        def handler(**kwargs: Any) -> FakeInteraction:
            return FakeInteraction(output_text=_json.dumps(response_payload), usage=usage or FakeUsage())

        import google.genai as genai_module

        monkeypatch.setattr(genai_module, "Client", _make_client_factory(handler))

    return _apply


@pytest.fixture
def patch_genai_error(monkeypatch: pytest.MonkeyPatch):
    """Uso: `patch_genai_error(monkeypatch, TimeoutError("..."))` — toda chamada levanta essa exceção."""

    def _apply(exc: Exception) -> None:
        def handler(**kwargs: Any) -> FakeInteraction:
            raise exc

        import google.genai as genai_module

        monkeypatch.setattr(genai_module, "Client", _make_client_factory(handler))

    return _apply


@pytest.fixture
def patch_genai_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Substitui google.genai.Client por um dublê que FALHA o teste se
    `interactions.create` for chamado — usado para provar afirmativamente
    que um modo/caminho de código "nunca chama o LLM" (ex.: modo
    "heuristic"), em vez de só inferir isso pela ausência de erro.
    """

    def handler(**kwargs: Any) -> FakeInteraction:
        raise AssertionError("O LLM não deveria ter sido chamado neste cenário.")

    import google.genai as genai_module

    monkeypatch.setattr(genai_module, "Client", _make_client_factory(handler))
