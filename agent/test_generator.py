"""
Geração de casos de teste cruzados de BOLA.

ESTRATÉGIA CENTRAL: para cada RelationCandidate (endpoint + parâmetro que
identifica um recurso de usuário), gera dois casos de teste:
  1. Usuário B ataca o recurso do Usuário A (token de B, mas ID de A).
  2. Usuário A ataca o recurso do Usuário B (token de A, mas ID de B).

LIMITAÇÃO CONHECIDA (relevante para a seção de ameaças à validade do TCC): o
vAPI não expõe um endpoint de listagem de recursos. Por isso o "recurso
conhecido" de cada usuário usado aqui é sempre o próprio perfil (USER_A_ID /
USER_B_ID, vindos do .env), nunca um recurso descoberto dinamicamente. Isso
significa que, neste ambiente, o agente só consegue testar BOLA sobre o
recurso "usuário" — não generaliza para recursos subordinados (ex.: pedidos
de um usuário) sem uma fonte adicional de identificadores.

LIMITAÇÃO CONHECIDA #2: quando um endpoint tem mais de um parâmetro de path,
todos são substituídos pelo ID da vítima (não só o parâmetro candidato). Isso
é suficiente para os endpoints do vAPI avaliados aqui (um único parâmetro de
path cada), mas não seria correto para um endpoint hipotético do tipo
"/users/{user_id}/orders/{order_id}" onde só um dos dois deveria variar.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Identity
from .openapi_parser import Endpoint, Parameter
from .relation_inference import RelationCandidate

# Prefixo do valor "canário" injetado em escritas (PUT/PATCH) para permitir
# que o classifier confirme, via GET de verificação pós-ataque, se a escrita
# do atacante realmente persistiu no recurso da vítima.
CANARY_PREFIX = "bola-test"

# INCIDENTE REAL (rodada contra o vAPI real, 2026-09-05): a primeira versão
# deste probe preenchia TODOS os campos de body do schema com o canário —
# incluindo "username" e "password" no PUT /api1/user/{api1_id}. Como o vAPI
# autentica comparando username/senha em texto puro contra a tabela, isso
# sobrescreveu as credenciais da PRÓPRIA VÍTIMA durante o ataque, quebrando a
# verificação pós-ataque (que usa o token original da vítima) e invalidando o
# .env no meio da execução. Por isso excluímos explicitamente campos com cara
# de credencial do probe de escrita — o canário ainda fica visível via outros
# campos do corpo (ex.: "name", "course"), então a capacidade de detecção não
# é perdida.
CREDENTIAL_LIKE_FIELD_NAMES = {"username", "password", "email", "token", "secret", "api_key", "apikey"}


@dataclass
class TestCase:
    case_id: str
    endpoint: Endpoint
    target_parameter: str  # nome do parâmetro candidato (ex.: "api1_id")
    attacker: Identity
    victim: Identity
    path_substitutions: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None


def canary_value(attacker_label: str) -> str:
    return f"{CANARY_PREFIX}-{attacker_label.lower()}"


def _attacker_body_probe(endpoint: Endpoint, attacker: Identity) -> Optional[Dict[str, Any]]:
    """
    Para métodos de escrita (PUT/PATCH), monta um corpo mínimo de sondagem:
    preenche os campos de body do schema (exceto os de cara de credencial —
    ver CREDENTIAL_LIKE_FIELD_NAMES) com um valor "canário" fácil de
    reconhecer na resposta (contém o rótulo do atacante).
    """
    if endpoint.method not in {"PUT", "PATCH"}:
        return None
    body: Dict[str, Any] = {}
    canary = canary_value(attacker.label)
    for param in endpoint.parameters:
        if param.location != "body":
            continue
        if param.name.lower() in CREDENTIAL_LIKE_FIELD_NAMES:
            continue
        if param.schema_type in (None, "string"):
            body[param.name] = canary
        elif param.schema_type in {"integer", "number"}:
            body[param.name] = 1
        elif param.schema_type == "boolean":
            body[param.name] = True
    return body or None


def _build_target(
    endpoint: Endpoint, candidate_param: Parameter, victim_id: str
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any]]:
    """Retorna (path_substitutions, query_params, body_overrides) para o ataque."""
    path_substitutions = {p.name: victim_id for p in endpoint.path_params}
    query_params: Dict[str, str] = {}
    body_overrides: Dict[str, Any] = {}

    if candidate_param.location == "query":
        query_params[candidate_param.name] = victim_id
    elif candidate_param.location == "body":
        body_overrides[candidate_param.name] = victim_id

    return path_substitutions, query_params, body_overrides


def generate_test_cases(
    candidates: List[RelationCandidate],
    identity_resolver: Callable[[str], Tuple[Identity, Identity]],
) -> List[TestCase]:
    """
    `identity_resolver(module) -> (user_a, user_b)` retorna o par de
    identidades a usar para um dado módulo do vAPI (ex.: "api1", "api5").

    DECISÃO DE DESIGN: recebemos um resolvedor em vez de um par fixo de
    Identity porque cada módulo do vAPI tem sua própria tabela de usuários —
    "Usuário A no api1" e "Usuário A no api5" são contas diferentes, com IDs
    e credenciais independentes (ver config.py). O resolvedor permite ao
    orchestrator decidir/cachear como resolver isso sem test_generator.py
    precisar saber de onde vêm as credenciais.
    """
    cases: List[TestCase] = []
    seen: set = set()

    for candidate in candidates:
        endpoint = candidate.endpoint
        key = (endpoint.method, endpoint.path, candidate.parameter.name)
        if key in seen:
            continue
        seen.add(key)

        user_a, user_b = identity_resolver(endpoint.module)

        for attacker, victim in ((user_b, user_a), (user_a, user_b)):
            if victim.resource_id is None:
                continue

            path_substitutions, query_params, body_overrides = _build_target(
                endpoint, candidate.parameter, victim.resource_id
            )

            body = _attacker_body_probe(endpoint, attacker)
            if body_overrides:
                body = {**(body or {}), **body_overrides}

            case_id = (
                f"{endpoint.method}:{endpoint.path}:{candidate.parameter.name}:"
                f"{attacker.label}->{victim.label}"
            )
            cases.append(
                TestCase(
                    case_id=case_id,
                    endpoint=endpoint,
                    target_parameter=candidate.parameter.name,
                    attacker=attacker,
                    victim=victim,
                    path_substitutions=path_substitutions,
                    query_params=query_params,
                    body=body,
                )
            )

    return cases
