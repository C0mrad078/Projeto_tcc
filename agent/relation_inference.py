"""
Inferência de relações: identifica, entre os parâmetros de cada endpoint,
quais são candidatos a "identificador de objeto controlado por usuário" — ou
seja, candidatos a falha de BOLA caso o backend não verifique posse do
recurso.

ESTRATÉGIA (heurística primeiro, LLM como refinamento opcional):
1. Uma heurística por nome de parâmetro (regex) + localização (path pesa mais
   que query, que pesa mais que body) + método HTTP dá um veredito
   determinístico e reprodutível, sem custo de API — e já é suficiente para
   casos óbvios como "api1_id" em "GET /api1/user/{api1_id}".
2. Quando USE_LLM_FOR_RELATION_INFERENCE está ativo, só os candidatos com
   score "ambíguo" (nem claramente positivo, nem claramente negativo) são
   enviados ao LLM para uma segunda opinião. Isso mantém custo baixo (os
   casos óbvios nunca chegam a gerar uma chamada de API) e mantém a decisão
   auditável — a heurística sozinha já resolve os casos claros de forma
   determinística, o que importa para a reprodutibilidade dos experimentos
   do TCC.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import List, Optional

from .config import Config
from .openapi_parser import Endpoint, OpenAPISpec, Parameter

# Casa nomes como "id", "user_id", "api1_id", "orderId", "uuid", "account_uid".
ID_PARAM_RE = re.compile(r"(?i)^(id|.*_id|.*id|uuid|.*_uuid|.*_uid|guid|.*_guid)$")

LOCATION_WEIGHT = {"path": 0.9, "query": 0.5, "body": 0.4, "header": 0.2, "cookie": 0.2}
METHOD_WEIGHT = {"GET": 1.0, "PUT": 1.0, "PATCH": 1.0, "DELETE": 1.0, "POST": 0.6}

CONFIRM_THRESHOLD = 0.7
REJECT_THRESHOLD = 0.3


@dataclass
class RelationCandidate:
    endpoint: Endpoint
    parameter: Parameter
    score: float
    source: str  # "heuristic" | "llm"
    rationale: str


def _heuristic_score(endpoint: Endpoint, parameter: Parameter) -> float:
    if not ID_PARAM_RE.match(parameter.name):
        return 0.0
    location_weight = LOCATION_WEIGHT.get(parameter.location, 0.2)
    method_weight = METHOD_WEIGHT.get(endpoint.method, 0.5)
    return location_weight * method_weight


def infer_relations(spec: OpenAPISpec, use_llm: Optional[bool] = None) -> List[RelationCandidate]:
    use_llm = Config.USE_LLM_FOR_RELATION_INFERENCE if use_llm is None else use_llm

    confirmed: List[RelationCandidate] = []
    ambiguous: List[RelationCandidate] = []

    for endpoint in spec.endpoints:
        if not endpoint.requires_auth:
            # BOLA pressupõe uma identidade autenticada cujo acesso pode ser
            # indevidamente concedido a outra — endpoints públicos (login,
            # registro) ficam fora do escopo de candidatos por definição.
            continue
        for parameter in endpoint.parameters:
            score = _heuristic_score(endpoint, parameter)
            if score <= REJECT_THRESHOLD:
                continue
            candidate = RelationCandidate(
                endpoint=endpoint,
                parameter=parameter,
                score=score,
                source="heuristic",
                rationale=(
                    f"Nome '{parameter.name}' corresponde ao padrão de identificador "
                    f"(localização={parameter.location}, método={endpoint.method})."
                ),
            )
            if score >= CONFIRM_THRESHOLD:
                confirmed.append(candidate)
            else:
                ambiguous.append(candidate)

    if ambiguous and use_llm:
        try:
            ambiguous = _llm_refine(ambiguous, Config.LLM_MODEL)
        except Exception as exc:  # noqa: BLE001
            # Captura ampla e deliberada: o refinamento por LLM é um passo
            # opcional. Qualquer falha aqui (chave ausente, rede, erro da
            # API) deve degradar para a lista heurística original, nunca
            # derrubar o pipeline inteiro — mas o aviso é impresso de forma
            # explícita para não mascarar a limitação.
            print(
                f"[relation_inference] Aviso: refinamento por LLM falhou ({exc}); "
                f"mantendo {len(ambiguous)} candidato(s) apenas com a heurística."
            )

    return confirmed + ambiguous


def _llm_refine(candidates: List[RelationCandidate], model: str) -> List[RelationCandidate]:
    import anthropic

    client = anthropic.Anthropic()
    items = [
        {
            "index": i,
            "method": c.endpoint.method,
            "path": c.endpoint.path,
            "parameter": c.parameter.name,
            "location": c.parameter.location,
        }
        for i, c in enumerate(candidates)
    ]
    schema = {
        "type": "object",
        "properties": {
            "decisions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer"},
                        "is_object_identifier": {"type": "boolean"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["index", "is_object_identifier", "rationale"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["decisions"],
        "additionalProperties": False,
    }
    prompt = (
        "Você é um especialista em segurança de APIs REST (OWASP API Top 10). "
        "Para cada item da lista abaixo, decida se o parâmetro provavelmente "
        "identifica um recurso pertencente a um usuário específico (candidato "
        "a falha de BOLA/IDOR caso o backend não verifique posse), ou se é um "
        "identificador não relacionado a controle de acesso por usuário "
        "(ex.: categoria de produto, enum, código de país).\n\n"
        f"Itens:\n{json.dumps(items, ensure_ascii=False, indent=2)}"
    )
    response = client.messages.create(
        model=model,
        max_tokens=4096,
        output_config={"effort": "low", "format": {"type": "json_schema", "schema": schema}},
        messages=[{"role": "user", "content": prompt}],
    )
    text = next(b.text for b in response.content if b.type == "text")
    decisions = {d["index"]: d for d in json.loads(text)["decisions"]}

    refined: List[RelationCandidate] = []
    for i, candidate in enumerate(candidates):
        decision = decisions.get(i)
        if decision is None:
            # Sem decisão do LLM para este índice (resposta incompleta):
            # mantém a heurística original em vez de descartar silenciosamente.
            refined.append(candidate)
            continue
        if decision["is_object_identifier"]:
            refined.append(
                RelationCandidate(
                    endpoint=candidate.endpoint,
                    parameter=candidate.parameter,
                    score=max(candidate.score, 0.75),
                    source="llm",
                    rationale=decision["rationale"],
                )
            )
        # Se o LLM rejeitar, o candidato é descartado e não vira caso de teste.
    return refined
