"""
Inferência de relações: identifica, entre os parâmetros de cada endpoint,
quais são candidatos a "identificador de objeto controlado por usuário" — ou
seja, candidatos a falha de BOLA caso o backend não verifique posse do
recurso.

ARQUITETURA HÍBRIDA (Fase 2 da refatoração metodológica do TCC): dois níveis
de decisão, sempre nesta ordem de prioridade —

1. HEURÍSTICA (determinística, sem custo de API): nome do parâmetro (regex)
   + localização (path pesa mais que query, que pesa mais que body) + método
   HTTP. Suficiente para casos óbvios como "api1_id" em
   "GET /api1/user/{api1_id}".
2. LLM (Google Gemini): só entra quando a heurística não tem confiança
   suficiente (score na faixa ambígua entre REJECT_THRESHOLD e
   CONFIRM_THRESHOLD) — no modo "hybrid" (recomendado/default). Ver
   `agent.config.Mode` para os três modos experimentais.

Cada candidato carrega uma `Decision` (agent/decision.py) registrando
explicitamente qual mecanismo decidiu, o motivo, e a confiança (nunca
inventada — `None` quando não há como calcular).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import List, Optional

from .config import Config, Mode
from .decision import Decision
from .llm_telemetry import telemetry
from .openapi_parser import Endpoint, OpenAPISpec, Parameter

# Casa nomes como "id", "user_id", "api1_id", "orderId", "uuid", "account_uid".
ID_PARAM_RE = re.compile(r"(?i)^(id|.*_id|.*id|uuid|.*_uuid|.*_uid|guid|.*_guid)$")

LOCATION_WEIGHT = {"path": 0.9, "query": 0.5, "body": 0.4, "header": 0.2, "cookie": 0.2}
METHOD_WEIGHT = {"GET": 1.0, "PUT": 1.0, "PATCH": 1.0, "DELETE": 1.0, "POST": 0.6}

CONFIRM_THRESHOLD = 0.7
REJECT_THRESHOLD = 0.3

TELEMETRY_MODULE = "relation_inference"


@dataclass
class RelationCandidate:
    endpoint: Endpoint
    parameter: Parameter
    score: float  # sinal heurístico bruto (0-1) — sempre calculado, mesmo quando a decisão final vem do LLM
    decision: Decision


def _heuristic_score(endpoint: Endpoint, parameter: Parameter) -> float:
    if not ID_PARAM_RE.match(parameter.name):
        return 0.0
    location_weight = LOCATION_WEIGHT.get(parameter.location, 0.2)
    method_weight = METHOD_WEIGHT.get(endpoint.method, 0.5)
    return location_weight * method_weight


def _heuristic_candidate(endpoint: Endpoint, parameter: Parameter, score: float) -> RelationCandidate:
    return RelationCandidate(
        endpoint=endpoint,
        parameter=parameter,
        score=score,
        decision=Decision(
            decision_source="heuristic",
            reason=(
                f"Nome '{parameter.name}' corresponde ao padrão de identificador "
                f"(localização={parameter.location}, método={endpoint.method}, score={score:.2f})."
            ),
            confidence=score,
        ),
    )


def infer_relations(spec: OpenAPISpec, mode: Optional[Mode] = None) -> List[RelationCandidate]:
    """
    `mode` controla como os dois níveis de decisão interagem (ver
    agent.config.Mode); default: Config.MODE ("hybrid").

    - "heuristic": só a heurística decide. Candidatos na faixa ambígua NUNCA
      são confirmados (ficam de fora) — não há para onde escalar a dúvida.
    - "hybrid" (recomendado): heurística decide os casos claros; candidatos
      ambíguos vão para o LLM como desempate. Se o LLM confirmar, a decisão
      final é rotulada "hybrid" (a heurística já tinha sinalizado o
      candidato — não é o LLM decidindo do zero).
    - "llm": modo experimental — TODO parâmetro que bate no regex de
      identificador é enviado ao LLM, mesmo os que a heurística já
      confirmaria sozinha. Existe para permitir, futuramente, um estudo de
      ablação comparando heurística pura vs. híbrido vs. LLM puro (ver
      README). NÃO é o modo recomendado para uso normal.
    """
    mode = mode or Config.MODE

    confirmed: List[RelationCandidate] = []
    ambiguous: List[RelationCandidate] = []
    llm_forced: List[RelationCandidate] = []

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
            candidate = _heuristic_candidate(endpoint, parameter, score)
            if mode == "llm":
                llm_forced.append(candidate)
            elif score >= CONFIRM_THRESHOLD:
                confirmed.append(candidate)
            else:
                ambiguous.append(candidate)

    if mode == "heuristic":
        # Sem LLM para desempatar: candidatos ambíguos ficam de fora — a
        # heurística sozinha não tem como confirmá-los, e mantê-los como
        # "confirmados" sem verificação seria uma falha de precisão do
        # próprio modo heurístico (ver Fase 5: este é o baseline "só
        # heurística" do futuro estudo de ablação).
        return confirmed

    if mode == "llm":
        try:
            return _llm_refine(llm_forced, Config.LLM_MODEL, force=True)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[relation_inference] Aviso: modo 'llm' falhou ({exc}); "
                f"degradando para a heurística em {len(llm_forced)} candidato(s)."
            )
            return [c for c in llm_forced if c.score >= CONFIRM_THRESHOLD]

    # mode == "hybrid" (default)
    if ambiguous:
        try:
            ambiguous = _llm_refine(ambiguous, Config.LLM_MODEL, force=False)
        except Exception as exc:  # noqa: BLE001
            # Captura ampla e deliberada: o refinamento por LLM é um passo
            # opcional em modo híbrido. Qualquer falha aqui (chave ausente,
            # rede, erro da API) deve degradar para a lista heurística
            # original, nunca derrubar o pipeline inteiro — mas o aviso é
            # impresso de forma explícita para não mascarar a limitação.
            print(
                f"[relation_inference] Aviso: refinamento por LLM falhou ({exc}); "
                f"mantendo {len(ambiguous)} candidato(s) apenas com a heurística."
            )

    return confirmed + ambiguous


def _llm_refine(
    candidates: List[RelationCandidate], model: str, *, force: bool
) -> List[RelationCandidate]:
    """
    `force=False` (modo "hybrid"): só é chamada com candidatos que a
    heurística já marcou como ambíguos — a decisão final, se o LLM
    confirmar, é rotulada "hybrid" porque a heurística contribuiu com o
    sinal inicial.

    `force=True` (modo "llm"): candidatos podem já ter score de heurística
    confiante; o LLM decide de qualquer forma, e a decisão final é rotulada
    "llm" puro — é o LLM substituindo a heurística, não complementando.
    """
    if not candidates:
        return []

    from google import genai

    client = genai.Client(api_key=Config.GOOGLE_API_KEY) if Config.GOOGLE_API_KEY else genai.Client()
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
                        "confidence": {
                            "type": "number",
                            "description": "Confiança própria do modelo na decisão, de 0.0 a 1.0.",
                        },
                    },
                    "required": ["index", "is_object_identifier", "rationale", "confidence"],
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

    reason_for_call = (
        "candidato marcado como forçado pelo modo experimental 'llm'"
        if force
        else "score heurístico na faixa ambígua (entre REJECT_THRESHOLD e CONFIRM_THRESHOLD)"
    )
    start = time.monotonic()
    error_str: Optional[str] = None
    decisions: dict = {}
    try:
        interaction = client.interactions.create(
            model=model,
            input=prompt,
            # "schema_" (com underscore) é o nome de campo correto no SDK
            # google-genai instalado (verificado por introspecção do pacote —
            # a documentação pública, no momento em que este código foi escrito,
            # mostrava "schema" sem underscore, o que causaria erro).
            response_format={"type": "text", "mime_type": "application/json", "schema_": schema},
            timeout=Config.LLM_TIMEOUT_S,
        )
        decisions = {d["index"]: d for d in json.loads(interaction.output_text)["decisions"]}
        usage = interaction.usage
        telemetry.record(
            module=TELEMETRY_MODULE,
            reason=reason_for_call,
            model=model,
            duration_ms=(time.monotonic() - start) * 1000,
            input_tokens=getattr(usage, "total_input_tokens", None) if usage else None,
            output_tokens=getattr(usage, "total_output_tokens", None) if usage else None,
            total_tokens=getattr(usage, "total_tokens", None) if usage else None,
            result_summary=f"{len(decisions)} decisão(ões) recebida(s) para {len(candidates)} candidato(s).",
        )
    except Exception as exc:  # noqa: BLE001
        error_str = str(exc)
        telemetry.record(
            module=TELEMETRY_MODULE,
            reason=reason_for_call,
            model=model,
            duration_ms=(time.monotonic() - start) * 1000,
            error=error_str,
            fallback_used=True,
        )
        raise

    refined: List[RelationCandidate] = []
    decision_source = "llm" if force else "hybrid"
    for i, candidate in enumerate(candidates):
        llm_decision = decisions.get(i)
        if llm_decision is None:
            # Sem decisão do LLM para este índice (resposta incompleta):
            # mantém a heurística original em vez de descartar silenciosamente.
            refined.append(candidate)
            continue
        if llm_decision["is_object_identifier"]:
            refined.append(
                RelationCandidate(
                    endpoint=candidate.endpoint,
                    parameter=candidate.parameter,
                    score=candidate.score,
                    decision=Decision(
                        decision_source=decision_source,
                        reason=llm_decision["rationale"],
                        # Auto-reportada pelo próprio modelo via schema
                        # estruturado — NÃO é uma confiança calibrada
                        # estatisticamente, é a estimativa do modelo sobre
                        # si mesmo. Documentado como tal no relatório e no
                        # README; nunca substituída por um valor inventado.
                        confidence=llm_decision.get("confidence"),
                        model=model,
                    ),
                )
            )
        # Se o LLM rejeitar, o candidato é descartado e não vira caso de teste.
    return refined
