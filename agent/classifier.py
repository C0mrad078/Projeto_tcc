"""
Classificador de veredito para cada ExecutionResult.

TRÊS VEREDITOS POSSÍVEIS (taxonomia usada no desenho experimental do TCC):
  - "confirmed": há evidência de que o atacante acessou/alterou o recurso da
    vítima (falha de BOLA confirmada).
  - "not_found": o backend negou o acesso corretamente (não há falha de BOLA
    neste caso). O nome não se refere ao HTTP 404 — refere-se a "nenhuma
    falha foi encontrada", inclusive quando a negação vem como 401/403.
  - "ambiguous": a heurística não teve confiança suficiente; se
    USE_LLM_FOR_CLASSIFICATION estiver ativo, o LLM decide como desempate,
    senão o caso fica marcado para revisão manual.

DECISÃO DE DESIGN: a heurística decide sozinha os casos óbvios (401/403 nega;
200 com corpo claramente correspondente à vítima confirma) para manter o LLM
fora do caminho crítico — reduz custo e, mais importante, mantém
determinismo/reprodutibilidade nos casos que não exigem julgamento semântico
sobre o conteúdo da resposta.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional

from .config import Config
from .executor import ExecutionResult
from .test_generator import canary_value

CONFIRMED = "confirmed"
NOT_FOUND = "not_found"
AMBIGUOUS = "ambiguous"


@dataclass
class Verdict:
    result: str  # CONFIRMED | NOT_FOUND | AMBIGUOUS
    reason: str
    source: str  # "heuristic" | "llm"
    confidence: float


def _body_contains(body: Any, needle: str) -> bool:
    """
    Busca ingênua (mas explícita) por uma string em qualquer lugar do corpo
    da resposta.

    CUIDADO: se `needle` for puramente numérico (ex.: um ID incremental "1"
    ou "2", comum em bancos de teste recém-criados), uma busca por substring
    simples teria alto risco de falso positivo — bastaria o corpo conter
    "201" (um status HTTP, uma contagem, etc.) para "casar" com o ID "1" ou
    "2" de vAPI. Por isso, para needles numéricos, exigimos que não haja
    outro dígito colado antes/depois (fronteira de número). Para needles não
    numéricos (ex.: um ObjectId hexadecimal de 24 caracteres, ou o canário
    "bola-test-a"), a colisão por substring é considerada improvável o
    suficiente para manter a busca simples.
    """
    if body is None:
        return False
    text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    if needle.isdigit():
        return re.search(rf"(?<!\d){re.escape(needle)}(?!\d)", text) is not None
    return needle in text


def _bodies_match(baseline_body: Any, attack_body: Any) -> bool:
    if baseline_body is None or attack_body is None:
        return False
    return json.dumps(baseline_body, sort_keys=True, ensure_ascii=False) == json.dumps(
        attack_body, sort_keys=True, ensure_ascii=False
    )


def classify_heuristic(result: ExecutionResult) -> Verdict:
    attack = result.attack_exchange
    victim_id = str(result.test_case.victim.resource_id)

    if attack.error is not None:
        return Verdict(AMBIGUOUS, f"Erro de rede/execução: {attack.error}", "heuristic", 0.0)

    if attack.status_code in (401, 403):
        return Verdict(
            NOT_FOUND, f"Acesso negado corretamente (HTTP {attack.status_code}).", "heuristic", 0.9
        )

    if attack.status_code == 404:
        # 404 é estruturalmente ambíguo sem um baseline: pode ser proteção
        # por "404 disfarçado" (o backend nega escondendo a existência do
        # recurso) OU uma divergência entre a spec manual e o comportamento
        # real do endpoint (ex.: formato de ID errado).
        if result.baseline_exchange and result.baseline_exchange.status_code == 200:
            return Verdict(
                AMBIGUOUS,
                "Atacante recebeu 404 mas a vítima consegue acessar o próprio "
                "recurso (200) — pode ser proteção por 404 disfarçado OU "
                "imprecisão da spec quanto ao formato do identificador.",
                "heuristic",
                0.4,
            )
        return Verdict(
            AMBIGUOUS,
            "404 tanto para o atacante quanto (possivelmente) para a vítima — "
            "possível divergência entre a spec manual e o comportamento real do endpoint.",
            "heuristic",
            0.3,
        )

    if attack.status_code is not None and 200 <= attack.status_code < 300:
        if result.test_case.endpoint.method == "GET":
            if _body_contains(attack.response_body, victim_id):
                return Verdict(
                    CONFIRMED,
                    f"HTTP {attack.status_code} e o corpo da resposta contém o "
                    f"identificador da vítima ({victim_id}).",
                    "heuristic",
                    0.85,
                )
            if result.baseline_exchange and _bodies_match(
                result.baseline_exchange.response_body, attack.response_body
            ):
                return Verdict(
                    CONFIRMED,
                    "HTTP 200 e o corpo da resposta é idêntico ao baseline da vítima.",
                    "heuristic",
                    0.9,
                )
            return Verdict(
                AMBIGUOUS,
                "HTTP 200 mas não foi possível confirmar heuristicamente que o "
                "corpo pertence à vítima (pode ser um corpo genérico ou um "
                "erro disfarçado de 200).",
                "heuristic",
                0.3,
            )

        # PUT/PATCH: só a verificação pós-ataque prova exploração real.
        expected_canary = canary_value(result.test_case.attacker.label)
        if result.verification_exchange and _body_contains(
            result.verification_exchange.response_body, expected_canary
        ):
            return Verdict(
                CONFIRMED,
                "A escrita do atacante persistiu no recurso da vítima "
                "(confirmado via GET de verificação pós-ataque).",
                "heuristic",
                0.9,
            )
        return Verdict(
            AMBIGUOUS,
            f"HTTP {attack.status_code} na escrita, mas a verificação pós-ataque "
            "não confirmou que o valor do atacante persistiu.",
            "heuristic",
            0.3,
        )

    return Verdict(
        AMBIGUOUS,
        f"Status HTTP inesperado ({attack.status_code}) não coberto pela heurística.",
        "heuristic",
        0.2,
    )


def _llm_tie_break(result: ExecutionResult, model: str) -> Optional[Verdict]:
    from google import genai

    client = genai.Client(api_key=Config.GOOGLE_API_KEY) if Config.GOOGLE_API_KEY else genai.Client()
    payload = {
        "endpoint": f"{result.test_case.endpoint.method} {result.test_case.endpoint.path}",
        "attacker": result.test_case.attacker.label,
        "victim": result.test_case.victim.label,
        "victim_resource_id": result.test_case.victim.resource_id,
        "attack_status": result.attack_exchange.status_code,
        "attack_body": result.attack_exchange.response_body,
        "baseline_status": result.baseline_exchange.status_code if result.baseline_exchange else None,
        "baseline_body": result.baseline_exchange.response_body if result.baseline_exchange else None,
        "verification_status": (
            result.verification_exchange.status_code if result.verification_exchange else None
        ),
        "verification_body": (
            result.verification_exchange.response_body if result.verification_exchange else None
        ),
    }
    schema = {
        "type": "object",
        "properties": {
            "result": {"type": "string", "enum": [CONFIRMED, NOT_FOUND, AMBIGUOUS]},
            "reason": {"type": "string"},
            "confidence": {"type": "number"},
        },
        "required": ["result", "reason", "confidence"],
        "additionalProperties": False,
    }
    prompt = (
        "Você está analisando o resultado de um teste de BOLA (Broken Object "
        "Level Authorization) contra uma API REST. Um atacante autenticado "
        "tentou acessar/alterar o recurso de outro usuário (a vítima) usando "
        "o identificador de recurso da vítima. Decida se a evidência abaixo "
        "CONFIRMA a falha, NÃO confirma (proteção correta), ou permanece "
        "AMBÍGUA mesmo após sua análise.\n\n"
        f"Evidência (JSON):\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )
    try:
        interaction = client.interactions.create(
            model=model,
            input=prompt,
            # Ver nota equivalente em relation_inference.py: "schema_" (com
            # underscore) é o nome de campo correto no SDK google-genai
            # instalado, verificado por introspecção do pacote.
            response_format={"type": "text", "mime_type": "application/json", "schema_": schema},
        )
    except Exception as exc:  # noqa: BLE001
        # Captura ampla e deliberada (ver relation_inference.py para a mesma
        # decisão): o desempate por LLM é um refinamento opcional. Qualquer
        # falha aqui deve degradar para o veredito heurístico "ambiguous",
        # nunca derrubar o pipeline inteiro.
        print(f"[classifier] Aviso: desempate por LLM falhou ({exc}); mantendo veredito ambíguo.")
        return None

    data = json.loads(interaction.output_text)
    return Verdict(data["result"], data["reason"], "llm", float(data["confidence"]))


def classify(result: ExecutionResult) -> Verdict:
    heuristic_verdict = classify_heuristic(result)
    if heuristic_verdict.result != AMBIGUOUS:
        return heuristic_verdict
    if not Config.USE_LLM_FOR_CLASSIFICATION:
        return heuristic_verdict
    llm_verdict = _llm_tie_break(result, Config.LLM_MODEL)
    return llm_verdict or heuristic_verdict
