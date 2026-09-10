"""
Classificador de veredito para cada ExecutionResult.

TRÊS VEREDITOS POSSÍVEIS (taxonomia usada no desenho experimental do TCC):
  - "confirmed": há evidência de que o atacante acessou/alterou o recurso da
    vítima (falha de BOLA confirmada).
  - "not_found": o backend negou o acesso corretamente (não há falha de BOLA
    neste caso). O nome não se refere ao HTTP 404 — refere-se a "nenhuma
    falha foi encontrada", inclusive quando a negação vem como 401/403.
  - "ambiguous": a heurística não teve confiança suficiente; o que acontece
    a seguir depende do modo (ver `mode` em `classify()`).

ARQUITETURA HÍBRIDA (Fase 2 da refatoração metodológica): a heurística decide
sozinha os casos óbvios (401/403 nega; 200 com corpo claramente
correspondente à vítima confirma) para manter o LLM fora do caminho crítico
— reduz custo e, mais importante, mantém determinismo/reprodutibilidade nos
casos que não exigem julgamento semântico sobre o conteúdo da resposta. Cada
veredito carrega uma `Decision` (agent/decision.py) registrando o mecanismo,
o motivo e a confiança (nunca inventada).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

from .config import Config, Mode
from .decision import Decision
from .executor import ExecutionResult
from .llm_telemetry import telemetry
from .test_generator import canary_value

CONFIRMED = "confirmed"
NOT_FOUND = "not_found"
AMBIGUOUS = "ambiguous"

TELEMETRY_MODULE = "response_classification"


@dataclass
class Verdict:
    result: str  # CONFIRMED | NOT_FOUND | AMBIGUOUS
    decision: Decision


def _body_contains(body: Any, needle: str) -> bool:
    r"""
    Busca por uma string em qualquer lugar do corpo da resposta, exigindo
    fronteira de "palavra" (\b) dos dois lados — não uma substring nua.

    HISTÓRICO: a primeira versão só evitava colisão entre dígitos (ex.: ID
    "1" não deveria casar com "201"), usando lookaround negativo restrito a
    \d. Isso deixava passar um caso real, encontrado testando um cenário
    de ambiguidade genuína (ver README, "Caso ambíguo de demonstração"): um
    ID numérico "1" "casava" com o final de um identificador alfanumérico
    como "demoaea06a1", porque a letra "a" antes do "1" não é um dígito, mas
    também não é uma fronteira de palavra de verdade. \b do Python trata
    letras/dígitos/underscore como caractere de "palavra", então
    \b1\b NÃO casa dentro de "201" (dígitos grudados) NEM dentro de
    "demoaea06a1" (letra grudada) — resolve os dois casos com uma regra só,
    e vale tanto para needles numéricos (IDs) quanto não-numéricos (ex.: o
    canário "bola-test-a").
    """
    if body is None:
        return False
    text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    return re.search(rf"\b{re.escape(needle)}\b", text) is not None


def _bodies_match(baseline_body: Any, attack_body: Any) -> bool:
    if baseline_body is None or attack_body is None:
        return False
    return json.dumps(baseline_body, sort_keys=True, ensure_ascii=False) == json.dumps(
        attack_body, sort_keys=True, ensure_ascii=False
    )


def classify_heuristic(result: ExecutionResult) -> Verdict:
    start = time.monotonic()
    verdict = _classify_heuristic_impl(result)
    verdict.decision.duration_ms = (time.monotonic() - start) * 1000
    return verdict


def _heuristic_verdict(result: str, reason: str, confidence: float) -> Verdict:
    return Verdict(result=result, decision=Decision(decision_source="heuristic", reason=reason, confidence=confidence))


def _classify_heuristic_impl(result: ExecutionResult) -> Verdict:
    attack = result.attack_exchange
    victim_id = str(result.test_case.victim.resource_id)

    if attack.error is not None:
        return _heuristic_verdict(AMBIGUOUS, f"Erro de rede/execução: {attack.error}", 0.0)

    if attack.status_code in (401, 403):
        return _heuristic_verdict(
            NOT_FOUND, f"Acesso negado corretamente (HTTP {attack.status_code}).", 0.9
        )

    if attack.status_code == 404:
        # 404 é estruturalmente ambíguo sem um baseline: pode ser proteção
        # por "404 disfarçado" (o backend nega escondendo a existência do
        # recurso) OU uma divergência entre a spec manual e o comportamento
        # real do endpoint (ex.: formato de ID errado).
        if result.baseline_exchange and result.baseline_exchange.status_code == 200:
            return _heuristic_verdict(
                AMBIGUOUS,
                "Atacante recebeu 404 mas a vítima consegue acessar o próprio "
                "recurso (200) — pode ser proteção por 404 disfarçado OU "
                "imprecisão da spec quanto ao formato do identificador.",
                0.4,
            )
        return _heuristic_verdict(
            AMBIGUOUS,
            "404 tanto para o atacante quanto (possivelmente) para a vítima — "
            "possível divergência entre a spec manual e o comportamento real do endpoint.",
            0.3,
        )

    if attack.status_code is not None and 200 <= attack.status_code < 300:
        if result.test_case.endpoint.method == "GET":
            if _body_contains(attack.response_body, victim_id):
                return _heuristic_verdict(
                    CONFIRMED,
                    f"HTTP {attack.status_code} e o corpo da resposta contém o "
                    f"identificador da vítima ({victim_id}).",
                    0.85,
                )
            if result.baseline_exchange and _bodies_match(
                result.baseline_exchange.response_body, attack.response_body
            ):
                return _heuristic_verdict(
                    CONFIRMED, "HTTP 200 e o corpo da resposta é idêntico ao baseline da vítima.", 0.9
                )
            return _heuristic_verdict(
                AMBIGUOUS,
                "HTTP 200 mas não foi possível confirmar heuristicamente que o "
                "corpo pertence à vítima (pode ser um corpo genérico ou um "
                "erro disfarçado de 200).",
                0.3,
            )

        # PUT/PATCH: só a verificação pós-ataque prova exploração real.
        expected_canary = canary_value(result.test_case.attacker.label)
        if result.verification_exchange and _body_contains(
            result.verification_exchange.response_body, expected_canary
        ):
            return _heuristic_verdict(
                CONFIRMED,
                "A escrita do atacante persistiu no recurso da vítima "
                "(confirmado via GET de verificação pós-ataque).",
                0.9,
            )
        return _heuristic_verdict(
            AMBIGUOUS,
            f"HTTP {attack.status_code} na escrita, mas a verificação pós-ataque "
            "não confirmou que o valor do atacante persistiu.",
            0.3,
        )

    return _heuristic_verdict(
        AMBIGUOUS, f"Status HTTP inesperado ({attack.status_code}) não coberto pela heurística.", 0.2
    )


def _llm_tie_break(result: ExecutionResult, model: str, *, decision_source: str) -> Optional[Verdict]:
    """
    `decision_source` é "hybrid" quando chamada a partir do modo "hybrid"
    (a heurística já produziu um veredito AMBIGUOUS, e o LLM está
    desempatando esse sinal) ou "llm" quando chamada a partir do modo
    experimental "llm" (o LLM decide mesmo sobre casos que a heurística já
    teria resolvido com confiança).
    """
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

    reason_for_call = (
        "modo experimental 'llm': reavaliação forçada de um veredito que a heurística já resolveria"
        if decision_source == "llm"
        else "veredito heurístico ambíguo — desempate necessário"
    )
    start = time.monotonic()
    try:
        interaction = client.interactions.create(
            model=model,
            input=prompt,
            # Ver nota equivalente em relation_inference.py: "schema_" (com
            # underscore) é o nome de campo correto no SDK google-genai
            # instalado, verificado por introspecção do pacote.
            response_format={"type": "text", "mime_type": "application/json", "schema_": schema},
            timeout=Config.LLM_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001
        # Captura ampla e deliberada (ver relation_inference.py para a mesma
        # decisão): o desempate por LLM é um refinamento opcional em modo
        # híbrido (e, no modo "llm", a única fonte de decisão — se falhar
        # ali, o chamador decide como degradar). Qualquer falha aqui nunca
        # derruba o pipeline inteiro.
        duration_ms = (time.monotonic() - start) * 1000
        telemetry.record(
            module=TELEMETRY_MODULE,
            reason=reason_for_call,
            model=model,
            duration_ms=duration_ms,
            error=str(exc),
            fallback_used=True,
        )
        print(f"[classifier] Aviso: chamada ao LLM falhou ({exc}); mantendo veredito heurístico.")
        return None

    data = json.loads(interaction.output_text)
    duration_ms = (time.monotonic() - start) * 1000
    usage = interaction.usage
    telemetry.record(
        module=TELEMETRY_MODULE,
        reason=reason_for_call,
        model=model,
        duration_ms=duration_ms,
        input_tokens=getattr(usage, "total_input_tokens", None) if usage else None,
        output_tokens=getattr(usage, "total_output_tokens", None) if usage else None,
        total_tokens=getattr(usage, "total_tokens", None) if usage else None,
        result_summary=f"veredito={data['result']}",
    )
    return Verdict(
        result=data["result"],
        decision=Decision(
            decision_source=decision_source,
            reason=data["reason"],
            confidence=data.get("confidence"),
            model=model,
            duration_ms=duration_ms,
        ),
    )


def classify(result: ExecutionResult, mode: Optional[Mode] = None) -> Verdict:
    """
    `mode` controla como os dois níveis de decisão interagem (ver
    agent.config.Mode); default: Config.MODE ("hybrid").

    - "heuristic": só a heurística decide. Um veredito heurístico AMBIGUOUS
      permanece AMBIGUOUS — não há para onde escalar a dúvida.
    - "hybrid" (recomendado): a heurística decide os casos claros; só os
      vereditos AMBIGUOUS vão para o LLM como desempate (decision_source
      final = "hybrid").
    - "llm": modo experimental — TODO caso é reavaliado pelo LLM, mesmo os
      que a heurística já resolveria com confiança (decision_source final =
      "llm"). Existe para permitir, futuramente, um estudo de ablação (ver
      README). NÃO é o modo recomendado para uso normal.
    """
    mode = mode or Config.MODE
    heuristic_verdict = classify_heuristic(result)

    if mode == "heuristic":
        return heuristic_verdict

    if mode == "llm":
        llm_verdict = _llm_tie_break(result, Config.LLM_MODEL, decision_source="llm")
        return llm_verdict or heuristic_verdict

    # mode == "hybrid" (default)
    if heuristic_verdict.result != AMBIGUOUS:
        return heuristic_verdict
    if not Config.USE_LLM_FOR_CLASSIFICATION:
        return heuristic_verdict
    llm_verdict = _llm_tie_break(result, Config.LLM_MODEL, decision_source="hybrid")
    return llm_verdict or heuristic_verdict
