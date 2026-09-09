"""
Telemetria centralizada de chamadas ao LLM (Fase 4 da refatoração
metodológica do TCC).

Todo módulo que chama o Gemini (hoje: relation_inference.py e classifier.py)
registra a chamada aqui — origem, motivo, modelo, duração, tokens (quando a
API retorna essa informação), erro e se houve fallback para a heurística.
Isso é o que permite ao relatório final responder perguntas como "quantas
decisões usaram LLM" e "quanto cada chamada custou em tokens", sem precisar
instrumentar cada chamador individualmente na hora de gerar métricas.

DECISÃO DE DESIGN: coletor de módulo (singleton simples), não uma classe
injetada em cada função. Cada execução do pipeline roda num processo Python
de vida curta (main.py é chamado uma vez por execução, mesmo no modo
interativo — cada opção do menu chama run_pipeline() do zero), então um
estado de módulo é suficiente e evita ter que passar um objeto de telemetria
por toda a cadeia de chamadas só para registrar 1-2 eventos por execução.
`reset()` existe explicitamente para os testes (que rodam vários cenários no
mesmo processo) e para reuso futuro caso o pipeline passe a rodar múltiplas
vezes num mesmo processo de longa duração.

SEGURANÇA: nunca registramos a API key nem o corpo do prompt/resposta aqui
(isso já fica no relatório de evidência do executor, quando relevante, com a
mesma redação parcial usada para o token de autenticação do alvo). Mensagens
de erro são truncadas por precaução, já que exceções de bibliotecas HTTP
ocasionalmente ecoam parte da requisição.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_MAX_ERROR_LEN = 300


@dataclass
class LLMCallRecord:
    module: str  # ex.: "relation_inference", "response_classification"
    reason: str
    model: str
    timestamp: str
    duration_ms: float
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    error: Optional[str] = None
    fallback_used: bool = False
    result_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LLMTelemetry:
    def __init__(self) -> None:
        self._calls: List[LLMCallRecord] = []

    def reset(self) -> None:
        self._calls = []

    def record(
        self,
        module: str,
        reason: str,
        model: str,
        duration_ms: float,
        *,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        error: Optional[str] = None,
        fallback_used: bool = False,
        result_summary: Optional[str] = None,
    ) -> LLMCallRecord:
        record = LLMCallRecord(
            module=module,
            reason=reason,
            model=model,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_ms=duration_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            error=(error[:_MAX_ERROR_LEN] if error else None),
            fallback_used=fallback_used,
            result_summary=result_summary,
        )
        self._calls.append(record)
        return record

    @property
    def calls(self) -> List[LLMCallRecord]:
        return list(self._calls)

    def to_list(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self._calls]

    def summary(self) -> Dict[str, Any]:
        """
        Agregados usados nas métricas experimentais (Fase 5): total de
        chamadas, erros, fallbacks, chamadas por módulo, duração média, e
        tokens totais quando disponíveis (None quando nenhuma chamada
        reportou tokens — nunca 0 forjado).
        """
        calls = self._calls
        calls_by_module: Dict[str, int] = {}
        for c in calls:
            calls_by_module[c.module] = calls_by_module.get(c.module, 0) + 1

        durations = [c.duration_ms for c in calls]
        input_tokens = [c.input_tokens for c in calls if c.input_tokens is not None]
        output_tokens = [c.output_tokens for c in calls if c.output_tokens is not None]
        total_tokens = [c.total_tokens for c in calls if c.total_tokens is not None]

        return {
            "total_calls": len(calls),
            "errors": sum(1 for c in calls if c.error is not None),
            "fallbacks_used": sum(1 for c in calls if c.fallback_used),
            "calls_by_module": calls_by_module,
            "avg_duration_ms": (sum(durations) / len(durations)) if durations else None,
            "input_tokens_total": sum(input_tokens) if input_tokens else None,
            "output_tokens_total": sum(output_tokens) if output_tokens else None,
            "total_tokens_total": sum(total_tokens) if total_tokens else None,
        }


# Instância única do processo — ver DECISÃO DE DESIGN acima.
telemetry = LLMTelemetry()
