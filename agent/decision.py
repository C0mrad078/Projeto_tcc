"""
Estrutura formal de rastreabilidade de decisão, usada por relation_inference.py
e classifier.py — os dois pontos do pipeline onde o agente decide algo que
pode vir de uma regra determinística ou de uma chamada ao LLM.

DECISÃO DE DESIGN: antes desta refatoração, cada módulo tinha seu próprio jeito
ad-hoc de registrar a origem de uma decisão (RelationCandidate.source,
Verdict.source/confidence). Consolidamos num único formato, porque o TCC
precisa comparar, de forma consistente entre os dois pontos de decisão, quantas
decisões vieram de cada mecanismo — isso é a Fase 3/5 da refatoração
metodológica do projeto.

Três origens possíveis:
  - "heuristic": decidido inteiramente por regra determinística.
  - "llm": decidido inteiramente pelo modelo (a heurística não teve
    confiança suficiente, ou o modo experimental "llm" forçou a chamada).
  - "hybrid": a heurística já tinha um sinal (ex.: candidato na faixa
    ambígua, ou um veredito heurístico não-ambíguo sendo re-checado no modo
    "llm"), e o LLM confirmou/ajustou esse sinal — nem heurística pura, nem
    LLM isolado decidindo do zero.

`confidence` é `None` quando não há como calcular um número real — nunca
inventamos um valor só para preencher o campo (regra explícita do TCC).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

DecisionSource = Literal["heuristic", "llm", "hybrid"]


@dataclass
class Decision:
    decision_source: DecisionSource
    reason: str
    confidence: Optional[float] = None
    model: Optional[str] = None
    # Duração da decisão em milissegundos (heurística: tempo de CPU local;
    # LLM/híbrida: tempo de rede+inferência) — usado pelas métricas de
    # comparação heurística-vs-LLM da Fase 5.
    duration_ms: Optional[float] = None

    def to_dict(self) -> dict:
        data = {
            "decision_source": self.decision_source,
            "reason": self.reason,
            "confidence": self.confidence,
        }
        if self.model is not None:
            data["model"] = self.model
        if self.duration_ms is not None:
            data["duration_ms"] = round(self.duration_ms, 2)
        return data
