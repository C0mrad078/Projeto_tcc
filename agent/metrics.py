"""
Cálculo de métricas de avaliação (precisão, revocação, F1) comparando o
relatório de execução do agente com um gabarito (ground truth) construído
manualmente (ver ground_truth/vapi.json, a ser criado na etapa 5 do roteiro
do TCC — este módulo não depende do arquivo existir para ser testado).

UNIDADE DE COMPARAÇÃO: cada tupla (método, path, direção do ataque) é tratada
como um "caso" independente para fins de VP/FP/FN — não o endpoint como um
todo — porque o mesmo endpoint pode ser vulnerável em uma direção e não na
outra (ex.: um bug de autorização que só afeta um dos dois usuários de teste).

Formato esperado do ground truth (JSON):
{
  "vulnerabilities": [
    {"method": "GET", "path": "/api1/user/{api1_id}", "direction": "any"},
    {"method": "PUT", "path": "/api1/user/{api1_id}", "direction": "a_to_b"}
  ]
}
`direction` é "a_to_b", "b_to_a" ou "any" (equivale às duas direções).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

Case = Tuple[str, str, str]  # (method, path, direction)


@dataclass
class MetricsResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    fp_cases: List[Case]
    fn_cases: List[Case]


def _direction_from_result(entry: Dict[str, Any]) -> str:
    return f"{entry['attacker'].lower()}_to_{entry['victim'].lower()}"


def load_ground_truth(path: Path) -> Set[Case]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: Set[Case] = set()
    for item in data["vulnerabilities"]:
        directions = ["a_to_b", "b_to_a"] if item["direction"] == "any" else [item["direction"]]
        for direction in directions:
            cases.add((item["method"].upper(), item["path"], direction))
    return cases


def load_predicted_positive(report: Dict[str, Any]) -> Set[Case]:
    """Casos que o agente classificou como 'confirmed' (positivos previstos)."""
    cases: Set[Case] = set()
    for entry in report["results"]:
        if entry.get("verdict") != "confirmed":
            continue
        method, path = entry["endpoint"].split(" ", 1)
        cases.add((method.upper(), path, _direction_from_result(entry)))
    return cases


def load_all_evaluated(report: Dict[str, Any]) -> Set[Case]:
    """
    Todas as combinações (endpoint, direção) que o agente de fato testou.
    Usado para não contar como falso negativo um item do gabarito que nem
    estava no escopo desta execução (ex.: o gabarito cobre API5 mas a
    execução rodou só com a spec de API1).
    """
    cases: Set[Case] = set()
    for entry in report["results"]:
        method, path = entry["endpoint"].split(" ", 1)
        cases.add((method.upper(), path, _direction_from_result(entry)))
    return cases


def compute_metrics(
    ground_truth: Set[Case], predicted_positive: Set[Case], evaluated: Set[Case]
) -> MetricsResult:
    ground_truth_in_scope = ground_truth & evaluated
    tp = predicted_positive & ground_truth_in_scope
    fp = predicted_positive - ground_truth_in_scope
    fn = ground_truth_in_scope - predicted_positive

    precision = len(tp) / len(predicted_positive) if predicted_positive else 0.0
    recall = len(tp) / len(ground_truth_in_scope) if ground_truth_in_scope else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return MetricsResult(
        true_positives=len(tp),
        false_positives=len(fp),
        false_negatives=len(fn),
        precision=precision,
        recall=recall,
        f1=f1,
        fp_cases=sorted(fp),
        fn_cases=sorted(fn),
    )
