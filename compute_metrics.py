#!/usr/bin/env python3
"""
CLI para calcular precisão/revocação/F1 de uma execução do agente contra o
gabarito manual (ground truth).

Uso:
    python compute_metrics.py --run runs/run_<id>.json --ground-truth ground_truth/vapi.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.metrics import (
    compute_hybrid_usage,
    compute_metrics,
    load_all_evaluated,
    load_ground_truth,
    load_predicted_positive,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path, help="Relatório JSON gerado pelo orchestrator.")
    parser.add_argument("--ground-truth", required=True, type=Path, help="Gabarito manual (ground_truth/vapi.json).")
    args = parser.parse_args()

    report = json.loads(args.run.read_text(encoding="utf-8"))
    ground_truth = load_ground_truth(args.ground_truth)
    predicted = load_predicted_positive(report)
    evaluated = load_all_evaluated(report)

    result = compute_metrics(ground_truth, predicted, evaluated)

    print(f"Modo: {report.get('mode', '?')}  |  Alvo: {report.get('target', '?')}")
    print(f"Verdadeiros positivos: {result.true_positives}")
    print(f"Falsos positivos:      {result.false_positives}")
    print(f"Falsos negativos:      {result.false_negatives}")
    print(f"Precisão:  {result.precision:.3f}")
    print(f"Revocação: {result.recall:.3f}")
    print(f"F1:        {result.f1:.3f}")

    if result.fp_cases:
        print("\nCasos de falso positivo:")
        for case in result.fp_cases:
            print(f"  - {case}")
    if result.fn_cases:
        print("\nCasos de falso negativo:")
        for case in result.fn_cases:
            print(f"  - {case}")

    usage = compute_hybrid_usage(report)
    print("\n--- Uso da arquitetura híbrida ---")
    print(f"Total de casos de teste:  {usage.total_test_cases}")
    print(f"Decisões heurísticas:     {usage.heuristic_decisions}")
    print(f"Decisões híbridas:        {usage.hybrid_decisions}")
    print(f"Decisões só-LLM:          {usage.llm_decisions}")
    print(f"Chamadas ao LLM:          {usage.llm_calls} (erros: {usage.llm_errors}, fallbacks: {usage.llm_fallbacks})")
    if usage.avg_heuristic_decision_time_ms is not None:
        print(f"Tempo médio — heurística: {usage.avg_heuristic_decision_time_ms:.2f} ms")
    if usage.avg_llm_decision_time_ms is not None:
        print(f"Tempo médio — LLM:        {usage.avg_llm_decision_time_ms:.2f} ms")
    if usage.total_tokens_total is not None:
        print(
            f"Tokens — entrada: {usage.input_tokens_total} | "
            f"saída: {usage.output_tokens_total} | total: {usage.total_tokens_total}"
        )


if __name__ == "__main__":
    main()
