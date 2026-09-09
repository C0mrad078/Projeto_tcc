"""Testes de agent/metrics.py — Precisão/Revocação/F1 e métricas de uso híbrido."""
from __future__ import annotations

from agent.metrics import compute_hybrid_usage, compute_metrics


def test_compute_metrics_precision_recall_f1():
    ground_truth = {
        ("GET", "/api1/user/{api1_id}", "a_to_b"),
        ("GET", "/api1/user/{api1_id}", "b_to_a"),
    }
    predicted_positive = {
        ("GET", "/api1/user/{api1_id}", "a_to_b"),  # VP
        ("GET", "/api5/user/{api5_id}", "a_to_b"),  # FP: não está no gabarito
    }
    evaluated = {
        ("GET", "/api1/user/{api1_id}", "a_to_b"),
        ("GET", "/api1/user/{api1_id}", "b_to_a"),  # avaliado, mas o agente não confirmou -> FN
        ("GET", "/api5/user/{api5_id}", "a_to_b"),
    }

    result = compute_metrics(ground_truth, predicted_positive, evaluated)

    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_negatives == 1
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert abs(result.f1 - 0.5) < 1e-9


def test_compute_metrics_handles_empty_predictions():
    result = compute_metrics(ground_truth=set(), predicted_positive=set(), evaluated=set())
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def _fake_report(results, llm_summary=None):
    return {"results": results, "llm_usage": {"summary": llm_summary or {}}}


def test_compute_hybrid_usage_counts_by_decision_source():
    report = _fake_report(
        results=[
            {"decision": {"decision_source": "heuristic", "duration_ms": 0.1}},
            {"decision": {"decision_source": "heuristic", "duration_ms": 0.2}},
            {"decision": {"decision_source": "hybrid", "duration_ms": 1200.0}},
            {"decision": {"decision_source": "llm", "duration_ms": 900.0}},
        ],
        llm_summary={
            "total_calls": 2, "errors": 0, "fallbacks_used": 0,
            "input_tokens_total": 100, "output_tokens_total": 40, "total_tokens_total": 140,
        },
    )
    usage = compute_hybrid_usage(report)

    assert usage.total_test_cases == 4
    assert usage.heuristic_decisions == 2
    assert usage.hybrid_decisions == 1
    assert usage.llm_decisions == 1
    assert usage.llm_calls == 2
    assert abs(usage.avg_heuristic_decision_time_ms - 0.15) < 1e-9
    assert abs(usage.avg_llm_decision_time_ms - 1050.0) < 1e-9  # média de hybrid+llm juntos
    assert usage.total_tokens_total == 140


def test_compute_hybrid_usage_never_invents_missing_data():
    """Sem nenhuma chamada de LLM na execução, os campos de token/tempo ficam None, não 0."""
    report = _fake_report(results=[{"decision": {"decision_source": "heuristic", "duration_ms": 0.05}}])
    usage = compute_hybrid_usage(report)

    assert usage.avg_llm_decision_time_ms is None
    assert usage.input_tokens_total is None
    assert usage.output_tokens_total is None
    assert usage.total_tokens_total is None
