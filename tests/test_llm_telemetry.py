"""Testes de agent/llm_telemetry.py — o coletor central de chamadas ao LLM."""
from __future__ import annotations

from agent.llm_telemetry import LLMTelemetry


def test_record_and_summary():
    t = LLMTelemetry()
    t.record(
        module="relation_inference", reason="ambíguo", model="gemini-3.8-flash",
        duration_ms=120.5, input_tokens=50, output_tokens=20, total_tokens=70,
    )
    t.record(
        module="response_classification", reason="ambíguo", model="gemini-3.8-flash",
        duration_ms=300.0, error="timeout", fallback_used=True,
    )

    summary = t.summary()
    assert summary["total_calls"] == 2
    assert summary["errors"] == 1
    assert summary["fallbacks_used"] == 1
    assert summary["calls_by_module"] == {"relation_inference": 1, "response_classification": 1}
    assert summary["input_tokens_total"] == 50  # só a chamada com sucesso reportou tokens
    assert summary["total_tokens_total"] == 70


def test_summary_with_no_calls_never_invents_zero_for_tokens():
    t = LLMTelemetry()
    summary = t.summary()
    assert summary["total_calls"] == 0
    assert summary["input_tokens_total"] is None
    assert summary["avg_duration_ms"] is None


def test_reset_clears_state():
    t = LLMTelemetry()
    t.record(module="x", reason="y", model="m", duration_ms=1.0)
    assert len(t.calls) == 1
    t.reset()
    assert t.calls == []
    assert t.summary()["total_calls"] == 0


def test_error_messages_are_truncated():
    t = LLMTelemetry()
    long_error = "x" * 1000
    record = t.record(module="m", reason="r", model="mo", duration_ms=1.0, error=long_error)
    assert len(record.error) <= 300


def test_to_list_never_includes_api_key_field():
    """Garante que nenhum campo de chave/segredo é aceito pela API de telemetria (Fase 4: 'evite armazenar secrets')."""
    t = LLMTelemetry()
    t.record(module="m", reason="r", model="mo", duration_ms=1.0)
    for record in t.to_list():
        assert "api_key" not in record
        assert "GOOGLE_API_KEY" not in str(record)
