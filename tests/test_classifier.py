"""Testes de agent/classifier.py — classificação heurística, LLM de desempate, e os três modos."""
from __future__ import annotations

from agent.classifier import AMBIGUOUS, CONFIRMED, NOT_FOUND, classify, classify_heuristic
from agent.test_generator import canary_value

from .conftest import make_execution_result


def test_401_is_not_found_by_heuristic(api1_endpoint, identity_a, identity_b, patch_genai_forbidden):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=401, attack_body={"success": "false"},
    )
    verdict = classify_heuristic(result)
    assert verdict.result == NOT_FOUND
    assert verdict.decision.decision_source == "heuristic"
    assert verdict.decision.duration_ms is not None


def test_403_is_not_found_by_heuristic(api1_endpoint, identity_a, identity_b):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=403, attack_body={"cause": "usernameOrPasswordIncorrect"},
    )
    assert classify_heuristic(result).result == NOT_FOUND


def test_200_with_victim_id_in_body_is_confirmed(api1_endpoint, identity_a, identity_b):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"id": 1, "username": "usera"},
    )
    verdict = classify_heuristic(result)
    assert verdict.result == CONFIRMED
    assert verdict.decision.decision_source == "heuristic"


def test_numeric_id_does_not_false_positive_on_substring(api1_endpoint, identity_a, identity_b):
    """
    victim.resource_id="1" não deve "casar" com um "201" qualquer no corpo —
    achado real de uma execução contra o vAPI (ver classifier._body_contains).
    """
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"http_status_seen_elsewhere": 201, "username": "outro"},
    )
    verdict = classify_heuristic(result)
    assert verdict.result != CONFIRMED


def test_200_generic_body_without_baseline_is_ambiguous(api1_endpoint, identity_a, identity_b):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"success": "true"},
    )
    assert classify_heuristic(result).result == AMBIGUOUS


def test_put_confirmed_only_when_canary_persists(api1_put_endpoint, identity_a, identity_b):
    canary = canary_value(identity_b.label)
    result = make_execution_result(
        endpoint=api1_put_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"id": 1},
        verification_status=200, verification_body={"id": 1, "name": canary},
    )
    assert classify_heuristic(result).result == CONFIRMED


def test_put_ambiguous_when_verification_does_not_confirm(api1_put_endpoint, identity_a, identity_b):
    result = make_execution_result(
        endpoint=api1_put_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"id": 1},
        verification_status=200, verification_body={"id": 1, "name": "valor original"},
    )
    assert classify_heuristic(result).result == AMBIGUOUS


def test_heuristic_mode_never_calls_llm_even_when_ambiguous(api1_endpoint, identity_a, identity_b, patch_genai_forbidden):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"success": "true"},  # ambíguo pela heurística
    )
    verdict = classify(result, mode="heuristic")
    assert verdict.result == AMBIGUOUS
    assert verdict.decision.decision_source == "heuristic"


def test_hybrid_mode_calls_llm_only_when_heuristic_is_ambiguous(api1_endpoint, identity_a, identity_b, patch_genai_success):
    patch_genai_success({"result": "confirmed", "reason": "corpo corresponde à vítima", "confidence": 0.81})
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"success": "true"},
    )
    verdict = classify(result, mode="hybrid")
    assert verdict.result == CONFIRMED
    assert verdict.decision.decision_source == "hybrid"
    assert verdict.decision.confidence == 0.81


def test_hybrid_mode_does_not_call_llm_when_heuristic_is_confident(api1_endpoint, identity_a, identity_b, patch_genai_forbidden):
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=403, attack_body={"cause": "x"},  # heurística decide sozinha
    )
    verdict = classify(result, mode="hybrid")
    assert verdict.result == NOT_FOUND
    assert verdict.decision.decision_source == "heuristic"


def test_hybrid_mode_degrades_to_heuristic_on_llm_error(api1_endpoint, identity_a, identity_b, patch_genai_error):
    patch_genai_error(TimeoutError("timeout simulado"))
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=200, attack_body={"success": "true"},
    )
    verdict = classify(result, mode="hybrid")
    assert verdict.result == AMBIGUOUS  # fallback: mantém o veredito heurístico original
    assert verdict.decision.decision_source == "heuristic"


def test_llm_mode_forces_llm_even_when_heuristic_is_confident(api1_endpoint, identity_a, identity_b, patch_genai_success):
    patch_genai_success({"result": "not_found", "reason": "reavaliado pelo LLM", "confidence": 0.6})
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=403, attack_body={"cause": "x"},  # heurística já decidiria sozinha (not_found)
    )
    verdict = classify(result, mode="llm")
    assert verdict.decision.decision_source == "llm"


def test_llm_mode_falls_back_to_heuristic_on_error(api1_endpoint, identity_a, identity_b, patch_genai_error):
    patch_genai_error(RuntimeError("erro simulado"))
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=403, attack_body={"cause": "x"},
    )
    verdict = classify(result, mode="llm")
    assert verdict.result == NOT_FOUND
    assert verdict.decision.decision_source == "heuristic"  # degradou para a heurística
