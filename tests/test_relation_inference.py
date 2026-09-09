"""Testes de agent/relation_inference.py — os dois níveis de decisão e os três modos."""
from __future__ import annotations

from agent.openapi_parser import OpenAPISpec
from agent.relation_inference import CONFIRM_THRESHOLD, REJECT_THRESHOLD, infer_relations


def _spec_with(*endpoints) -> OpenAPISpec:
    return OpenAPISpec(base_url="http://x", endpoints=list(endpoints), security_schemes={}, title="teste")


def test_heuristic_confirms_confident_candidate(api1_endpoint, patch_genai_forbidden):
    """Path param batendo no regex de ID, em GET: score alto, decidido sozinho pela heurística."""
    spec = _spec_with(api1_endpoint)
    candidates = infer_relations(spec, mode="hybrid")

    assert len(candidates) == 1
    assert candidates[0].decision.decision_source == "heuristic"
    assert candidates[0].score >= CONFIRM_THRESHOLD
    assert candidates[0].decision.confidence == candidates[0].score


def test_unauthenticated_endpoint_never_becomes_candidate(api1_endpoint, patch_genai_forbidden):
    api1_endpoint.requires_auth = False
    spec = _spec_with(api1_endpoint)
    assert infer_relations(spec, mode="hybrid") == []


def test_unrelated_parameter_name_is_rejected(unrelated_endpoint, patch_genai_forbidden):
    spec = _spec_with(unrelated_endpoint)
    assert infer_relations(spec, mode="hybrid") == []


def test_heuristic_mode_never_calls_llm_and_drops_ambiguous(ambiguous_endpoint, patch_genai_forbidden):
    """
    Modo 'heuristic': o candidato ambíguo (score entre os dois limiares) não
    tem como ser confirmado sem LLM — e o LLM não pode ser chamado neste
    modo. `patch_genai_forbidden` garante isso: se o código tentasse
    chamar o LLM mesmo assim, o teste falharia explicitamente.
    """
    spec = _spec_with(ambiguous_endpoint)
    candidates = infer_relations(spec, mode="heuristic")
    assert candidates == []


def test_hybrid_mode_refines_ambiguous_candidate_via_llm(ambiguous_endpoint, patch_genai_success):
    """
    Modo 'hybrid': candidato ambíguo é enviado ao LLM; se o LLM confirmar,
    o decision_source final é 'hybrid' (a heurística contribuiu o sinal
    inicial, o LLM decidiu o desempate) — não 'llm' puro.
    """
    patch_genai_success({"decisions": [{"index": 0, "is_object_identifier": True, "rationale": "parece um ID de recurso", "confidence": 0.77}]})
    spec = _spec_with(ambiguous_endpoint)
    candidates = infer_relations(spec, mode="hybrid")

    assert len(candidates) == 1
    assert candidates[0].decision.decision_source == "hybrid"
    assert candidates[0].decision.confidence == 0.77
    assert candidates[0].decision.model is not None


def test_hybrid_mode_drops_candidate_rejected_by_llm(ambiguous_endpoint, patch_genai_success):
    patch_genai_success({"decisions": [{"index": 0, "is_object_identifier": False, "rationale": "não parece ser um identificador de objeto", "confidence": 0.9}]})
    spec = _spec_with(ambiguous_endpoint)
    assert infer_relations(spec, mode="hybrid") == []


def test_hybrid_mode_degrades_to_heuristic_on_llm_error(ambiguous_endpoint, patch_genai_error):
    """
    Se o LLM falhar (erro de rede, timeout, etc.) durante o refinamento em
    modo híbrido, o candidato ambíguo original é mantido (fallback) em vez
    de o pipeline inteiro quebrar.
    """
    patch_genai_error(RuntimeError("erro de rede simulado"))
    spec = _spec_with(ambiguous_endpoint)
    candidates = infer_relations(spec, mode="hybrid")

    assert len(candidates) == 1
    assert candidates[0].decision.decision_source == "heuristic"  # candidato original, não refinado


def test_llm_mode_forces_llm_even_for_confident_candidate(api1_endpoint, patch_genai_success):
    """
    Modo 'llm' (experimental): mesmo um candidato que a heurística já
    confirmaria sozinha (score alto) é reavaliado pelo LLM — decision_source
    final é 'llm' puro, não 'heuristic'.
    """
    patch_genai_success({"decisions": [{"index": 0, "is_object_identifier": True, "rationale": "confirmado pelo LLM", "confidence": 0.95}]})
    spec = _spec_with(api1_endpoint)
    candidates = infer_relations(spec, mode="llm")

    assert len(candidates) == 1
    assert candidates[0].decision.decision_source == "llm"
    assert candidates[0].score >= CONFIRM_THRESHOLD  # a heurística JÁ confirmaria — mas o modo força o LLM mesmo assim
