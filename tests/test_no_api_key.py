"""
Testes de execução sem GOOGLE_API_KEY (Fase 14: "execução sem API key quando
o modo não necessita de LLM").

DECISÃO DE DESIGN sob teste: em modo "heuristic", nem relation_inference.py
nem classifier.py chegam a executar `from google import genai` — esse import
tardio só acontece dentro de `_llm_refine`/`_llm_tie_break`, que o modo
"heuristic" nunca chama. Por isso rodar sem chave configurada não deve
levantar nenhum erro relacionado a autenticação/API.
"""
from __future__ import annotations

from agent.classifier import NOT_FOUND, classify
from agent.config import Config
from agent.openapi_parser import OpenAPISpec
from agent.relation_inference import infer_relations

from .conftest import make_execution_result


def test_relation_inference_heuristic_mode_works_without_api_key(
    api1_endpoint, monkeypatch, patch_genai_forbidden
):
    monkeypatch.setattr(Config, "GOOGLE_API_KEY", None)
    spec = OpenAPISpec(base_url="http://x", endpoints=[api1_endpoint], security_schemes={}, title="t")

    candidates = infer_relations(spec, mode="heuristic")

    assert len(candidates) == 1
    assert candidates[0].decision.decision_source == "heuristic"


def test_classifier_heuristic_mode_works_without_api_key(
    api1_endpoint, identity_a, identity_b, monkeypatch, patch_genai_forbidden
):
    monkeypatch.setattr(Config, "GOOGLE_API_KEY", None)
    result = make_execution_result(
        endpoint=api1_endpoint, attacker=identity_b, victim=identity_a,
        attack_status=403, attack_body={"cause": "x"},
    )

    verdict = classify(result, mode="heuristic")

    assert verdict.result == NOT_FOUND
