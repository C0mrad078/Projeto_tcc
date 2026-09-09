"""
Testes estáticos (Fase 14 / Fase 10): garante que o ground truth NUNCA é lido
pelo pipeline de detecção — só por metrics.py/compute_metrics.py, na etapa
de AVALIAÇÃO, depois que os veredictos já existem.

Se um módulo de detecção passar a importar/referenciar "ground_truth" no
futuro, isso é um vazamento metodológico (o agente estaria decidindo com
base no gabarito) e este teste deve falhar.
"""
from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DETECTION_MODULES = [
    "agent/openapi_parser.py",
    "agent/relation_inference.py",
    "agent/test_generator.py",
    "agent/http_client.py",
    "agent/executor.py",
    "agent/classifier.py",
    "agent/decision.py",
    "agent/llm_telemetry.py",
]

# Módulos que legitimamente conhecem o ground truth (avaliação, não detecção).
ALLOWED_TO_REFERENCE_GROUND_TRUTH = {"agent/metrics.py", "agent/orchestrator.py", "main.py", "compute_metrics.py"}


def test_detection_modules_never_reference_ground_truth():
    offenders = []
    for rel_path in DETECTION_MODULES:
        path = PROJECT_ROOT / rel_path
        text = path.read_text(encoding="utf-8")
        if "ground_truth" in text.lower():
            offenders.append(rel_path)
    assert offenders == [], f"Vazamento de ground truth para o pipeline de detecção em: {offenders}"


def test_orchestrator_only_uses_ground_truth_for_reporting_path_not_decisions():
    """
    orchestrator.py pode, no máximo, conhecer o CAMINHO de um arquivo de
    ground truth (para repassar a outro comando) — não pode importar
    agent.metrics.load_ground_truth nem compute_metrics diretamente dentro
    de run_pipeline(), o que indicaria uso do gabarito durante a detecção.
    """
    text = (PROJECT_ROOT / "agent/orchestrator.py").read_text(encoding="utf-8")
    assert "load_ground_truth" not in text
    assert "compute_metrics(" not in text
