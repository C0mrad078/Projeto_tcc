"""
Orquestrador: liga parser -> inferência de relações -> geração de casos ->
execução -> classificação -> relatório JSON (e CSV) em ./runs/.

Este é o único módulo que decide a política de "modo offline" (--dry-run):
quando ativado, o pipeline para logo após a geração dos casos de teste, antes
de qualquer chamada HTTP real — é o que permite validar spec/heurística sem
uma instância do vAPI no ar.

Também é o único módulo que sabe sobre os TRÊS MODOS EXPERIMENTAIS
("heuristic" / "hybrid" / "llm" — ver agent.config.Mode) e sobre a
TELEMETRIA DE LLM (agent.llm_telemetry): reseta o coletor no início de cada
execução (para que cada relatório reflita só as chamadas desta execução, não
de uma execução anterior no mesmo processo) e anexa o snapshot ao relatório
final.
"""
from __future__ import annotations

import csv
import json
import time
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .classifier import classify
from .config import Config, Identity, Mode
from .executor import Executor
from .llm_telemetry import telemetry
from .openapi_parser import parse_openapi
from .relation_inference import infer_relations
from .test_generator import generate_test_cases


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return str(obj)


def run_pipeline(
    spec_path: Optional[Path] = None,
    dry_run: bool = False,
    mode: Optional[Mode] = None,
) -> Dict[str, Any]:
    mode = mode or Config.MODE
    telemetry.reset()
    pipeline_start = time.monotonic()

    spec_path = spec_path or Config.OPENAPI_SPEC_PATH
    spec = parse_openapi(spec_path)

    # DECISÃO DE DESIGN: TARGET_BASE_URL (.env ou --target-url) é sempre o
    # que efetivamente decide para onde as requisições vão — não o campo
    # "servers" da spec. Isso permite validar a mesma spec contra ambientes
    # diferentes (ex.: Docker em outra porta) só trocando o alvo. Como
    # consequência, uma divergência silenciosa entre os dois viraria um erro
    # difícil de diagnosticar, então avisamos explicitamente em vez de ignorar.
    if spec.base_url and spec.base_url != Config.TARGET_BASE_URL:
        print(
            f"[orchestrator] Aviso: a URL do servidor declarada na spec ({spec.base_url}) "
            f"difere de TARGET_BASE_URL ({Config.TARGET_BASE_URL}). TARGET_BASE_URL "
            "sempre prevalece nas requisições reais — ajuste o .env/--target-url se isso não for esperado."
        )

    # DECISÃO DE DESIGN: --dry-run nunca faz nenhuma chamada de rede, nem
    # mesmo ao LLM — independente do `mode` pedido. Achado ao testar o modo
    # "llm" combinado com --dry-run: como esse modo força reavaliação por
    # LLM de todo candidato, sem essa trava o "dry-run" faria uma chamada
    # real ao Gemini (confirmado empiricamente: ~9s, ~1000 tokens). O modo
    # pedido continua registrado no relatório para transparência; só o
    # comportamento de inferência é rebaixado para "heuristic" aqui.
    inference_mode = "heuristic" if dry_run else mode
    if dry_run and mode != "heuristic":
        print(
            f"[orchestrator] Aviso: --dry-run nunca chama o LLM, mesmo em modo '{mode}' — "
            "a inferência de relações abaixo reflete só a heurística. Rode sem --dry-run "
            f"para ver o comportamento completo do modo '{mode}'."
        )
    candidates = infer_relations(spec, mode=inference_mode)

    # Módulos do vAPI (ex.: "api1", "api5") de fato envolvidos nos candidatos
    # desta execução — cada um tem sua própria tabela de usuários (ver
    # config.py), então só exigimos/carregamos credenciais para estes.
    modules = sorted({c.endpoint.module for c in candidates})

    if not dry_run:
        Config.require_network_config(modules)

    _identity_cache: Dict[str, Tuple[Identity, Identity]] = {}

    def identity_resolver(module: str) -> Tuple[Identity, Identity]:
        if module not in _identity_cache:
            user_a = Config.identity(module, "A")
            user_b = Config.identity(module, "B")
            if dry_run:
                # Em --dry-run não exigimos IDs reais (não há chamada HTTP),
                # mas generate_test_cases() pula vítimas sem resource_id. Para
                # preservar a validação offline da contagem de casos gerados,
                # usamos IDs de exemplo aqui — nunca em uma execução real,
                # onde require_network_config() já teria barrado antes.
                if user_a.resource_id is None:
                    user_a = Identity(
                        label="A", username=user_a.username, password=user_a.password,
                        resource_id="1", token=user_a.token,
                    )
                    print(
                        f"[orchestrator] Aviso: USER_A_{module.upper()}_ID ausente; "
                        "usando ID de exemplo '1' apenas para --dry-run."
                    )
                if user_b.resource_id is None:
                    user_b = Identity(
                        label="B", username=user_b.username, password=user_b.password,
                        resource_id="2", token=user_b.token,
                    )
                    print(
                        f"[orchestrator] Aviso: USER_B_{module.upper()}_ID ausente; "
                        "usando ID de exemplo '2' apenas para --dry-run."
                    )
            _identity_cache[module] = (user_a, user_b)
        return _identity_cache[module]

    test_cases = generate_test_cases(candidates, identity_resolver)

    experiment_id = str(uuid.uuid4())
    report: Dict[str, Any] = {
        # "run_id" mantido por compatibilidade (é o que nomeia o arquivo);
        # "experiment_id" é o mesmo valor, com o nome pedido pela Fase 7
        # (preparação para o estudo de ablação futuro).
        "run_id": experiment_id,
        "experiment_id": experiment_id,
        "mode": mode,
        "target": spec.title or Config.TARGET_BASE_URL,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "spec_path": str(spec_path),
        "target_base_url": Config.TARGET_BASE_URL,
        "dry_run": dry_run,
        "candidates": [asdict(c) for c in candidates],
        "test_cases_generated": len(test_cases),
        "results": [],
    }

    if dry_run:
        report["results"] = [
            {"case_id": tc.case_id, "note": "dry-run: nenhuma requisição HTTP foi feita."}
            for tc in test_cases
        ]
        _finalize_report(report, pipeline_start)
        _write_report(report)
        return report

    executor = Executor(spec.endpoints)
    for test_case in test_cases:
        execution = executor.run(test_case)
        verdict = classify(execution, mode=mode)
        report["results"].append(
            {
                "case_id": test_case.case_id,
                "endpoint": f"{test_case.endpoint.method} {test_case.endpoint.path}",
                "attacker": test_case.attacker.label,
                "victim": test_case.victim.label,
                "verdict": verdict.result,
                "decision": verdict.decision.to_dict(),
                "attack_exchange": execution.attack_exchange.to_dict(),
                "baseline_exchange": (
                    execution.baseline_exchange.to_dict() if execution.baseline_exchange else None
                ),
                "verification_exchange": (
                    execution.verification_exchange.to_dict()
                    if execution.verification_exchange
                    else None
                ),
            }
        )

    _finalize_report(report, pipeline_start)
    _write_report(report)
    _write_csv_report(report)
    return report


def _finalize_report(report: Dict[str, Any], pipeline_start: float) -> None:
    """
    Anexa telemetria de LLM (Fase 4) e métricas de uso híbrido (Fase 5) ao
    relatório, e fecha o timestamp/tempo total de execução. Import local de
    agent.metrics para evitar um ciclo de import (metrics.py não precisa
    conhecer orchestrator.py, mas usa a MESMA estrutura de relatório).
    """
    from .metrics import compute_hybrid_usage

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["total_execution_time_ms"] = round((time.monotonic() - pipeline_start) * 1000, 2)
    report["llm_usage"] = {
        "summary": telemetry.summary(),
        "calls": telemetry.to_list(),
    }
    report["hybrid_usage"] = asdict(compute_hybrid_usage(report))


def _write_report(report: Dict[str, Any]) -> Path:
    Config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = Config.RUNS_DIR / f"run_{report['run_id']}.json"
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8"
    )
    print(f"[orchestrator] Relatório salvo em {path}")
    return path


def _write_csv_report(report: Dict[str, Any]) -> Optional[Path]:
    """
    Exportação tabular (Fase 7 — preparação para comparação/ablação futura):
    uma linha por caso de teste, com as colunas mais relevantes para análise
    em planilha/pandas. O JSON completo (com corpos de requisição/resposta)
    continua sendo a fonte de evidência auditável; o CSV é um resumo.
    """
    if not report["results"] or "note" in report["results"][0]:
        return None  # dry-run não gera CSV — não há veredito para tabular

    Config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = Config.RUNS_DIR / f"run_{report['run_id']}.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "experiment_id", "mode", "target", "case_id", "endpoint",
                "attacker", "victim", "verdict", "decision_source", "confidence",
                "decision_model", "duration_ms", "attack_status_code",
            ]
        )
        for entry in report["results"]:
            decision = entry.get("decision", {})
            writer.writerow(
                [
                    report["experiment_id"], report["mode"], report["target"],
                    entry["case_id"], entry["endpoint"], entry["attacker"], entry["victim"],
                    entry["verdict"], decision.get("decision_source"), decision.get("confidence"),
                    decision.get("model"), decision.get("duration_ms"),
                    entry["attack_exchange"]["status_code"],
                ]
            )
    print(f"[orchestrator] CSV salvo em {path}")
    return path
