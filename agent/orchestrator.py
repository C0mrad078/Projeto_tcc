"""
Orquestrador: liga parser -> inferência de relações -> geração de casos ->
execução -> classificação -> relatório JSON em ./runs/.

Este é o único módulo que decide a política de "modo offline" (--dry-run):
quando ativado, o pipeline para logo após a geração dos casos de teste, antes
de qualquer chamada HTTP real — é o que permite validar spec/heurística sem
uma instância do vAPI no ar.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .classifier import classify
from .config import Config, Identity
from .executor import Executor
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
    use_llm_relation_inference: Optional[bool] = None,
) -> Dict[str, Any]:
    spec_path = spec_path or Config.OPENAPI_SPEC_PATH
    spec = parse_openapi(spec_path)

    # DECISÃO DE DESIGN: TARGET_BASE_URL (.env) é sempre o que efetivamente
    # decide para onde as requisições vão — não o campo "servers" da spec.
    # Isso permite validar a mesma spec contra ambientes diferentes (ex.:
    # Docker em outra porta) só trocando o .env. Como consequência, uma
    # divergência silenciosa entre os dois viraria um erro difícil de
    # diagnosticar, então avisamos explicitamente em vez de ignorar.
    if spec.base_url and spec.base_url != Config.TARGET_BASE_URL:
        print(
            f"[orchestrator] Aviso: a URL do servidor declarada na spec ({spec.base_url}) "
            f"difere de TARGET_BASE_URL ({Config.TARGET_BASE_URL}). TARGET_BASE_URL "
            "sempre prevalece nas requisições reais — ajuste o .env se isso não for esperado."
        )

    candidates = infer_relations(spec, use_llm=use_llm_relation_inference)

    if not dry_run:
        Config.require_network_config()
    user_a, user_b = Config.user_a(), Config.user_b()

    if dry_run:
        # Em --dry-run não exigimos USER_A_ID/USER_B_ID reais (não há
        # nenhuma chamada HTTP), mas generate_test_cases() pula vítimas sem
        # resource_id. Para preservar a validação offline da contagem de
        # casos gerados, usamos IDs de exemplo aqui — nunca em uma execução
        # real, onde require_network_config() já teria barrado antes.
        if user_a.resource_id is None:
            user_a = Identity(label="A", email=user_a.email, password=user_a.password, resource_id="1", token=user_a.token)
            print("[orchestrator] Aviso: USER_A_ID ausente; usando ID de exemplo '1' apenas para --dry-run.")
        if user_b.resource_id is None:
            user_b = Identity(label="B", email=user_b.email, password=user_b.password, resource_id="2", token=user_b.token)
            print("[orchestrator] Aviso: USER_B_ID ausente; usando ID de exemplo '2' apenas para --dry-run.")

    test_cases = generate_test_cases(candidates, user_a, user_b)

    report: Dict[str, Any] = {
        "run_id": str(uuid.uuid4()),
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
        _write_report(report)
        return report

    executor = Executor(spec.endpoints)
    for test_case in test_cases:
        execution = executor.run(test_case)
        verdict = classify(execution)
        report["results"].append(
            {
                "case_id": test_case.case_id,
                "endpoint": f"{test_case.endpoint.method} {test_case.endpoint.path}",
                "attacker": test_case.attacker.label,
                "victim": test_case.victim.label,
                "verdict": verdict.result,
                "reason": verdict.reason,
                "verdict_source": verdict.source,
                "confidence": verdict.confidence,
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

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write_report(report)
    return report


def _write_report(report: Dict[str, Any]) -> Path:
    Config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = Config.RUNS_DIR / f"run_{report['run_id']}.json"
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8"
    )
    print(f"[orchestrator] Relatório salvo em {path}")
    return path
