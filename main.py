#!/usr/bin/env python3
"""
Ponto de entrada do pipeline do agente de detecção de BOLA.

Uso típico:
    python main.py --dry-run     # parser + inferência + geração, sem rede real
    python main.py                 # execução completa contra o vAPI real
    python main.py --no-llm        # força modo 100% heurístico (sem chamadas ao Gemini)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.config import Config
from agent.orchestrator import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--spec", type=Path, default=None,
        help="Caminho da especificação OpenAPI (default: specs/vapi_openapi.json).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Executa só parser + inferência + geração de casos, sem chamadas HTTP reais.",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Desativa o uso do LLM em toda a pipeline (inferência de relações e classificação).",
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Imprime só o resumo final, sem o JSON completo no stdout (o relatório completo sempre é salvo em ./runs/).",
    )
    args = parser.parse_args()

    use_llm_relation_inference = None
    if args.no_llm:
        use_llm_relation_inference = False
        Config.USE_LLM_FOR_CLASSIFICATION = False

    report = run_pipeline(
        spec_path=args.spec,
        dry_run=args.dry_run,
        use_llm_relation_inference=use_llm_relation_inference,
    )

    print(f"\n[main] {report['test_cases_generated']} caso(s) de teste gerado(s).")
    if not args.dry_run:
        counts: dict = {}
        for entry in report["results"]:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        print(f"[main] Vereditos: {counts}")

    if not args.summary_only:
        print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    main()
