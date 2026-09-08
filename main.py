#!/usr/bin/env python3
"""
Ponto de entrada do pipeline do agente de detecção de BOLA.

Uso interativo (recomendado para uso manual/exploração):
    python main.py                 # abre um menu por prompt, com escolha de alvo

Uso via flags (recomendado para scripts/reprodutibilidade — ver README):
    python main.py --dry-run                                  # sem rede real, contra a spec default (vAPI)
    python main.py --run                                        # execução completa contra o alvo do .env
    python main.py --run --spec outra_spec.json --target-url http://localhost:9000/base
    python main.py --run --no-llm                                # força modo 100% heurístico
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from agent.config import Config
from agent.orchestrator import run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent


def _print_summary(report: Dict[str, Any], full_json: bool = False) -> None:
    print(f"\n[main] {report['test_cases_generated']} caso(s) de teste gerado(s).")
    if not report.get("dry_run"):
        counts: Dict[str, int] = {}
        for entry in report["results"]:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        print(f"[main] Vereditos: {counts}")
    if full_json:
        print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])


def _run(dry_run: bool, no_llm: bool, spec: Optional[Path] = None) -> None:
    use_llm_relation_inference = None
    if no_llm:
        use_llm_relation_inference = False
        Config.USE_LLM_FOR_CLASSIFICATION = False
    try:
        report = run_pipeline(spec_path=spec, dry_run=dry_run, use_llm_relation_inference=use_llm_relation_inference)
    except RuntimeError as exc:
        print(f"\n[main] Erro: {exc}")
        return
    _print_summary(report)


def _find_latest_report() -> Optional[Path]:
    reports = sorted(Config.RUNS_DIR.glob("run_*.json"), key=lambda p: p.stat().st_mtime)
    return reports[-1] if reports else None


def _compute_metrics_on_latest() -> None:
    latest = _find_latest_report()
    if latest is None:
        print("[main] Nenhum relatório encontrado em ./runs/. Rode uma execução real primeiro (opção 2).")
        return
    ground_truth = PROJECT_ROOT / "ground_truth" / "vapi.json"
    if not ground_truth.exists():
        print(f"[main] Gabarito não encontrado em {ground_truth}. Métricas exigem um gabarito para o alvo testado.")
        return
    subprocess.run(
        [sys.executable, "compute_metrics.py", "--run", str(latest), "--ground-truth", str(ground_truth)],
        cwd=PROJECT_ROOT,
    )


def _choose_target(require_auth_confirmation: bool) -> Optional[Path]:
    """
    Pergunta ao usuário QUAL SITE/SPEC testar antes de rodar, em vez de
    assumir sempre o vAPI local — é o que permite apontar este agente para
    outro alvo (outra instância do vAPI noutra porta, outro laboratório
    vulnerável, ou qualquer API sua com uma spec OpenAPI equivalente) sem
    editar código.

    Retorna o caminho da spec escolhida, ou None se o usuário cancelar (spec
    inexistente, ou recusa a confirmação de autorização).

    DECISÃO DE DESIGN: a confirmação de autorização só é pedida para
    execuções REAIS (`require_auth_confirmation=True`, chamadas HTTP de
    verdade) — o modo --dry-run não faz nenhuma requisição de rede, então não
    há nada a autorizar. Isso opera estruturalmente a regra "nunca teste sem
    autorização explícita" em vez de depender só de lembrete em conversa.
    """
    print("\n--- Alvo do teste ---")
    default_spec = Config.OPENAPI_SPEC_PATH
    spec_input = input(f"Spec OpenAPI do site a testar [{default_spec}]: ").strip()
    spec_path = Path(spec_input) if spec_input else default_spec

    if not spec_path.exists():
        print(f"[main] Arquivo de spec não encontrado: {spec_path}")
        return None

    default_url = Config.TARGET_BASE_URL
    url_input = input(f"URL base do alvo (onde a spec acima está rodando) [{default_url}]: ").strip()
    if url_input:
        Config.TARGET_BASE_URL = url_input

    if require_auth_confirmation:
        print(f"\nVocê está prestes a testar: {Config.TARGET_BASE_URL}  (spec: {spec_path})")
        confirm = (
            input(
                "Você TEM AUTORIZAÇÃO EXPLÍCITA para testar este alvo — é seu, "
                "ou você tem permissão por escrito do dono/responsável? "
                "Digite 'sim' para confirmar: "
            )
            .strip()
            .lower()
        )
        if confirm != "sim":
            print("[main] Execução cancelada — sem confirmação de autorização.")
            return None

    return spec_path


MENU = """
=== Agente de Detecção de BOLA ===
1) Rodar em modo dry-run (escolher spec, sem rede real)
2) Rodar execução completa contra um alvo real
3) Rodar execução completa sem LLM (só heurística)
4) Registrar usuários de teste no vAPI (setup_vapi_users.py)
5) Calcular métricas do último relatório (compute_metrics.py)
6) Rodar baseline OWASP ZAP (baseline/run_zap_api_scan.sh)
0) Sair
"""


def run_interactive_menu() -> None:
    """
    Menu por prompt: ponto de entrada quando `python main.py` é chamado sem
    nenhum argumento. Cobre as operações mais comuns do fluxo do TCC sem
    exigir que o usuário memorize flags de linha de comando — essas
    continuam disponíveis e são o caminho recomendado para reprodutibilidade
    em script (ver README e `python main.py --help`).
    """
    while True:
        print(MENU)
        choice = input("Escolha uma opção: ").strip()
        if choice == "0":
            print("Até mais.")
            return
        elif choice == "1":
            spec = _choose_target(require_auth_confirmation=False)
            if spec is not None:
                _run(dry_run=True, no_llm=False, spec=spec)
        elif choice == "2":
            spec = _choose_target(require_auth_confirmation=True)
            if spec is not None:
                _run(dry_run=False, no_llm=False, spec=spec)
        elif choice == "3":
            spec = _choose_target(require_auth_confirmation=True)
            if spec is not None:
                _run(dry_run=False, no_llm=True, spec=spec)
        elif choice == "4":
            subprocess.run([sys.executable, "setup_vapi_users.py"], cwd=PROJECT_ROOT)
        elif choice == "5":
            _compute_metrics_on_latest()
        elif choice == "6":
            subprocess.run(["bash", str(PROJECT_ROOT / "baseline" / "run_zap_api_scan.sh")], cwd=PROJECT_ROOT)
        else:
            print("Opção inválida.")


def main() -> None:
    # Sem nenhum argumento: abre o menu interativo (uso exploratório/manual).
    # Com qualquer flag: comportamento tradicional via argparse, pensado
    # para scripts e reprodutibilidade (é o que o README documenta).
    if len(sys.argv) == 1:
        run_interactive_menu()
        return

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--run", action="store_true",
        help="Execução completa contra o alvo real (default quando alguma flag é passada e --dry-run não está presente).",
    )
    parser.add_argument(
        "--spec", type=Path, default=None,
        help="Caminho da especificação OpenAPI do site a testar (default: specs/vapi_openapi.json).",
    )
    parser.add_argument(
        "--target-url", type=str, default=None,
        help="URL base do alvo, sobrescrevendo TARGET_BASE_URL do .env (ex.: http://localhost:9000/base).",
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

    if args.target_url:
        Config.TARGET_BASE_URL = args.target_url

    if not args.dry_run:
        # Aviso não-bloqueante (não interativo, para não quebrar scripts/CI):
        # execução real contra QUALQUER alvo exige autorização explícita —
        # ver README, seção "Escopo de uso".
        print(f"[main] Execução real contra: {Config.TARGET_BASE_URL} — confirme que você tem autorização para isso.")

    use_llm_relation_inference = None
    if args.no_llm:
        use_llm_relation_inference = False
        Config.USE_LLM_FOR_CLASSIFICATION = False

    try:
        report = run_pipeline(
            spec_path=args.spec,
            dry_run=args.dry_run,
            use_llm_relation_inference=use_llm_relation_inference,
        )
    except RuntimeError as exc:
        print(f"\n[main] Erro: {exc}")
        raise SystemExit(1)

    _print_summary(report, full_json=not args.summary_only)


if __name__ == "__main__":
    main()
