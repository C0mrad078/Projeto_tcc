#!/usr/bin/env python3
"""
Ponto de entrada do pipeline do agente de detecção de BOLA.

Uso interativo (recomendado para uso manual/exploração):
    python main.py                 # abre um menu por prompt, com escolha de alvo e modo

Uso via flags (recomendado para scripts/reprodutibilidade — ver README):
    python main.py --dry-run                                  # sem rede real, contra a spec default (vAPI)
    python main.py --run                                        # modo hybrid (recomendado), contra o alvo do .env
    python main.py --run --mode heuristic                         # só heurística, LLM nunca chamado
    python main.py --run --mode llm                                 # experimental: LLM força reavaliação de tudo
    python main.py --run --spec outra_spec.json --target-url http://localhost:9000/base
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from agent.config import Config, Mode, VALID_MODES
from agent.orchestrator import run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent


def _print_summary(report: Dict[str, Any], full_json: bool = False) -> None:
    print(f"\n[main] modo={report.get('mode')}  {report['test_cases_generated']} caso(s) de teste gerado(s).")
    if not report.get("dry_run"):
        counts: Dict[str, int] = {}
        for entry in report["results"]:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        print(f"[main] Vereditos: {counts}")
        hybrid = report.get("hybrid_usage", {})
        print(
            f"[main] Decisões — heurística: {hybrid.get('heuristic_decisions')} | "
            f"híbrida: {hybrid.get('hybrid_decisions')} | llm: {hybrid.get('llm_decisions')} "
            f"(chamadas ao LLM: {hybrid.get('llm_calls')}, erros: {hybrid.get('llm_errors')})"
        )
    if full_json:
        print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])


def _run(dry_run: bool, mode: Mode, spec: Optional[Path] = None) -> None:
    try:
        report = run_pipeline(spec_path=spec, dry_run=dry_run, mode=mode)
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
        print("[main] Nenhum relatório encontrado em ./runs/. Rode uma execução real primeiro (opção 2, 3 ou 4).")
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
2) Rodar execução completa — modo hybrid (recomendado)
3) Rodar execução completa — modo heuristic (LLM nunca chamado)
4) Rodar execução completa — modo llm (experimental; força reavaliação por LLM)
5) Registrar usuários de teste no vAPI (setup_vapi_users.py)
6) Calcular métricas do último relatório (compute_metrics.py)
7) Rodar baseline OWASP ZAP (baseline/run_zap_api_scan.sh)
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
                _run(dry_run=True, mode="hybrid", spec=spec)
        elif choice == "2":
            spec = _choose_target(require_auth_confirmation=True)
            if spec is not None:
                _run(dry_run=False, mode="hybrid", spec=spec)
        elif choice == "3":
            spec = _choose_target(require_auth_confirmation=True)
            if spec is not None:
                _run(dry_run=False, mode="heuristic", spec=spec)
        elif choice == "4":
            spec = _choose_target(require_auth_confirmation=True)
            if spec is not None:
                print(
                    "[main] Aviso: modo 'llm' é experimental — força o LLM a reavaliar "
                    "TODOS os casos, mesmo os que a heurística já resolveria sozinha. "
                    "Não é o modo recomendado para uso normal (use 'hybrid')."
                )
                _run(dry_run=False, mode="llm", spec=spec)
        elif choice == "5":
            subprocess.run([sys.executable, "setup_vapi_users.py"], cwd=PROJECT_ROOT)
        elif choice == "6":
            _compute_metrics_on_latest()
        elif choice == "7":
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
        "--mode", choices=list(VALID_MODES), default=None,
        help=(
            "Modo experimental: 'heuristic' (LLM nunca chamado), 'hybrid' "
            "(recomendado — heurística primeiro, LLM só em ambiguidade), "
            "'llm' (experimental — força reavaliação por LLM de tudo). "
            "Default: AGENT_MODE do .env, ou 'hybrid'."
        ),
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Atalho para --mode heuristic (mantido por compatibilidade com versões anteriores).",
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Imprime só o resumo final, sem o JSON completo no stdout (o relatório completo sempre é salvo em ./runs/).",
    )
    args = parser.parse_args()

    if args.target_url:
        Config.TARGET_BASE_URL = args.target_url

    mode: Mode = args.mode or Config.MODE
    if args.no_llm:
        mode = "heuristic"

    if not args.dry_run:
        # Aviso não-bloqueante (não interativo, para não quebrar scripts/CI):
        # execução real contra QUALQUER alvo exige autorização explícita —
        # ver README, seção "Escopo de uso".
        print(
            f"[main] Execução real (modo={mode}) contra: {Config.TARGET_BASE_URL} — "
            "confirme que você tem autorização para isso."
        )

    try:
        report = run_pipeline(spec_path=args.spec, dry_run=args.dry_run, mode=mode)
    except RuntimeError as exc:
        print(f"\n[main] Erro: {exc}")
        raise SystemExit(1)

    _print_summary(report, full_json=not args.summary_only)


if __name__ == "__main__":
    main()
