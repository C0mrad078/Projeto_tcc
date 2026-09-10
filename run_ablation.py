#!/usr/bin/env python3
"""
Estudo de ablação: roda o agente nos modos heuristic/hybrid/llm contra o
mesmo alvo (vAPI real) N vezes cada, agrega Precisão/Revocação/F1 (média e
desvio padrão) + uso da arquitetura híbrida, e imprime/exporta a comparação
Heurística vs. Híbrido vs. LLM vs. ZAP.

Uso:
    python run_ablation.py                       # defaults conservadores (ver abaixo)
    python run_ablation.py --heuristic-runs 5 --hybrid-runs 5 --llm-runs 3
    python run_ablation.py --skip-llm            # pula o modo llm inteiramente

DECISÃO DE DESIGN: o número de repetições por modo tem defaults diferentes.
`heuristic`/`hybrid` não fazem nenhuma chamada de LLM contra o vAPI (nenhum
candidato/veredito é ambíguo neste ambiente — ver README), então repetir
várias vezes é rápido e gratuito. `llm` faz até 9 chamadas reais ao Gemini
por execução e esbarrou no limite de cota do tier gratuito do Google AI
Studio (~20 req/dia, "429 RESOURCE_EXHAUSTED") numa sessão anterior deste
projeto — por isso o default de --llm-runs é 1, não 3-5 como os outros.
Ajuste via flag se tiver cota disponível (ver README, "Próximos passos").

O número do ZAP não é recalculado aqui (não reroda o scan) — é o resultado
já documentado em README.md / baseline/, citado como referência fixa.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from agent.metrics import (
    compute_hybrid_usage,
    compute_metrics,
    load_all_evaluated,
    load_ground_truth,
    load_predicted_positive,
)
from agent.orchestrator import run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent
GROUND_TRUTH_PATH = PROJECT_ROOT / "ground_truth" / "vapi.json"

# Resultado já documentado do baseline OWASP ZAP (ver README.md, seção
# "Baseline com OWASP ZAP") — não recalculado aqui, é uma referência fixa.
ZAP_REFERENCE = {
    "mode": "zap_baseline",
    "n_runs": 1,
    "mean_precision": None,  # 0 positivos previstos -> precisão indefinida
    "std_precision": None,
    "mean_recall": 0.0,
    "std_recall": 0.0,
    "mean_f1": 0.0,
    "std_f1": 0.0,
    "total_llm_calls": None,
    "total_llm_errors": None,
    "note": "Resultado já documentado (não recalculado aqui): 13 tipos de alerta, 0 relacionados a BOLA.",
}


@dataclass
class ModeResult:
    mode: str
    n_runs: int
    precisions: List[float]
    recalls: List[float]
    f1s: List[float]
    total_llm_calls: int
    total_llm_errors: int


def _run_mode(mode: str, n_runs: int, ground_truth) -> Optional[ModeResult]:
    if n_runs <= 0:
        return None
    precisions, recalls, f1s = [], [], []
    total_calls = total_errors = 0
    for i in range(n_runs):
        print(f"[ablation] modo={mode} execução {i + 1}/{n_runs}...")
        report = run_pipeline(dry_run=False, mode=mode)
        predicted = load_predicted_positive(report)
        evaluated = load_all_evaluated(report)
        result = compute_metrics(ground_truth, predicted, evaluated)
        precisions.append(result.precision)
        recalls.append(result.recall)
        f1s.append(result.f1)
        usage = compute_hybrid_usage(report)
        total_calls += usage.llm_calls
        total_errors += usage.llm_errors
    return ModeResult(mode, n_runs, precisions, recalls, f1s, total_calls, total_errors)


def _mean_std(values: List[float]) -> Tuple[float, float]:
    mean = statistics.mean(values)
    std = statistics.pstdev(values) if len(values) > 1 else 0.0
    return mean, std


def _row_from_result(r: ModeResult) -> dict:
    p_mean, p_std = _mean_std(r.precisions)
    rc_mean, rc_std = _mean_std(r.recalls)
    f1_mean, f1_std = _mean_std(r.f1s)
    return {
        "mode": r.mode,
        "n_runs": r.n_runs,
        "mean_precision": round(p_mean, 4),
        "std_precision": round(p_std, 4),
        "mean_recall": round(rc_mean, 4),
        "std_recall": round(rc_std, 4),
        "mean_f1": round(f1_mean, 4),
        "std_f1": round(f1_std, 4),
        "total_llm_calls": r.total_llm_calls,
        "total_llm_errors": r.total_llm_errors,
        "note": None,
    }


def _print_table(rows: List[dict]) -> None:
    print("\n=== Estudo de ablação: Heurística vs. Híbrido vs. LLM vs. ZAP ===\n")
    header = f"{'Modo':<14} {'n':>3} {'Precisão':>10} {'Revocação':>10} {'F1 (média±dp)':>16} {'Chamadas LLM':>13}"
    print(header)
    print("-" * len(header))
    for row in rows:
        precision_str = f"{row['mean_precision']:.3f}" if row["mean_precision"] is not None else "—"
        f1_str = f"{row['mean_f1']:.3f}±{row['std_f1']:.3f}" if row["std_f1"] is not None else f"{row['mean_f1']:.3f}"
        calls_str = str(row["total_llm_calls"]) if row["total_llm_calls"] is not None else "n/a"
        print(
            f"{row['mode']:<14} {row['n_runs']:>3} {precision_str:>10} "
            f"{row['mean_recall']:>10.3f} {f1_str:>16} {calls_str:>13}"
        )
        if row.get("note"):
            print(f"  ↳ {row['note']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--heuristic-runs", type=int, default=3)
    parser.add_argument("--hybrid-runs", type=int, default=3)
    parser.add_argument(
        "--llm-runs", type=int, default=1,
        help="Default baixo por causa do limite de cota do tier gratuito do Gemini — ver README.",
    )
    parser.add_argument("--skip-llm", action="store_true", help="Pula o modo llm inteiramente.")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "runs" / "ablation_study.json")
    args = parser.parse_args()

    if not GROUND_TRUTH_PATH.exists():
        raise SystemExit(f"Gabarito não encontrado: {GROUND_TRUTH_PATH}")
    ground_truth = load_ground_truth(GROUND_TRUTH_PATH)

    rows: List[dict] = []
    for mode, n_runs in (
        ("heuristic", args.heuristic_runs),
        ("hybrid", args.hybrid_runs),
        ("llm", 0 if args.skip_llm else args.llm_runs),
    ):
        result = _run_mode(mode, n_runs, ground_truth)
        if result is None:
            print(f"[ablation] modo={mode} pulado (n_runs=0).")
            continue
        rows.append(_row_from_result(result))

    rows.append(ZAP_REFERENCE)
    _print_table(rows)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    csv_path = args.out.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[ablation] Resultado salvo em {args.out} e {csv_path}")


if __name__ == "__main__":
    main()
