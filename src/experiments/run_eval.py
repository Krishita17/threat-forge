"""Evaluation experiment: coverage / precision / noise on the synthetic catalog.

Runs the full grounded pipeline on every synthetic system and scores the
resulting register against that system's injected-weakness ground truth. Writes
per-system and aggregate metrics to ``results/`` for the figures and README.
Deterministic given the seed.
"""

from __future__ import annotations

import csv
import json
import os

from ..data.evaluation import score_threats
from ..data.synthetic import generate_catalog
from ..pipeline import run_on_model

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS = os.path.join(ROOT, "results")


def run_evaluation(seed: int = 7) -> dict:
    os.makedirs(RESULTS, exist_ok=True)
    catalog = generate_catalog(seed=seed)
    rows = []
    agg = {"expected": 0, "proposed": 0, "tp": 0, "fn": 0, "fp": 0}

    for name, sysm in catalog.items():
        threats = run_on_model(sysm.model, backend_config={"backend": "stub"})
        res = score_threats(sysm.expected_keys(), threats)
        rows.append({
            "system": name,
            **res.to_dict(),
        })
        agg["expected"] += res.expected
        agg["proposed"] += res.proposed
        agg["tp"] += res.found
        agg["fn"] += res.missed
        agg["fp"] += res.extra

    coverage = agg["tp"] / agg["expected"] if agg["expected"] else 1.0
    precision = agg["tp"] / agg["proposed"] if agg["proposed"] else 0.0
    noise = agg["fp"] / agg["proposed"] if agg["proposed"] else 0.0
    summary = {
        "systems": len(catalog),
        "expected_total": agg["expected"],
        "proposed_total": agg["proposed"],
        "true_positives": agg["tp"],
        "false_negatives": agg["fn"],
        "false_positives": agg["fp"],
        "coverage": round(coverage, 3),
        "precision": round(precision, 3),
        "noise_rate": round(noise, 3),
    }

    with open(os.path.join(RESULTS, "evaluation.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(RESULTS, "evaluation_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print("Evaluation (grounded pipeline vs synthetic ground truth):")
    for r in rows:
        print(f"  {r['system']:18} coverage={r['coverage']:.2f} "
              f"precision={r['precision']:.2f} noise={r['noise_rate']:.2f} "
              f"(TP={r['true_positives']} FN={r['false_negatives']} FP={r['false_positives']})")
    print(f"  {'AGGREGATE':18} coverage={summary['coverage']:.2f} "
          f"precision={summary['precision']:.2f} noise={summary['noise_rate']:.2f}")
    print(f"Wrote {RESULTS}/evaluation.csv and evaluation_summary.json")
    return summary


if __name__ == "__main__":
    run_evaluation()
