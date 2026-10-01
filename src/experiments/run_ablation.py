"""Ablation experiment: grounded reasoner vs. ungrounded LLM baseline.

The headline research result. Both reasoners run over the same synthetic
catalog; the grounded reasoner is constrained to KB patterns that match the
extracted model, while the ungrounded baseline emits the textbook STRIDE threats
per element type regardless of model support (mimicking "just ask the LLM").

We report, for each, coverage of the ground truth and the relevant-threat rate
(precision) / noise rate. The expected finding: grounding keeps coverage while
sharply cutting irrelevant/unsupported threats - quantifying how much the
structure-extraction layer matters. Deterministic given the seed.
"""

from __future__ import annotations

import csv
import json
import os

from ..data.evaluation import score_threats
from ..data.synthetic import generate_catalog
from ..mitigate.mapper import MitigationMapper
from ..reason.reasoner import GroundedReasoner, UngroundedReasoner
from ..stride.kb import StrideKB

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS = os.path.join(ROOT, "results")


def run_ablation(seed: int = 7) -> dict:
    os.makedirs(RESULTS, exist_ok=True)
    kb = StrideKB.load()
    mapper = MitigationMapper()
    catalog = generate_catalog(seed=seed)

    agg = {
        "grounded": {"expected": 0, "proposed": 0, "tp": 0, "fp": 0},
        "ungrounded": {"expected": 0, "proposed": 0, "tp": 0, "fp": 0},
    }

    grounded_reasoner = GroundedReasoner(kb)
    ungrounded_reasoner = UngroundedReasoner(kb)

    for name, sysm in catalog.items():
        gt = sysm.expected_keys()

        g_threats = mapper.enrich(grounded_reasoner.analyze(sysm.model))
        u_threats = ungrounded_reasoner.analyze(sysm.model)

        g = score_threats(gt, g_threats)
        u = score_threats(gt, u_threats)
        for key, res in (("grounded", g), ("ungrounded", u)):
            agg[key]["expected"] += res.expected
            agg[key]["proposed"] += res.proposed
            agg[key]["tp"] += res.found
            agg[key]["fp"] += res.extra

    def summarize(d):
        cov = d["tp"] / d["expected"] if d["expected"] else 1.0
        prec = d["tp"] / d["proposed"] if d["proposed"] else 0.0
        noise = d["fp"] / d["proposed"] if d["proposed"] else 0.0
        return {
            "proposed_total": d["proposed"],
            "true_positives": d["tp"],
            "false_positives": d["fp"],
            "coverage": round(cov, 3),
            "precision": round(prec, 3),
            "noise_rate": round(noise, 3),
        }

    summary = {
        "grounded": summarize(agg["grounded"]),
        "ungrounded": summarize(agg["ungrounded"]),
    }
    summary["noise_reduction"] = round(
        summary["ungrounded"]["noise_rate"] - summary["grounded"]["noise_rate"], 3
    )
    summary["precision_gain"] = round(
        summary["grounded"]["precision"] - summary["ungrounded"]["precision"], 3
    )

    with open(os.path.join(RESULTS, "ablation.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["reasoner", "proposed", "true_positives", "false_positives",
                         "coverage", "precision", "noise_rate"])
        for key in ("grounded", "ungrounded"):
            s = summary[key]
            writer.writerow([key, s["proposed_total"], s["true_positives"],
                             s["false_positives"], s["coverage"], s["precision"],
                             s["noise_rate"]])
    with open(os.path.join(RESULTS, "ablation_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print("Ablation (grounded vs ungrounded reasoner):")
    for key in ("grounded", "ungrounded"):
        s = summary[key]
        print(f"  {key:11} coverage={s['coverage']:.2f} precision={s['precision']:.2f} "
              f"noise={s['noise_rate']:.2f} (proposed {s['proposed_total']}, "
              f"FP {s['false_positives']})")
    print(f"  => grounding cuts noise by {summary['noise_reduction']:.2f} and "
          f"raises precision by {summary['precision_gain']:.2f}")
    print(f"Wrote {RESULTS}/ablation.csv and ablation_summary.json")
    return summary


if __name__ == "__main__":
    run_ablation()
