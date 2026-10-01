"""Tier-2 evaluation: tool output vs a hand-authored reference threat model.

Runs the full pipeline on the bundled sample app (code + diagram) and scores the
register against the human-authored gold model in ``references/``. Reports
coverage (fraction of reference threats surfaced), precision and the noise rate -
the honest comparison against an expert baseline.
"""

from __future__ import annotations

import json
import os

from ..data.evaluation import score_threats
from ..pipeline import run_pipeline

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS = os.path.join(ROOT, "results")


def _load_reference(path: str) -> set[tuple[str, str]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {(t["component"], t["stride"]) for t in data["threats"]}


def run_reference_eval() -> dict:
    os.makedirs(RESULTS, exist_ok=True)
    ref_path = os.path.join(ROOT, "references", "sample_webapp.reference.json")
    expected = _load_reference(ref_path)

    code = os.path.join(ROOT, "samples", "py_webapp")
    diagram = os.path.join(ROOT, "samples", "diagrams", "py_webapp.mmd")
    _, threats = run_pipeline("Sample Web App", repo_path=code, diagram_path=diagram,
                              backend_config={"backend": "stub"})
    res = score_threats(expected, threats)
    summary = {"system": "Sample Web App", "reference": os.path.relpath(ref_path, ROOT),
               **res.to_dict()}
    with open(os.path.join(RESULTS, "reference_eval.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print("Tier-2 evaluation vs hand-authored reference (sample web app):")
    print(f"  coverage={summary['coverage']:.2f} precision={summary['precision']:.2f} "
          f"noise={summary['noise_rate']:.2f} "
          f"(TP={summary['true_positives']} FN={summary['false_negatives']} "
          f"FP={summary['false_positives']})")
    print(f"Wrote {RESULTS}/reference_eval.json")
    return summary


if __name__ == "__main__":
    run_reference_eval()
