"""Generate every chart embedded in the README (all code-generated, regenerable).

Produces, into ``figures/``:
  pipeline.png            - the ThreatForge pipeline (schematic)
  threats_by_stride.png   - STRIDE distribution for the sample app
  risk_heatmap.png        - likelihood x impact grid of the sample register
  threats_by_boundary.png - where threats concentrate by trust boundary
  coverage_by_system.png  - coverage vs ground truth per synthetic system
  precision_noise.png     - precision vs noise rate per synthetic system
  ablation.png            - grounded vs ungrounded reasoner (headline result)

Uses matplotlib with the non-interactive Agg backend. Deterministic.
"""

from __future__ import annotations

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from ..data.synthetic import generate_catalog  # noqa: E402
from ..experiments.run_ablation import run_ablation  # noqa: E402
from ..experiments.run_eval import run_evaluation  # noqa: E402
from ..pipeline import run_pipeline, run_on_model  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIG = os.path.join(ROOT, "figures")

_STRIDE = ["S", "T", "R", "I", "D", "E"]
_STRIDE_FULL = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Info. disclosure", "D": "Denial of service",
                "E": "Elev. of privilege"}
_PALETTE = ["#1a73e8", "#8430ce", "#d93025", "#e37400", "#188038", "#9aa0a6"]


def _sample_threats():
    code = os.path.join(ROOT, "samples", "py_webapp")
    diagram = os.path.join(ROOT, "samples", "diagrams", "py_webapp.mmd")
    diagram = diagram if os.path.exists(diagram) else None
    model, threats = run_pipeline("Sample Web App", repo_path=code,
                                  diagram_path=diagram, backend_config={"backend": "stub"})
    return model, threats


def fig_pipeline():
    fig, ax = plt.subplots(figsize=(11, 2.6))
    ax.axis("off")
    stages = ["Code /\nDiagram", "System Model\n+ Trust Bounds", "STRIDE KB\n(grounding)",
              "Grounded\nReasoner", "Mitigation\n+ Risk", "Threat-Model\nReport"]
    n = len(stages)
    for i, s in enumerate(stages):
        x = i / n
        ax.add_patch(plt.Rectangle((x + 0.005, 0.3), 1 / n - 0.03, 0.4,
                                   facecolor=_PALETTE[i % len(_PALETTE)], alpha=0.85,
                                   edgecolor="none"))
        ax.text(x + (1 / n - 0.025) / 2 + 0.005, 0.5, s, ha="center", va="center",
                color="white", fontsize=9, fontweight="bold")
        if i < n - 1:
            ax.annotate("", xy=(x + 1 / n - 0.015, 0.5), xytext=(x + 1 / n - 0.03, 0.5),
                        arrowprops=dict(arrowstyle="->", color="#444"))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("ThreatForge pipeline: system -> model -> grounded reasoning -> report",
                 fontsize=11)
    _save(fig, "pipeline.png")


def fig_threats_by_stride(threats):
    counts = {c: 0 for c in _STRIDE}
    for t in threats:
        counts[t.stride] = counts.get(t.stride, 0) + 1
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([_STRIDE_FULL[c] for c in _STRIDE], [counts[c] for c in _STRIDE],
           color=_PALETTE)
    ax.set_ylabel("Number of threats")
    ax.set_title("Sample app: threats by STRIDE category")
    plt.xticks(rotation=25, ha="right")
    _save(fig, "threats_by_stride.png")


def fig_risk_heatmap(threats):
    grid = np.zeros((5, 5), dtype=int)
    for t in threats:
        li = min(max(t.likelihood, 1), 5) - 1
        im = min(max(t.impact, 1), 5) - 1
        grid[4 - li, im] += 1
    fig, ax = plt.subplots(figsize=(6, 5))
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list(
        "risk", ["#188038", "#e37400", "#d93025"])
    ax.imshow(grid, cmap=cmap, aspect="equal")
    for i in range(5):
        for j in range(5):
            if grid[i, j]:
                ax.text(j, i, str(grid[i, j]), ha="center", va="center",
                        color="white", fontweight="bold")
    ax.set_xticks(range(5)); ax.set_xticklabels([1, 2, 3, 4, 5])
    ax.set_yticks(range(5)); ax.set_yticklabels([5, 4, 3, 2, 1])
    ax.set_xlabel("Impact"); ax.set_ylabel("Likelihood")
    ax.set_title("Sample app: risk heatmap (likelihood x impact)")
    _save(fig, "risk_heatmap.png")


def fig_threats_by_boundary(threats):
    counts: dict[str, int] = {}
    for t in threats:
        key = t.boundary or "(no boundary)"
        counts[key] = counts.get(key, 0) + 1
    items = sorted(counts.items(), key=lambda kv: -kv[1])
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh([k for k, _ in items][::-1], [v for _, v in items][::-1],
            color=_PALETTE[0])
    ax.set_xlabel("Number of threats")
    ax.set_title("Sample app: threats by trust boundary")
    _save(fig, "threats_by_boundary.png")


def fig_coverage_by_system(eval_rows):
    names = [r["system"] for r in eval_rows]
    cov = [r["coverage"] for r in eval_rows]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, cov, color=_PALETTE[4])
    ax.set_ylim(0, 1.05)
    ax.axhline(1.0, color="#999", ls="--", lw=1)
    ax.set_ylabel("Coverage of ground-truth threats")
    ax.set_title("Threat coverage per synthetic system (vs injected-weakness oracle)")
    plt.xticks(rotation=20, ha="right")
    for i, v in enumerate(cov):
        ax.text(i, v + 0.02, f"{v:.0%}", ha="center", fontsize=9)
    _save(fig, "coverage_by_system.png")


def fig_precision_noise(eval_rows):
    names = [r["system"] for r in eval_rows]
    prec = [r["precision"] for r in eval_rows]
    noise = [r["noise_rate"] for r in eval_rows]
    x = np.arange(len(names))
    w = 0.38
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - w / 2, prec, w, label="Precision (legitimate)", color=_PALETTE[0])
    ax.bar(x + w / 2, noise, w, label="Noise rate (spurious)", color=_PALETTE[2])
    ax.set_xticks(x); ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_title("Precision vs noise rate per synthetic system")
    ax.legend()
    _save(fig, "precision_noise.png")


def fig_ablation(ablation):
    labels = ["Coverage", "Precision", "Noise rate"]
    grounded = [ablation["grounded"]["coverage"], ablation["grounded"]["precision"],
                ablation["grounded"]["noise_rate"]]
    ungrounded = [ablation["ungrounded"]["coverage"], ablation["ungrounded"]["precision"],
                  ablation["ungrounded"]["noise_rate"]]
    x = np.arange(len(labels))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7, 4.3))
    ax.bar(x - w / 2, grounded, w, label="Grounded reasoner", color=_PALETTE[0])
    ax.bar(x + w / 2, ungrounded, w, label="Ungrounded baseline", color=_PALETTE[5])
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.1)
    for i, (g, u) in enumerate(zip(grounded, ungrounded)):
        ax.text(i - w / 2, g + 0.02, f"{g:.2f}", ha="center", fontsize=8)
        ax.text(i + w / 2, u + 0.02, f"{u:.2f}", ha="center", fontsize=8)
    ax.set_title("Ablation: grounding keeps coverage while cutting noise")
    ax.legend()
    _save(fig, "ablation.png")


def _save(fig, name):
    os.makedirs(FIG, exist_ok=True)
    fig.tight_layout()
    path = os.path.join(FIG, name)
    fig.savefig(path, dpi=130, bbox_inches="tight")
    plt.close(fig)
    print(f"  figure -> figures/{name}")


def _read_eval_rows():
    import csv
    path = os.path.join(ROOT, "results", "evaluation.csv")
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["coverage"] = float(r["coverage"])
        r["precision"] = float(r["precision"])
        r["noise_rate"] = float(r["noise_rate"])
    return rows


def generate_all_figures():
    print("Generating figures...")
    # Ensure experiment outputs exist / are fresh.
    run_evaluation()
    ablation = run_ablation()
    eval_rows = _read_eval_rows()

    model, threats = _sample_threats()

    fig_pipeline()
    fig_threats_by_stride(threats)
    fig_risk_heatmap(threats)
    fig_threats_by_boundary(threats)
    fig_coverage_by_system(eval_rows)
    fig_precision_noise(eval_rows)
    fig_ablation(ablation)
    print("All figures written to figures/")


if __name__ == "__main__":
    generate_all_figures()
