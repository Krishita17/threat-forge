"""ThreatForge command-line interface.

Subcommands mirror the pipeline stages so each can be run and inspected on its
own (human-in-the-loop review between stages):

    data       generate synthetic systems + matching diagrams + ground truth
    analyze    recover a system model from code and/or a diagram
    model      print/save the normalized system model (with trust boundaries)
    reason     run the grounded STRIDE sweep over a model
    report     produce the full threat-model report + exports
    evaluate   score coverage/precision on the synthetic catalog
    ablation   grounded vs. ungrounded reasoner comparison
    figures    (re)generate all charts and the sample worked example
    sample     run the full pipeline on the bundled sample app end-to-end

Everything defaults to the deterministic stub backend, so it runs offline.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .config import load_config
from .data.diagram_gen import to_mermaid
from .data.synthetic import generate_catalog
from .model.schema import SystemModel
from .pipeline import analyze_inputs, run_on_model, run_pipeline
from .report.report import generate_report

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _p(*parts: str) -> str:
    return os.path.join(ROOT, *parts)


def cmd_data(args):
    out = _p("results", "synthetic")
    diag_out = _p("samples", "diagrams")
    os.makedirs(out, exist_ok=True)
    os.makedirs(diag_out, exist_ok=True)
    catalog = generate_catalog(seed=args.seed)
    index = {}
    for name, sysm in catalog.items():
        # Save the model.
        with open(os.path.join(out, f"{name}.model.json"), "w", encoding="utf-8") as fh:
            fh.write(sysm.model.to_json())
        # Save ground truth.
        gt = [{"component": g.component, "stride": g.stride, "weakness": g.weakness}
              for g in sysm.expected]
        with open(os.path.join(out, f"{name}.groundtruth.json"), "w", encoding="utf-8") as fh:
            json.dump(gt, fh, indent=2)
        # Save a matching Mermaid diagram.
        with open(os.path.join(diag_out, f"{name}.mmd"), "w", encoding="utf-8") as fh:
            fh.write(to_mermaid(sysm.model))
        index[name] = {"expected_threats": len(sysm.expected),
                       "components": len([e for e in sysm.model.elements])}
    with open(os.path.join(out, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
    print(f"Generated {len(catalog)} synthetic systems -> {out}")
    print(f"Matching diagrams -> {diag_out}")


def cmd_analyze(args):
    model = analyze_inputs(args.name, repo_path=args.code, diagram_path=args.diagram)
    text = model.to_json()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Model -> {args.out}")
    else:
        print(text)


def cmd_model(args):
    model = analyze_inputs(args.name, repo_path=args.code, diagram_path=args.diagram)
    print(f"System: {model.name}")
    print(f"  elements: {len([e for e in model.elements])}")
    print(f"  flows: {len(model.flows)}")
    print(f"  trust boundaries: {len(model.boundaries)}")
    for b in model.boundaries:
        print(f"    - {b.name} ({len(b.crossing_flows)} crossing flows)")


def cmd_reason(args):
    cfg = load_config()
    model = analyze_inputs(args.name, repo_path=args.code, diagram_path=args.diagram)
    threats = run_on_model(model, backend_config=cfg["reasoner"])
    print(f"{len(threats)} threats identified:")
    for t in threats:
        print(f"  [{t.id}] {t.stride_name:22} {t.component:20} risk {t.risk:2} ({t.risk_level})")


def cmd_report(args):
    cfg = load_config()
    model, threats = run_pipeline(
        args.name, repo_path=args.code, diagram_path=args.diagram,
        backend_config=cfg["reasoner"],
    )
    out_dir = args.out or _p("reports")
    paths = generate_report(model, threats, out_dir, slug=args.slug)
    print("Report artifacts:")
    for k, v in paths.items():
        print(f"  {k:14} {os.path.relpath(v, ROOT)}")


def cmd_sample(args):
    """Full pipeline on the bundled sample app + its diagram."""
    cfg = load_config()
    code = _p("samples", "py_webapp")
    diagram = _p("samples", "diagrams", "py_webapp.mmd")
    diagram = diagram if os.path.exists(diagram) else None
    model, threats = run_pipeline(
        "Sample Web App", repo_path=code, diagram_path=diagram,
        backend_config=cfg["reasoner"],
    )
    out_dir = _p("reports")
    paths = generate_report(model, threats, out_dir, slug="sample_webapp")
    print(f"Sample threat model: {len(threats)} threats, "
          f"{len(model.boundaries)} trust boundaries")
    for k, v in paths.items():
        print(f"  {k:14} {os.path.relpath(v, ROOT)}")


def cmd_evaluate(args):
    from .experiments.run_eval import run_evaluation  # noqa: E402
    run_evaluation(seed=args.seed)


def cmd_ablation(args):
    from .experiments.run_ablation import run_ablation  # noqa: E402
    run_ablation(seed=args.seed)


def cmd_reference_eval(args):
    from .experiments.run_reference_eval import run_reference_eval  # noqa: E402
    run_reference_eval()


def cmd_figures(args):
    from .report.figures import generate_all_figures  # noqa: E402
    generate_all_figures()


def _add_input_args(sp, require=False):
    sp.add_argument("--name", default="System", help="system name")
    sp.add_argument("--code", help="path to a code repository to analyze")
    sp.add_argument("--diagram", help="path to a Mermaid diagram to analyze")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatforge", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("data", help="generate synthetic systems + diagrams")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=cmd_data)

    sp = sub.add_parser("analyze", help="recover a system model")
    _add_input_args(sp)
    sp.add_argument("--out", help="write model JSON to this path")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("model", help="summarize the system model + boundaries")
    _add_input_args(sp)
    sp.set_defaults(func=cmd_model)

    sp = sub.add_parser("reason", help="run the grounded STRIDE sweep")
    _add_input_args(sp)
    sp.set_defaults(func=cmd_reason)

    sp = sub.add_parser("report", help="generate the threat-model report + exports")
    _add_input_args(sp)
    sp.add_argument("--out", help="output directory (default: reports/)")
    sp.add_argument("--slug", help="file slug")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("sample", help="run end-to-end on the bundled sample app")
    sp.set_defaults(func=cmd_sample)

    sp = sub.add_parser("evaluate", help="score coverage/precision on synthetic catalog")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("ablation", help="grounded vs ungrounded reasoner")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=cmd_ablation)

    sp = sub.add_parser("reference-eval", help="Tier-2: tool vs hand-authored reference")
    sp.set_defaults(func=cmd_reference_eval)

    sp = sub.add_parser("figures", help="regenerate all charts + sample example")
    sp.set_defaults(func=cmd_figures)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
