# Experiments

Reproducible experiment configurations. All experiments are deterministic given
the seed (default `7`) and the stub backend, and write their outputs to
`results/`. Run them via the Makefile or the CLI.

| Experiment | Command | Output | What it measures |
| --- | --- | --- | --- |
| Coverage / precision / noise | `make evaluate` | `results/evaluation.csv`, `results/evaluation_summary.json` | Does the grounded pipeline surface the injected-weakness ground truth on synthetic systems, and how much noise does it add? |
| Tier-2 reference | `make reference-eval` | `results/reference_eval.json` | Tool output vs a hand-authored expert reference for the sample app. |
| Ablation (headline) | `make ablation` | `results/ablation.csv`, `results/ablation_summary.json` | Grounded reasoner vs an ungrounded "just ask the LLM" baseline: how much does grounding cut irrelevant threats? |

## Configuration

See `config/config.json` for the reasoner backend toggle and seed. The default
`stub` backend is deterministic and offline; `local-llm` talks to a local
OpenAI-compatible endpoint and falls back to the stub if unreachable;
`ungrounded-stub` is used only by the ablation baseline.

## Reproducing the reported numbers

```bash
make setup      # once
make data
make evaluate
make reference-eval
make ablation
make figures
```

Author: Krishita Sanjay Choksi.
