# ThreatForge - reproducible pipeline targets.
# Author: Krishita Sanjay Choksi
#
# Everything runs offline with the deterministic stub LLM backend. A real local
# LLM and real repositories are optional (see README).

PY ?= ./.venv/bin/python
PIP ?= ./.venv/bin/pip
SEED ?= 7

.PHONY: help setup data analyze model reason attack verify privacy report sample \
        evaluate reference-eval ablation figures baseline gate test all clean

SAMPLE_ARGS = --name "Sample Web App" --code samples/py_webapp --diagram samples/diagrams/py_webapp.mmd

help:
	@echo "ThreatForge make targets:"
	@echo "  make setup           create .venv and install requirements"
	@echo "  make data            generate synthetic systems + matching diagrams"
	@echo "  make model           summarize the recovered model for the sample app"
	@echo "  make reason          run the grounded STRIDE sweep on the sample app"
	@echo "  make attack          chain threats into MITRE ATT&CK attack paths"
	@echo "  make verify          generate security tests (pytest) + Sigma rules"
	@echo "  make privacy         run the STRIDE + LINDDUN (privacy) sweep"
	@echo "  make report          full threat-model report + exports (sample app)"
	@echo "  make sample          alias for 'report' on the bundled sample app"
	@echo "  make evaluate        coverage/precision/noise on the synthetic catalog"
	@echo "  make reference-eval  Tier-2: tool vs hand-authored reference model"
	@echo "  make ablation        grounded vs ungrounded reasoner (headline result)"
	@echo "  make baseline        record current threats as the accepted baseline"
	@echo "  make gate            fail on new threats above the baseline (CI gating)"
	@echo "  make figures         (re)generate every chart in figures/"
	@echo "  make test            run the test suite"
	@echo "  make all             data -> report -> evaluate -> ablation -> figures"
	@echo "  make clean           remove generated results/figures/reports"

setup:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

data:
	$(PY) -m src.cli data --seed $(SEED)

analyze:
	$(PY) -m src.cli analyze --name "Sample Web App" \
		--code samples/py_webapp --diagram samples/diagrams/py_webapp.mmd

model:
	$(PY) -m src.cli model --name "Sample Web App" \
		--code samples/py_webapp --diagram samples/diagrams/py_webapp.mmd

reason:
	$(PY) -m src.cli reason --name "Sample Web App" \
		--code samples/py_webapp --diagram samples/diagrams/py_webapp.mmd

attack:
	$(PY) -m src.cli attack $(SAMPLE_ARGS)

verify:
	$(PY) -m src.cli verify $(SAMPLE_ARGS)

privacy:
	$(PY) -m src.cli reason $(SAMPLE_ARGS) --privacy

report sample:
	$(PY) -m src.cli sample

evaluate:
	$(PY) -m src.cli evaluate --seed $(SEED)

reference-eval:
	$(PY) -m src.cli reference-eval

ablation:
	$(PY) -m src.cli ablation --seed $(SEED)

baseline:
	$(PY) -m src.cli baseline $(SAMPLE_ARGS)

gate:
	$(PY) -m src.cli gate $(SAMPLE_ARGS) --fail-level $(FAIL_LEVEL)

FAIL_LEVEL ?= High

figures:
	$(PY) -m src.cli figures

test:
	$(PY) -m pytest tests/ -q

all: data report evaluate reference-eval ablation figures
	@echo "ThreatForge: full pipeline complete."

clean:
	rm -rf results/synthetic results/*.csv results/*.json figures/*.png \
		reports/sample_webapp* __pycache__ */__pycache__ */*/__pycache__
	@echo "Cleaned generated artifacts."
