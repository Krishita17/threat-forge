"""Configuration loader (backend toggle, framework selection, language)."""

from __future__ import annotations

import json
import os

_DEFAULT = {
    "reasoner": {"backend": "stub", "base_url": "http://localhost:11434", "model": "llama3"},
    "language": "python",
    "frameworks": ["ASVS", "NIST", "CWE"],
    "seed": 7,
}

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")


def load_config(path: str | None = None) -> dict:
    path = path or _CONFIG_PATH
    cfg = json.loads(json.dumps(_DEFAULT))  # deep copy
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        cfg.update(user)
    return cfg
