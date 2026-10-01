"""Pluggable LLM backends for the threat reasoner.

The reasoner is grounded: it is handed a tightly-scoped candidate (one element,
one STRIDE category, one KB pattern that already matched the extracted model)
and asked only to confirm relevance and phrase the rationale. That keeps the
backend swappable and the output reproducible.

* :class:`StubBackend` - the default. Deterministic, no model download, no
  network, no GPU. It accepts every grounded candidate and renders the KB's
  templated rationale. This is what lets the whole pipeline run from a clean
  clone and what the tests pin against.

* :class:`LocalLLMBackend` - optional. Talks to a local OpenAI-compatible
  endpoint (e.g. Ollama / llama.cpp server) so sensitive architecture never
  leaves the machine. Used only when explicitly configured; falls back to the
  stub if the endpoint is unreachable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class Candidate:
    """A grounded (element, category, pattern) tuple offered to the backend."""

    component: str
    component_type: str
    stride_code: str
    stride_name: str
    pattern_id: str
    title: str
    rationale: str          # KB-rendered rationale (the grounding)
    evidence: dict[str, Any]  # attributes/flow facts that caused the match


@dataclass
class Judgment:
    """A backend's verdict on a candidate."""

    accept: bool
    rationale: str
    confidence: float = 1.0


class ReasonerBackend(Protocol):
    name: str

    def judge(self, candidate: Candidate) -> Judgment: ...


class StubBackend:
    """Deterministic backend: accepts grounded candidates, renders rationale.

    Because every candidate is already supported by a matched KB pattern over
    the extracted model, the correct grounded behaviour is to accept and explain
    - no hallucination is possible since the candidate space is model-derived.
    """

    name = "stub"

    def judge(self, candidate: Candidate) -> Judgment:
        return Judgment(accept=True, rationale=candidate.rationale, confidence=1.0)


class UngroundedStubBackend:
    """Baseline for the ablation study: ignores the extracted model.

    Simulates the "just ask the LLM for threats" approach by proposing the
    textbook STRIDE threats for an element's *type* regardless of whether the
    model supports them, and by inventing a few generic threats that a
    structure-blind model tends to emit. Used only by the ablation experiment to
    quantify how much grounding reduces irrelevant/unsupported threats. It is
    deterministic so the ablation is reproducible.
    """

    name = "ungrounded-stub"

    def judge(self, candidate: Candidate) -> Judgment:
        # Accepts everything, including type-generic threats that may not be
        # supported by the actual model - that is the point of the baseline.
        return Judgment(
            accept=True,
            rationale=f"(ungrounded) {candidate.title} is a common threat for a "
            f"{candidate.component_type}.",
            confidence=0.5,
        )


class LocalLLMBackend:
    """Optional backend for a local OpenAI-compatible chat endpoint.

    Never required. If the endpoint is unreachable, :meth:`judge` degrades to the
    stub so the pipeline keeps working offline.
    """

    name = "local-llm"

    def __init__(self, base_url: str, model: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._fallback = StubBackend()

    def _prompt(self, candidate: Candidate) -> str:
        return (
            "You are a security architect performing a STRIDE threat model. "
            "You are given ONE candidate threat already grounded in the extracted "
            "system model. Confirm whether it is relevant for THIS system and "
            "rewrite the rationale in one sentence. Do not invent new threats or "
            "reference components not listed. Respond as JSON "
            '{"accept": bool, "rationale": str}.\n\n'
            f"Component: {candidate.component} ({candidate.component_type})\n"
            f"STRIDE: {candidate.stride_name}\n"
            f"Candidate: {candidate.title}\n"
            f"Grounding rationale: {candidate.rationale}\n"
            f"Evidence from the model: {json.dumps(candidate.evidence)}\n"
        )

    def judge(self, candidate: Candidate) -> Judgment:
        try:
            import urllib.request

            payload = json.dumps(
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": self._prompt(candidate)}],
                    "temperature": 0.0,
                    "stream": False,
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.base_url}/v1/chat/completions",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode())
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(_extract_json(content))
            return Judgment(
                accept=bool(parsed.get("accept", True)),
                rationale=str(parsed.get("rationale", candidate.rationale)),
                confidence=float(parsed.get("confidence", 0.8)),
            )
        except Exception:
            # Offline / unreachable / malformed - fall back to deterministic stub.
            return self._fallback.judge(candidate)


def _extract_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return "{}"


def get_backend(config: dict[str, Any] | None) -> ReasonerBackend:
    """Factory: pick a backend from config; default to the deterministic stub."""
    config = config or {}
    kind = (config.get("backend") or "stub").lower()
    if kind == "local-llm":
        return LocalLLMBackend(
            base_url=config.get("base_url", "http://localhost:11434"),
            model=config.get("model", "llama3"),
            timeout=float(config.get("timeout", 30.0)),
        )
    if kind == "ungrounded-stub":
        return UngroundedStubBackend()
    return StubBackend()
