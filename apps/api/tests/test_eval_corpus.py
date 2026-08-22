"""Regression gate over the golden incident corpus (no Ollama required)."""

from __future__ import annotations

import pytest

from app.eval.corpus import load_corpus
from app.eval.runner import run_incident


@pytest.mark.parametrize("spec", load_corpus(), ids=lambda item: item.id)
def test_eval_corpus_incident(spec):
    result = run_incident(spec)
    assert result.passed, "\n".join(result.failures)
