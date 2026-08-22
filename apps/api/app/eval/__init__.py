"""Golden-incident evaluation harness for Phase 4 model quality gates."""

from app.eval.runner import EvalReport, run_corpus, run_incident
from app.eval.scorers import score_incident

__all__ = ["EvalReport", "run_corpus", "run_incident", "score_incident"]
