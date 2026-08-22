"""LLM backend selection and latency budget errors."""

from app.inference.errors import ModelBudgetExceeded
from app.inference.factory import make_llm

__all__ = ["ModelBudgetExceeded", "make_llm"]
