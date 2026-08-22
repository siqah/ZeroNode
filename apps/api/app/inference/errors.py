"""Inference quality and budget failures."""


class ModelBudgetExceeded(RuntimeError):
    """Raised when an investigation or graph node exceeds its latency budget."""


class InferenceFallbackDisabled(RuntimeError):
    """Raised when the model did not emit a valid tool call and infer is off."""
