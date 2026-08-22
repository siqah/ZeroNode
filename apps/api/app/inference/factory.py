"""Construct the chat model from settings (Ollama or OpenAI-compatible vLLM)."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_ollama import ChatOllama

from app.config import Settings
from app.jobs.resilience import CircuitBreaker, ResilientChatModel


def _ollama_llm(settings: Settings) -> BaseChatModel:
    return ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
        num_predict=settings.ollama_num_predict,
        temperature=0,
    )


def _openai_compatible_llm(settings: Settings) -> BaseChatModel:
    if not settings.openai_compatible_base_url.strip():
        raise RuntimeError(
            "INFERENCE_BACKEND=openai_compatible requires OPENAI_COMPATIBLE_BASE_URL "
            "(for example http://gpu-host:8000/v1 for vLLM)"
        )
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:  # pragma: no cover - optional until installed
        raise RuntimeError(
            "INFERENCE_BACKEND=openai_compatible requires langchain-openai "
            "(pip install langchain-openai)"
        ) from exc

    return ChatOpenAI(
        model=settings.openai_compatible_model or settings.ollama_model,
        base_url=settings.openai_compatible_base_url.rstrip("/"),
        api_key=settings.openai_compatible_api_key or "EMPTY",
        temperature=0,
        max_tokens=settings.ollama_num_predict,
    )


def make_llm(settings: Settings) -> tuple[ResilientChatModel, CircuitBreaker]:
    backend = (settings.inference_backend or "ollama").strip().lower()
    if backend == "ollama":
        inner = _ollama_llm(settings)
    elif backend in {"openai_compatible", "vllm"}:
        inner = _openai_compatible_llm(settings)
    else:
        raise RuntimeError(
            f"Unknown INFERENCE_BACKEND {settings.inference_backend!r}; "
            "use ollama or openai_compatible"
        )

    circuit = CircuitBreaker(
        failure_threshold=settings.model_circuit_failures,
        reset_seconds=settings.model_circuit_reset_seconds,
    )
    wrapped = ResilientChatModel(
        inner,
        timeout_seconds=settings.model_timeout_seconds,
        max_retries=settings.model_max_retries,
        backoff_seconds=settings.model_retry_backoff_seconds,
        circuit=circuit,
    )
    return wrapped, circuit
