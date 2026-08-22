"""Bounded model calls: timeout, retry, and a circuit breaker."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitOpen(RuntimeError):
    """Raised when the inference circuit is open and calls are refused."""


@dataclass
class CircuitBreaker:
    failure_threshold: int
    reset_seconds: float
    failures: int = 0
    opened_at: float | None = None
    _lock: threading.Lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self.opened_at is None:
                return True
            if time.monotonic() - self.opened_at >= self.reset_seconds:
                # Half-open: one probe is allowed.
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                if self.opened_at is None:
                    logger.error(
                        "inference circuit opened after %d failures", self.failures
                    )
                self.opened_at = time.monotonic()

    def state(self) -> str:
        with self._lock:
            return self._state_unlocked()

    def _state_unlocked(self) -> str:
        if self.opened_at is None:
            return "closed"
        if time.monotonic() - self.opened_at >= self.reset_seconds:
            return "half_open"
        return "open"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state_unlocked(),
                "failures": self.failures,
                "threshold": self.failure_threshold,
                "reset_seconds": self.reset_seconds,
            }


def call_with_retry(
    operation: Callable[[], T],
    *,
    timeout_seconds: float,
    max_retries: int,
    backoff_seconds: float,
    circuit: CircuitBreaker,
    is_transient: Callable[[BaseException], bool] | None = None,
) -> T:
    """Run ``operation`` with a wall-clock timeout, retries, and a circuit."""
    if not circuit.allow():
        raise CircuitOpen("inference circuit is open")

    transient = is_transient or _default_transient
    last_error: BaseException | None = None
    attempts = max_retries + 1
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        try:
            # ChatOllama.invoke is synchronous; bound it with a worker thread.
            result = _run_with_timeout(operation, timeout_seconds)
            circuit.record_success()
            return result
        except CircuitOpen:
            raise
        except BaseException as exc:  # noqa: BLE001 - classified below
            last_error = exc
            elapsed = time.monotonic() - started
            if not transient(exc):
                circuit.record_failure()
                raise
            logger.warning(
                "transient model failure on attempt %d/%d after %.1fs: %s",
                attempt,
                attempts,
                elapsed,
                exc,
            )
            if attempt >= attempts:
                circuit.record_failure()
                break
            time.sleep(backoff_seconds * attempt)

    assert last_error is not None
    raise last_error


def _run_with_timeout(operation: Callable[[], T], timeout_seconds: float) -> T:
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = operation()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout_seconds)
    if thread.is_alive():
        raise TimeoutError(f"model call exceeded {timeout_seconds}s")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _default_transient(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, ConnectionError, OSError, CircuitOpen)):
        return True
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    needles = ("timeout", "timed out", "connection", "temporarily", "unavailable", "503")
    return any(item in name or item in text for item in needles)


class ResilientChatModel:
    """Thin wrapper that keeps the LangChain invoke surface and adds bounds."""

    def __init__(
        self,
        inner: BaseChatModel,
        *,
        timeout_seconds: float,
        max_retries: int,
        backoff_seconds: float,
        circuit: CircuitBreaker,
    ) -> None:
        self.inner = inner
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.circuit = circuit

    def invoke(self, messages: list[BaseMessage], **kwargs: Any) -> Any:
        return call_with_retry(
            lambda: self.inner.invoke(messages, **kwargs),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            backoff_seconds=self.backoff_seconds,
            circuit=self.circuit,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)
