"""Sliding-window rate limiting for the login endpoint.

Per-process and in memory, which is enough for a single API instance and is
stated as such: with several replicas the effective limit multiplies by the
replica count. Account lockout, which is stored in Postgres, is the control that
holds regardless of how many instances are running.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Record an attempt. Returns (allowed, seconds until a slot frees)."""
        moment = now if now is not None else time.monotonic()
        hits = self._hits[key]
        while hits and moment - hits[0] > self.window:
            hits.popleft()

        if len(hits) >= self.limit:
            return False, max(1, int(self.window - (moment - hits[0])))

        hits.append(moment)
        return True, 0

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)
