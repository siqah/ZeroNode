#!/usr/bin/env python3
"""Lightweight load test for /health and /metrics (no Ollama required)."""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from dataclasses import dataclass

import httpx


@dataclass
class Result:
    ok: int = 0
    failed: int = 0
    latencies_ms: list[float] | None = None

    def __post_init__(self) -> None:
        if self.latencies_ms is None:
            self.latencies_ms = []


async def _worker(
    client: httpx.AsyncClient,
    path: str,
    stop_at: float,
    result: Result,
) -> None:
    while time.perf_counter() < stop_at:
        started = time.perf_counter()
        try:
            response = await client.get(path)
            elapsed_ms = (time.perf_counter() - started) * 1000
            result.latencies_ms.append(elapsed_ms)
            if response.status_code < 500:
                result.ok += 1
            else:
                result.failed += 1
        except httpx.HTTPError:
            result.failed += 1


async def run_load(
    *,
    base_url: str,
    duration: float,
    concurrency: int,
    paths: list[str],
) -> dict[str, Result]:
    stop_at = time.perf_counter() + duration
    results = {path: Result() for path in paths}
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        tasks = []
        for path in paths:
            for _ in range(concurrency):
                tasks.append(asyncio.create_task(_worker(client, path, stop_at, results[path])))
        await asyncio.gather(*tasks)
    return results


def _summarise(path: str, result: Result) -> dict:
    total = result.ok + result.failed
    latencies = result.latencies_ms or []
    return {
        "path": path,
        "requests": total,
        "ok": result.ok,
        "failed": result.failed,
        "error_rate": (result.failed / total) if total else 0.0,
        "p50_ms": statistics.median(latencies) if latencies else 0.0,
        "p95_ms": (
            sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0.0
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Load-test ZeroNode read-only endpoints.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--duration", type=float, default=30.0, help="Seconds to run")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument(
        "--max-error-rate",
        type=float,
        default=0.01,
        help="Exit 1 if any path exceeds this error rate",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["/health", "/metrics"],
        help="Paths to hammer (read-only)",
    )
    args = parser.parse_args(argv)

    results = asyncio.run(
        run_load(
            base_url=args.base_url.rstrip("/"),
            duration=args.duration,
            concurrency=args.concurrency,
            paths=args.paths,
        )
    )

    failed_gate = False
    for path in args.paths:
        summary = _summarise(path, results[path])
        print(
            f"{summary['path']}: {summary['requests']} req, "
            f"{summary['failed']} fail, p50={summary['p50_ms']:.1f}ms, "
            f"p95={summary['p95_ms']:.1f}ms"
        )
        if summary["error_rate"] > args.max_error_rate:
            failed_gate = True

    return 1 if failed_gate else 0


if __name__ == "__main__":
    raise SystemExit(main())
