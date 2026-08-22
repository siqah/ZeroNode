#!/usr/bin/env python3
"""Wait for Postgres to accept connections in CI."""

from __future__ import annotations

import os
import sys
import time

import psycopg

DSN = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://zeronode:zeronode@localhost:5433/zeronode"
)


def main() -> int:
    deadline = time.time() + 60
    last_error = ""
    while time.time() < deadline:
        try:
            with psycopg.connect(DSN, connect_timeout=2):
                print(f"Postgres reachable at {DSN}")
                return 0
        except Exception as exc:  # pragma: no cover - retry loop
            last_error = str(exc)
            time.sleep(1)
    print(f"Postgres not reachable at {DSN}: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
