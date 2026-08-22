#!/usr/bin/env python3
"""Wait for the fake-asa SSH emulator to accept connections in CI."""

from __future__ import annotations

import os
import socket
import sys
import time

HOST = os.environ.get("FAKE_ASA_HOST", "127.0.0.1")
PORT = int(os.environ.get("FAKE_ASA_PORT", "2222"))


def main() -> int:
    deadline = time.time() + 60
    last_error = ""
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=2):
                print(f"Device emulator reachable at {HOST}:{PORT}")
                return 0
        except OSError as exc:
            last_error = str(exc)
            time.sleep(1)
    print(f"Device emulator not reachable at {HOST}:{PORT}: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
