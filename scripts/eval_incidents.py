#!/usr/bin/env python3
"""Run the golden incident eval corpus (no Ollama required)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.eval.runner import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
