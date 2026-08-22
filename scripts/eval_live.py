#!/usr/bin/env python3
"""Live golden-incident eval against Ollama or an OpenAI-compatible GPU server."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.eval.live import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
