"""Validate production configuration without starting the API."""

from __future__ import annotations

import sys

from app.config import settings
from app.config_validate import format_production_errors, validate_production_config


def main() -> int:
    errors = validate_production_config(settings)
    if errors:
        print(format_production_errors(errors), file=sys.stderr)
        return 1
    print("Production baseline configuration OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
