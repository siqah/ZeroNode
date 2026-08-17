from __future__ import annotations

from typing import Any


def minify_payload(value: Any, *, max_list_len: int = 50) -> Any:
    """Drop empty fields and cap list length before the LLM sees a tool result."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if item in (None, "", [], {}):
                continue
            out[key] = minify_payload(item, max_list_len=max_list_len)
        return out
    if isinstance(value, list):
        sliced = value[:max_list_len]
        items = [minify_payload(item, max_list_len=max_list_len) for item in sliced]
        omitted = len(value) - max_list_len
        if omitted > 0:
            items.append({"_truncated": True, "omitted": omitted})
        return items
    return value
