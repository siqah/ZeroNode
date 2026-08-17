"""Print the raw model output for a mid-investigation supervisor turn.

Useful when tool calls parse on turn one but not later: run this to see exactly
what the model emits once tool results are in the history.

    cd apps/api && .venv/bin/python ../../scripts/probe_turn.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_ollama import ChatOllama

from app.config import settings
from app.graph.prompts import SUPERVISOR_PROMPT

PATH_TEXT = (
    "Path Trace Success. Traffic flows through: "
    "Web_App -> SW_DMZ -> FW_Edge -> SW_TRUST -> DB_Primary"
)

HINT = (
    f"Known path: {PATH_TEXT}\n"
    "NEXT REQUIRED ACTION: security_boundary_check."
)

messages = [
    SystemMessage(content=SUPERVISOR_PROMPT + "\n\n" + HINT),
    HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443"),
    AIMessage(
        content="",
        tool_calls=[
            {
                "name": "trace_network_path",
                "args": {"source_device": "Web_App", "target_device": "DB_Primary"},
                "id": "xml-1",
                "type": "tool_call",
            }
        ],
    ),
    ToolMessage(content=PATH_TEXT, tool_call_id="xml-1"),
]

llm = ChatOllama(
    model=settings.ollama_model,
    base_url="http://127.0.0.1:11434",
    num_predict=settings.ollama_num_predict,
    temperature=0,
)

response = llm.invoke(messages)
print("----- RAW OUTPUT -----")
print(repr(response.content))
print("----- TOOL CALLS -----")
print(response.tool_calls)
print("----- KWARGS -----")
print(response.additional_kwargs)
print("----- METADATA -----")
print(response.response_metadata)
print("----- END -----")
