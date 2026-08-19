from langchain_core.messages import AIMessage, HumanMessage

from app.firewall.mock import MockFirewall
from app.graph.nodes import AgentRuntime, supervisor_node
from app.store.memory import InMemoryTopology


class NativeToolLLM:
    """Mimics Ollama answering with a tool_calls payload and empty content."""

    def __init__(self, name: str, args: dict):
        self.name = name
        self.args = args

    def invoke(self, _messages):
        return AIMessage(
            content="",
            tool_calls=[
                {"name": self.name, "args": self.args, "id": "n-1", "type": "tool_call"}
            ],
        )


def test_native_tool_call_is_executed_not_inferred():
    agent = AgentRuntime(
        llm=NativeToolLLM(
            "trace_network_path",
            {"source_device": "Web_App", "target_device": "DB_Primary"},
        ),
        topology=InMemoryTopology(),
        firewall=MockFirewall(),
    )
    state = {
        "messages": [HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443")],
        "topology_context": "",
        "zone_context": "",
        "tool_log": [],
    }

    command = supervisor_node(state, agent)

    tool_log = command.update["tool_log"]
    assert not any(entry.startswith("inferred") for entry in tool_log)
    assert tool_log[-1].startswith("trace_network_path:")
    assert "FW_Edge" in command.update["topology_context"]
