from langchain_core.language_models.fake_chat_models import FakeListChatModel

GOLDEN_RESPONSES = [
    """<thinking>
1. Analyze alert: Web_App cannot reach DB_Primary on tcp/443.
2. Topology needed: check whether the path crosses a security zone.
3. Next action: security_boundary_check
</thinking>
<tool_call>
{"name": "security_boundary_check", "arguments": {"source_device": "Web_App", "target_device": "DB_Primary"}}
</tool_call>""",
    """<thinking>
1. Analyze alert: zones differ, traffic crosses a firewall boundary.
2. Topology needed: shortest path to name devices for the specialist.
3. Next action: trace_network_path
</thinking>
<tool_call>
{"name": "trace_network_path", "arguments": {"source_device": "Web_App", "target_device": "DB_Primary"}}
</tool_call>""",
    """<thinking>
1. Analyze alert: path includes FW_Edge between DMZ and TRUST.
2. Topology needed: done.
3. Next action: delegate_to_firewall_specialist
</thinking>
<tool_call>
{"name": "delegate_to_firewall_specialist", "arguments": {"context": "Web_App (DMZ) cannot reach DB_Primary (TRUST) on tcp/443. Path: Web_App -> SW_DMZ -> FW_Edge -> SW_TRUST -> DB_Primary.", "target_devices": ["FW_Edge", "Web_App", "DB_Primary"]}}
</tool_call>""",
    """<thinking>
1. What do I know? Cross-zone HTTPS is blocked on the path through FW_Edge.
2. Which tool next? get_denied_flows
</thinking>
<tool_call>
{"name": "get_denied_flows", "arguments": {"source_device": "Web_App", "target_device": "DB_Primary"}}
</tool_call>""",
    """<thinking>
1. What do I know? ACL-DMZ-47 denies Web_App to DB_Primary:443.
2. Which tool next? propose_policy_change on FW_Edge
</thinking>
<tool_call>
{"name": "propose_policy_change", "arguments": {"device_id": "FW_Edge", "command": "access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443", "rationale": "ACL-DMZ-47 denies Web_App->DB_Primary:443. Permit HTTPS exception on FW_Edge."}}
</tool_call>""",
    # Simulation rejects the line above: appended below ACL-DMZ-47 it is shadowed.
    """<thinking>
1. What do I know? The permit was appended after the deny at line 40, so it never matches.
2. Which tool next? propose_policy_change with an explicit position above line 40.
</thinking>
<tool_call>
{"name": "propose_policy_change", "arguments": {"device_id": "FW_Edge", "command": "access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443", "position": 39, "rationale": "ACL-DMZ-47 at line 40 denies Web_App->DB_Primary:443. Insert the HTTPS permit at line 39 so it is evaluated first."}}
</tool_call>""",
]


def scripted_llm(extra: list[str] | None = None) -> FakeListChatModel:
    return FakeListChatModel(responses=GOLDEN_RESPONSES + (extra or []))
