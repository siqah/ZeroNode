from app.graph.parser import extract_thinking, parse_tool_call


def test_parse_xml_wrapped_json():
    text = """
    filler
    <thinking>
    Need OSPF on core-router-04
    </thinking>
    <tool_call>
    {"name": "get_routing_stanza", "arguments": {"device_id": "core-router-04", "protocol": "ospf"}}
    </tool_call>
    """
    parsed = parse_tool_call(text)
    assert parsed is not None
    assert parsed.name == "get_routing_stanza"
    assert parsed.arguments["device_id"] == "core-router-04"
    assert extract_thinking(text) == "Need OSPF on core-router-04"


def test_parse_strips_json_fence():
    text = """<tool_call>
```json
{"name": "trace_network_path", "arguments": {"source_device": "Web_App", "target_device": "DB_Primary"}}
```
</tool_call>"""
    parsed = parse_tool_call(text)
    assert parsed is not None
    assert parsed.name == "trace_network_path"


def test_parse_malformed_returns_none():
    assert parse_tool_call("Here is the tool call you requested: {name: nope,}") is None
    assert parse_tool_call("<tool_call>not json</tool_call>") is None


def test_parse_unclosed_tool_call_when_stop_truncates():
    text = '<tool_call>\n{"name": "trace_network_path", "arguments": {"source_device": "Web_App", "target_device": "DB_Primary"}}\n'
    parsed = parse_tool_call(text)
    assert parsed is not None
    assert parsed.name == "trace_network_path"


PATH_CONTEXT = (
    "Path Trace Success. Traffic flows through: "
    "Web_App -> SW_DMZ -> FW_Edge -> SW_TRUST -> DB_Primary"
)
SUPERVISOR_TOOLS = {
    "trace_network_path",
    "security_boundary_check",
    "delegate_to_firewall_specialist",
}


def test_infer_traces_before_any_topology():
    from langchain_core.messages import HumanMessage

    from app.graph.parser import infer_tool_call

    parsed = infer_tool_call(
        allowed=SUPERVISOR_TOOLS,
        topology_context="",
        messages=[HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443")],
    )
    assert parsed is not None
    assert parsed.name == "trace_network_path"
    assert parsed.arguments == {"source_device": "Web_App", "target_device": "DB_Primary"}


def test_infer_boundary_check_once_path_is_known():
    from app.graph.parser import infer_tool_call

    parsed = infer_tool_call(allowed=SUPERVISOR_TOOLS, topology_context=PATH_CONTEXT)
    assert parsed is not None
    assert parsed.name == "security_boundary_check"


def test_infer_delegates_and_never_retraces_when_topology_complete():
    from app.graph.parser import infer_tool_call

    parsed = infer_tool_call(
        allowed=SUPERVISOR_TOOLS,
        topology_context=PATH_CONTEXT,
        zone_context="source_zone=DMZ dest_zone=TRUST crosses_boundary=true",
    )
    assert parsed is not None
    assert parsed.name == "delegate_to_firewall_specialist"
    assert "FW_Edge" in parsed.arguments["target_devices"]


def test_infer_proposes_change_from_denied_flow_facts():
    from app.graph.parser import infer_tool_call

    parsed = infer_tool_call(
        allowed={"get_denied_flows", "get_acl_hits", "propose_policy_change"},
        topology_context=PATH_CONTEXT,
        tool_log=[
            "get_denied_flows: [{'src': '10.10.1.10', 'dst': '10.20.1.50', "
            "'port': 443, 'action': 'deny', 'rule_id': 'ACL-DMZ-47'}]",
            "get_acl_hits: [{'device': 'FW_Edge', 'rule_id': 'ACL-DMZ-47', 'line': 40, "
            "'action': 'deny', 'src': '10.10.1.0/24', 'dst': '10.20.1.50', 'port': 443}]",
        ],
    )
    assert parsed is not None
    assert parsed.name == "propose_policy_change"
    assert "host 10.10.1.10 host 10.20.1.50 eq 443" in parsed.arguments["command"]
    assert parsed.arguments["position"] == 39
    assert "ACL-DMZ-47" in parsed.arguments["rationale"]


def test_infer_reads_the_acl_before_proposing():
    from app.graph.parser import infer_tool_call

    parsed = infer_tool_call(
        allowed={"get_denied_flows", "get_acl_hits", "propose_policy_change"},
        topology_context=PATH_CONTEXT,
        tool_log=[
            "get_denied_flows: [{'src': '10.10.1.10', 'dst': '10.20.1.50', "
            "'port': 443, 'action': 'deny', 'rule_id': 'ACL-DMZ-47'}]"
        ],
    )
    assert parsed is not None
    assert parsed.name == "get_acl_hits"
