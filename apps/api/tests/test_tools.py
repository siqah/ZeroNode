from app.minify import minify_payload
from app.store.memory import InMemoryTopology
from app.tools.topology import (
    AclHitsInput,
    BoundaryInput,
    DelegateFirewallInput,
    DeniedFlowsInput,
    PathTraceInput,
    ProposeChangeInput,
    handle_acl_hits,
    handle_delegate_firewall,
    handle_denied_flows,
    handle_path_trace,
    handle_propose_change,
    handle_security_boundary,
)


def test_path_trace_cross_zone():
    topo = InMemoryTopology()
    result = handle_path_trace(
        PathTraceInput(source_device="Web_App", target_device="DB_Primary"),
        {},
        topo,
    )
    assert result.content == (
        "Path Trace Success. Traffic flows through: "
        "Web_App -> SW_DMZ -> FW_Edge -> SW_TRUST -> DB_Primary"
    )
    assert "Web_App -> SW_DMZ" in result.state_update["topology_context"]


def test_path_trace_unknown_device():
    topo = InMemoryTopology()
    result = handle_path_trace(
        PathTraceInput(source_device="core-router-04", target_device="DB_Primary"),
        {},
        topo,
    )
    assert result.content.startswith("Error: device 'core-router-04' not found")
    assert "Web_App" in result.content


def test_security_boundary_crosses():
    topo = InMemoryTopology()
    result = handle_security_boundary(
        BoundaryInput(source_device="Web_App", target_device="DB_Primary"),
        {},
        topo,
    )
    assert "source_zone=DMZ" in result.content
    assert "dest_zone=TRUST" in result.content
    assert "crosses_boundary=true" in result.content


def test_delegate_requires_topology_first():
    topo = InMemoryTopology()
    result = handle_delegate_firewall(
        DelegateFirewallInput(context="blocked", target_devices=["FW_Edge"]),
        {},
        topo,
    )
    assert result.goto is None
    assert "query topology" in result.content


def test_delegate_after_topology():
    topo = InMemoryTopology()
    result = handle_delegate_firewall(
        DelegateFirewallInput(context="blocked", target_devices=["FW_Edge"]),
        {"topology_context": "crosses_boundary=true"},
        topo,
    )
    assert result.goto == "firewall_specialist"
    assert result.state_update["active_worker"] == "firewall"


def test_denied_flows_minified():
    rows_msg = handle_denied_flows(
        DeniedFlowsInput(source_device="Web_App", target_device="DB_Primary"),
        {},
        InMemoryTopology(),
    )
    assert "ACL-DMZ-47" in rows_msg.content
    assert "None" not in rows_msg.content or "syslog" not in rows_msg.content


def test_acl_hits_filter():
    result = handle_acl_hits(
        AclHitsInput(device_id="FW_Edge", rule_id="ACL-DMZ-47"),
        {},
        InMemoryTopology(),
    )
    assert "ACL-DMZ-47" in result.content
    assert "ACL-DMZ-10" not in result.content


DENIED_FLOW_STATE = {
    "denied_flows": [
        {"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}
    ]
}


def test_propose_change_queues_hitl_when_simulation_passes():
    result = handle_propose_change(
        ProposeChangeInput(
            device_id="FW_Edge",
            command="access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
            position=39,
            rationale="allow https",
        ),
        DENIED_FLOW_STATE,
        InMemoryTopology(),
    )
    assert result.goto == "execute_change"
    action = result.state_update["pending_actions"][0]
    assert action["device"] == "FW_Edge"
    assert action["verified"] is True


def test_shadowed_change_is_not_queued_for_approval():
    result = handle_propose_change(
        ProposeChangeInput(
            device_id="FW_Edge",
            command="access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
            rationale="allow https",
        ),
        DENIED_FLOW_STATE,
        InMemoryTopology(),
    )
    assert result.goto is None
    assert "pending_actions" not in result.state_update
    assert "shadowed" in result.content


def test_change_without_evidence_is_not_queued():
    result = handle_propose_change(
        ProposeChangeInput(
            device_id="FW_Edge",
            command="permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
            rationale="allow https",
        ),
        {},
        InMemoryTopology(),
    )
    assert result.goto is None
    assert "No observed denied flow" in result.content


def test_minify_drops_empties():
    payload = minify_payload(
        {"keep": "x", "empty": None, "blank": "", "none_list": [], "nested": {"a": 1, "b": None}}
    )
    assert payload == {"keep": "x", "nested": {"a": 1}}
