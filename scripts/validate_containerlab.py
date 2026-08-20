#!/usr/bin/env python
"""Close the Phase 2 execution gate against a live Containerlab SR Linux node."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.execute import APPLIED, ROLLED_BACK, DeviceExecutor  # noqa: E402
from app.execute.session import ConfigSession  # noqa: E402
from app.firewall.base import FlowQuery  # noqa: E402
from app.firewall.srlinux import NokiaSrlinuxFirewall  # noqa: E402

DEVICE = "FW_Edge"
ACL = "DMZ_TO_TRUST"
COMMAND = (
    f"ip access-list extended {ACL} permit tcp "
    "host 10.10.1.10 host 10.20.1.50 eq 443"
)
ROLLBACK = f"no {COMMAND}"
FLOW = FlowQuery(
    source_device="Web_App",
    source_ip="10.10.1.10",
    target_device="DB_Primary",
    target_ip="10.20.1.50",
    port=443,
)
FLOWS = [
    {
        "src": "10.10.1.10",
        "dst": "10.20.1.50",
        "port": 443,
        "proto": "tcp",
    }
]


def action(position: int) -> dict:
    return {
        "device": DEVICE,
        "command": COMMAND,
        "rollback": ROLLBACK,
        "position": position,
        "verified": True,
        "rollback_verified": True,
    }


def packet_passes() -> bool:
    """Ask the DMZ host to make the actual TCP/443 connection."""
    result = subprocess.run(
        [
            "docker",
            "exec",
            "clab-zeronode-web",
            "wget",
            "-T",
            "3",
            "-qO-",
            "http://10.20.1.50:443/",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode == 0 and result.stdout.strip() == "ok"


def main() -> int:
    host = os.environ.get("SRL_HOST", "127.0.0.1")
    port = int(os.environ.get("SRL_PORT", "2223"))
    username = os.environ.get("SRL_USERNAME", "admin")
    password = os.environ.get("SRL_PASSWORD", "NokiaSrl1!")

    firewall = NokiaSrlinuxFirewall(
        host=host,
        port=port,
        username=username,
        password=password,
        acl_name=ACL,
        device_id=DEVICE,
        timeout=60,
    )

    def sessions(_: str) -> ConfigSession:
        return ConfigSession(
            host,
            username,
            password,
            device_type="nokia_srl",
            device_id=DEVICE,
            port=port,
            timeout=60,
        )

    def remove_test_rules() -> None:
        firewall.refresh(DEVICE)
        lines = [
            rule.line
            for rule in firewall.acl_policy(DEVICE)
            if rule.action == "permit"
            and rule.src in ("10.10.1.10", "10.10.1.10/32")
            and rule.dst in ("10.20.1.50", "10.20.1.50/32")
            and rule.port == 443
        ]
        if not lines:
            return
        session = sessions(DEVICE)
        try:
            commands = [
                f"delete / acl acl-filter {ACL} type ipv4 entry {line}"
                for line in lines
            ]
            session.send_config(commands)
        finally:
            session.close()
        firewall.refresh(DEVICE)

    try:
        remove_test_rules()
        denials = firewall.denied_flows(FLOW)
        if not denials:
            raise RuntimeError("the seeded HTTPS flow is not denied before the test")
        if packet_passes():
            raise RuntimeError("the real packet passed despite the seeded deny")
        print(f"READ PASS: {denials[0]['rule_id']} denies the seeded HTTPS flow")

        # Line 45 is after the deny at 40. The device accepts the ACE, live
        # verification catches that it does not fix the flow, and the executor
        # must remove it automatically.
        failed = DeviceExecutor(
            firewall,
            sessions,
            devices={DEVICE},
            auto_rollback=True,
            platform="nokia_srl",
        ).apply([action(45)], FLOWS)
        if failed.state != ROLLED_BACK:
            raise RuntimeError(
                f"expected automatic rollback, got {failed.state}: {failed.lines}"
            )
        if packet_passes():
            raise RuntimeError("the packet passed after the failed change was rolled back")
        print("ROLLBACK PASS: shadowed live change failed verification and was removed")

        # Line 30 is before the deny. It must land, permit the flow, and report
        # the device's read-back rather than the simulator's prediction.
        applied = DeviceExecutor(
            firewall,
            sessions,
            devices={DEVICE},
            auto_rollback=True,
            platform="nokia_srl",
        ).apply([action(30)], FLOWS)
        if applied.state != APPLIED:
            raise RuntimeError(f"expected applied, got {applied.state}: {applied.lines}")
        if firewall.denied_flows(FLOW):
            raise RuntimeError("the applied ACE is present but the flow is still denied")
        if not packet_passes():
            raise RuntimeError("the policy permits the flow but the real packet still fails")
        print("APPLY PASS: line 30 landed and a real HTTPS packet crossed the firewall")

        remove_test_rules()
        if not firewall.denied_flows(FLOW):
            raise RuntimeError("cleanup did not restore the original deny")
        if packet_passes():
            raise RuntimeError("cleanup restored the ACL model but not the packet deny")
        print("CLEANUP PASS: the lab returned to its seeded policy")
        return 0
    finally:
        try:
            remove_test_rules()
        finally:
            firewall.close()


if __name__ == "__main__":
    raise SystemExit(main())
