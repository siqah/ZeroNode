"""Validate a read-only backend against a real device.

Parsers can be tested exhaustively against captured text, but no test proves
that a given production device prints what we expect. This command connects,
reads, and reports exactly how much of the policy we could model, so that gap is
closed by running one command rather than by trusting the code.

It sends only `show` commands and never asks the agent or the LLM for anything.

    python -m app.firewall.probe --backend cisco_asa --host 10.0.0.1 \
        --username readonly --acl DMZ_TO_TRUST --flow 10.10.1.10,10.20.1.50,443
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Any

from app.firewall.devices import make_device_firewall
from app.firewall.ssh import ReadOnlyViolation


def _coverage(rules: list[Any]) -> tuple[int, list[Any]]:
    modelled = [rule for rule in rules if rule.action in ("permit", "deny")]
    unparsed = [rule for rule in rules if rule.action == "unparsed"]
    return len(modelled), unparsed


def probe(backend: str, device_id: str, flow: tuple[str, str, int] | None, **kwargs: Any) -> int:
    firewall = make_device_firewall(backend, device_id=device_id, **kwargs)
    print(f"backend       : {firewall.describe()}")

    try:
        rules = firewall.acl_policy(device_id)
    except Exception as exc:  # noqa: BLE001 - the whole point is to report the failure
        print(f"FAILED to read the policy: {exc}")
        return 2

    modelled, unparsed = _coverage(rules)
    total = modelled + len(unparsed)
    print(f"acl entries   : {total} read, {modelled} modelled, {len(unparsed)} not modelled")

    for rule in unparsed:
        print(f"  unmodelled  : line {rule.line}: {rule.raw}")

    if flow is not None:
        source, destination, port = flow
        print(f"flow          : {source} -> {destination}:{port}/tcp")
        try:
            assessment = firewall.nat_assessment(device_id, [source, destination])
            if assessment.applies:
                print(f"  nat         : TRANSLATED {assessment.translated}")
            elif assessment.unresolved:
                print(f"  nat         : unresolved {assessment.unresolved}")
            else:
                print("  nat         : no translation found for these addresses")
        except Exception as exc:  # noqa: BLE001
            print(f"  nat         : could not be read ({exc})")

        from app.firewall.base import FlowQuery
        from app.firewall.policy import evaluate_flow

        action, hit = evaluate_flow(rules, source, destination, port, "tcp")
        where = f"{hit.rule_id} at line {hit.line}" if hit else "implicit deny"
        print(f"  verdict     : {action} ({where})")

        denied = firewall.denied_flows(
            FlowQuery(
                source_device="probe-src",
                source_ip=source,
                target_device="probe-dst",
                target_ip=destination,
                port=port,
            )
        )
        print(f"  denied_flows: {len(denied)} record(s)")

    try:
        firewall._send("configure terminal")
    except ReadOnlyViolation:
        print("read-only     : enforced (a write command was refused before transport)")
    except Exception as exc:  # noqa: BLE001
        print(f"read-only     : UNEXPECTED {exc}")
        return 2
    else:
        print("read-only     : BROKEN, a non-show command was accepted")
        return 2
    finally:
        close = getattr(firewall, "close", None)
        if close:
            close()

    if unparsed:
        print(
            "\nSome entries could not be modelled. The simulator reports a change as "
            "INCONCLUSIVE when any of them sit above the proposed line, so this is safe "
            "but limits coverage. Send the lines above to extend the parser."
        )
        return 1

    print("\nEvery entry was modelled; this device is fully supported.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe a device read-only")
    parser.add_argument("--backend", default="cisco_asa", choices=["cisco_asa", "cisco_ios"])
    parser.add_argument("--host", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--acl", default="", help="restrict to one access list")
    parser.add_argument("--device-id", default="FW_Edge")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--enable", action="store_true", help="prompt for an enable secret")
    parser.add_argument(
        "--flow",
        default="",
        help="src,dst,port to evaluate against the policy, e.g. 10.1.1.5,10.2.2.9,443",
    )
    args = parser.parse_args()

    flow: tuple[str, str, int] | None = None
    if args.flow:
        parts = args.flow.split(",")
        if len(parts) != 3:
            parser.error("--flow expects src,dst,port")
        flow = (parts[0].strip(), parts[1].strip(), int(parts[2]))

    password = getpass.getpass(
        "device password (blank to resolve FIREWALL_PASSWORD from its secret source): "
    )
    secret = getpass.getpass("enable secret: ") if args.enable else ""

    sys.exit(
        probe(
            args.backend,
            args.device_id,
            flow,
            host=args.host,
            username=args.username,
            password=password,
            secret=secret,
            acl_name=args.acl,
            port=args.port,
            timeout=args.timeout,
        )
    )


if __name__ == "__main__":
    main()
