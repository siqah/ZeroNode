"""An SSH server that behaves enough like a Cisco ASA to break our client code.

The parsers are already tested against captured device output, which is the
right place for syntax. What fixtures cannot test is everything between our code
and that output: SSH negotiation, character echo, prompt detection, enable mode,
paging, configuration mode, and a device whose state actually changes when you
send it a command. Those are the parts of the client that have never run.

This is deliberately *not* a faithful ASA. It is a device-shaped surface that
Netmiko must drive for real, and its value is that it can refuse, paginate,
misparse and fail in the ways a real appliance does. Anything it proves about
syntax is a bonus; anything it proves about the transport is the point.
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import threading

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fake-asa")

HOSTNAME = "ciscoasa"
BANNER = "Type help or '?' for a list of available commands.\r\n"
PAGE_SIZE = 24

ACL_RE = re.compile(
    r"^access-list\s+(?P<acl>\S+)\s+"
    r"(?:line\s+(?P<line>\d+)\s+)?"
    r"(?:extended\s+)?"
    r"(?P<body>(?P<action>permit|deny)\s+.+)$",
    re.IGNORECASE,
)

SEED = [
    ("DMZ_TO_TRUST", 10, "permit tcp 10.10.1.0 255.255.255.0 10.20.1.0 255.255.255.0 eq www", 42),
    ("DMZ_TO_TRUST", 40, "deny tcp 10.10.1.0 255.255.255.0 host 10.20.1.50 eq https", 1284),
    ("DMZ_TO_TRUST", 50, "deny ip any any", 0),
]

NAT_OUTPUT = (
    "Manual NAT Policies (Section 1)\r\n"
    "1 (dmz) to (outside) source static WEB_APP WEB_APP_PUBLIC\r\n"
)

OBJECT_OUTPUT = (
    "object network WEB_APP\r\n"
    " host 10.10.1.10\r\n"
    "object network DB_PRIMARY\r\n"
    " host 10.20.1.50\r\n"
)


class Policy:
    """The device's configuration, and the only thing a change can alter."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.rules: list[dict] = [
            {"acl": acl, "line": line, "body": body, "hits": hits}
            for acl, line, body, hits in SEED
        ]

    def add(self, acl: str, line: int | None, body: str) -> str:
        with self.lock:
            existing = [r for r in self.rules if r["acl"] == acl]
            if any(r["body"].lower() == body.lower() for r in existing):
                # The ASA accepts a duplicate quietly rather than erroring.
                return ""
            placement = line if line is not None else max(
                (r["line"] for r in existing), default=0
            ) + 10
            # Inserting at a line pushes everything at or below it down.
            if line is not None:
                for rule in existing:
                    if rule["line"] >= line:
                        rule["line"] += 1
            self.rules.append({"acl": acl, "line": placement, "body": body, "hits": 0})
        return ""

    def remove(self, acl: str, body: str) -> str:
        with self.lock:
            doomed = [
                rule
                for rule in self.rules
                if rule["acl"] == acl and rule["body"].lower() == body.lower()
            ]
            if not doomed:
                return f"ERROR: access-list <{acl}> does not exist"

            for rule in doomed:
                self.rules.remove(rule)
                # Deleting a line closes the gap, exactly as inserting one opened
                # it. Without this the ACL drifts every time a change is undone.
                for other in self.rules:
                    if other["acl"] == acl and other["line"] > rule["line"]:
                        other["line"] -= 1
        return ""

    def show(self, acl_filter: str = "") -> str:
        with self.lock:
            rules = sorted(self.rules, key=lambda r: (r["acl"], r["line"]))
        if acl_filter:
            rules = [rule for rule in rules if rule["acl"] == acl_filter]

        lines = [
            "access-list cached ACL log flows: total 0, denied 0 (deny-flow-max 4096)",
            "            alert-interval 300",
        ]
        for acl in sorted({rule["acl"] for rule in rules}):
            members = [rule for rule in rules if rule["acl"] == acl]
            lines.append(f"access-list {acl}; {len(members)} elements; name hash: 0x1a2b3c4d")
            for rule in members:
                lines.append(
                    f"access-list {acl} line {rule['line']} extended {rule['body']} "
                    f"(hitcnt={rule['hits']}) 0x4f2a9b71"
                )
        return "\r\n".join(lines)


class Session:
    """One CLI session: prompts, modes and the commands each mode accepts."""

    def __init__(
        self,
        channel: paramiko.Channel,
        policy: Policy,
        enable_password: str,
        privilege: int = 15,
    ) -> None:
        self.channel = channel
        self.policy = policy
        self.enable_password = enable_password
        self.privilege = privilege
        # A privilege-15 account lands straight in enable mode, which is how a
        # read-only service account is usually built. Anything less has to
        # `enable` first, and Netmiko's ASA driver insists on getting there.
        self.enabled = privilege >= 15
        self.config_mode = False
        self.paging = True
        self.awaiting_enable_password = False

    @property
    def prompt(self) -> str:
        if self.config_mode:
            return f"{HOSTNAME}(config)# "
        return f"{HOSTNAME}# " if self.enabled else f"{HOSTNAME}> "

    def send(self, text: str) -> None:
        self.channel.send(text.replace("\n", "\r\n") if "\r\n" not in text else text)

    def paginate(self, body: str) -> None:
        """Paging is on until someone turns it off, exactly like the real thing."""
        lines = body.split("\r\n")
        if not self.paging or len(lines) <= PAGE_SIZE:
            self.send(body + "\r\n")
            return
        for start in range(0, len(lines), PAGE_SIZE):
            self.send("\r\n".join(lines[start : start + PAGE_SIZE]) + "\r\n")
            if start + PAGE_SIZE < len(lines):
                self.send("<--- More --->")
                self.channel.recv(16)
                self.send("\r\n")

    def run(self, line: str) -> None:
        command = line.strip()

        if self.awaiting_enable_password:
            self.awaiting_enable_password = False
            self.enabled = command == self.enable_password or not self.enable_password
            if not self.enabled:
                self.send("Access denied.\r\n")
            return

        if not command:
            return

        lowered = command.lower()

        if lowered == "enable":
            if self.enable_password:
                self.awaiting_enable_password = True
                self.channel.send("Password: ")
                return
            self.enabled = True
            return

        if lowered.startswith("terminal pager"):
            self.paging = not lowered.endswith("0")
            return
        if lowered.startswith("terminal width"):
            return

        if lowered in ("configure terminal", "conf t"):
            if not self.enabled:
                self.send("ERROR: % Invalid input detected at '^' marker.\r\n")
                return
            self.config_mode = True
            return

        if lowered in ("end", "exit", "quit"):
            if self.config_mode:
                self.config_mode = False
                return
            self.channel.close()
            return

        if self.config_mode:
            self.configure(command)
            return

        self.show(lowered, command)

    def configure(self, command: str) -> None:
        removal = command.lower().startswith("no ")
        body = command[3:].strip() if removal else command

        match = ACL_RE.match(body)
        if not match:
            # The response a real ASA gives, and the one our code has to survive.
            self.send("ERROR: % Invalid input detected at '^' marker.\r\n")
            return

        acl = match.group("acl")
        rule_body = " ".join(match.group("body").split())
        line = int(match.group("line")) if match.group("line") else None

        error = (
            self.policy.remove(acl, rule_body)
            if removal
            else self.policy.add(acl, line, rule_body)
        )
        if error:
            self.send(error + "\r\n")
        logger.info("config: %s", command)

    def show(self, lowered: str, command: str) -> None:
        if not lowered.startswith("show "):
            self.send("ERROR: % Invalid input detected at '^' marker.\r\n")
            return

        if lowered.startswith("show curpriv"):
            # Netmiko's ASA driver sends this before anything else.
            mode = "P_PRIV" if self.enabled else "P_UNPR"
            self.send(
                f"Username : netops\r\n"
                f"Current privilege level       : {self.privilege if self.enabled else 1}\r\n"
                f"Current Mode/s                : {mode}\r\n"
            )
        elif lowered.startswith("show access-list"):
            parts = command.split()
            self.paginate(self.policy.show(parts[2] if len(parts) > 2 else ""))
        elif "object-group" in lowered:
            self.send("\r\n")
        elif "running-config object" in lowered:
            self.send(OBJECT_OUTPUT)
        elif lowered.startswith("show nat"):
            self.send(NAT_OUTPUT)
        elif lowered.startswith("show version"):
            self.send(f"Cisco Adaptive Security Appliance Software Version 9.16(1)\r\n{HOSTNAME}\r\n")
        else:
            self.send("ERROR: % Invalid input detected at '^' marker.\r\n")


class Server(paramiko.ServerInterface):
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        logger.warning("rejected login for %s", username)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True

    def check_channel_pty_request(self, *args, **kwargs) -> bool:
        return True


def handle(client: socket.socket, host_key: paramiko.PKey, policy: Policy, args) -> None:
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server = Server(args.username, args.password)
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None or not server.shell_requested.wait(10):
            return

        session = Session(channel, policy, args.enable_password, args.privilege)
        channel.send(BANNER)
        channel.send(session.prompt)

        buffer = ""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            for char in data.decode("utf-8", "ignore"):
                if char in "\r\n":
                    channel.send("\r\n")
                    session.run(buffer)
                    buffer = ""
                    if channel.closed:
                        return
                    channel.send(session.prompt)
                elif char in ("\x7f", "\b"):
                    buffer = buffer[:-1]
                    channel.send("\b \b")
                else:
                    buffer += char
                    # Netmiko reads its own echo back to find the prompt.
                    channel.send(char)
    except Exception as exc:  # noqa: BLE001 - one bad session must not stop the server
        logger.warning("session ended: %s", exc)
    finally:
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="A fake Cisco ASA over SSH")
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - it is a lab container
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", default="netops")
    parser.add_argument("--password", default="zeronode")
    parser.add_argument("--enable-password", default="")
    parser.add_argument(
        "--privilege",
        type=int,
        default=15,
        help="15 lands the session in enable mode, as a service account usually does",
    )
    args = parser.parse_args()

    host_key = paramiko.RSAKey.generate(2048)
    policy = Policy()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(16)
    logger.info("fake ASA listening on %s:%s as %s", args.host, args.port, args.username)

    while True:
        client, address = listener.accept()
        logger.info("connection from %s", address[0])
        threading.Thread(
            target=handle, args=(client, host_key, policy, args), daemon=True
        ).start()


if __name__ == "__main__":
    main()
