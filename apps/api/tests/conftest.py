import pytest

from app.firewall.asa import CiscoAsaFirewall, ReadOnlyViolation


class FakeAsa(CiscoAsaFirewall):
    """Exercises the adapter without a device by replacing only the transport."""

    def __init__(
        self,
        acl_output: str,
        group_output: str = "",
        object_output: str = "",
        nat_output: str = "",
    ) -> None:
        super().__init__(host="192.0.2.10", username="ro", password="x")
        self.acl_output = acl_output
        self.group_output = group_output
        self.object_output = object_output
        self.nat_output = nat_output
        self.sent: list[str] = []

    def _send(self, command: str) -> str:
        if not command.strip().lower().startswith("show "):
            raise ReadOnlyViolation(command)
        self.sent.append(command)
        if "object-group" in command:
            return self.group_output
        if "running-config object" in command:
            return self.object_output
        if command.strip().lower() == "show nat":
            return self.nat_output
        return self.acl_output


@pytest.fixture
def fake_asa():
    return FakeAsa
