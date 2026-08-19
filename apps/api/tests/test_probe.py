"""The probe reports coverage honestly and stays read-only."""

import app.firewall.probe as probe_module
from app.firewall.probe import probe

ASA_ACL = (
    "access-list DMZ_TO_TRUST line 10 extended permit tcp host 10.10.1.10 "
    "host 10.20.1.50 eq www (hitcnt=4) 0xaaaa0001\n"
    "access-list DMZ_TO_TRUST line 20 extended deny tcp host 10.10.1.10 "
    "host 10.20.1.50 eq https (hitcnt=90) 0xaaaa0002\n"
)
UNSUPPORTED_ACL = ASA_ACL + (
    "access-list DMZ_TO_TRUST line 30 extended permit tcp object-group MISSING "
    "any eq https (hitcnt=0) 0xaaaa0003\n"
)


def run(monkeypatch, capsys, fake_asa, acl, flow=("10.10.1.10", "10.20.1.50", 443)):
    device = fake_asa(acl)
    monkeypatch.setattr(probe_module, "make_device_firewall", lambda *a, **k: device)
    code = probe("cisco_asa", "FW_Edge", flow)
    return code, capsys.readouterr().out, device


def test_a_fully_modelled_device_reports_success(monkeypatch, capsys, fake_asa):
    code, output, _ = run(monkeypatch, capsys, fake_asa, ASA_ACL)
    assert code == 0
    assert "2 read, 2 modelled, 0 not modelled" in output
    assert "fully supported" in output


def test_unmodelled_lines_are_printed_and_change_the_exit_code(monkeypatch, capsys, fake_asa):
    code, output, _ = run(monkeypatch, capsys, fake_asa, UNSUPPORTED_ACL)
    assert code == 1
    assert "1 not modelled" in output
    assert "MISSING" in output


def test_the_flow_verdict_and_read_only_guard_are_reported(monkeypatch, capsys, fake_asa):
    code, output, device = run(monkeypatch, capsys, fake_asa, ASA_ACL)
    assert "verdict     : deny (DMZ_TO_TRUST-20 at line 20)" in output
    assert "read-only     : enforced" in output
    assert all(command.startswith("show ") for command in device.sent)
    assert code == 0


def test_a_device_that_cannot_be_read_fails_loudly(monkeypatch, capsys, fake_asa):
    class Broken(fake_asa):
        def _send(self, command):
            raise RuntimeError("connection refused")

    device = Broken("")
    monkeypatch.setattr(probe_module, "make_device_firewall", lambda *a, **k: device)
    code = probe("cisco_asa", "FW_Edge", None)
    assert code == 2
    assert "FAILED to read the policy" in capsys.readouterr().out
