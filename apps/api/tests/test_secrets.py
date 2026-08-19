"""Secret references: where a credential comes from, and what leaks."""

import pytest

from app.secretref import SecretError, SecretResolver, describe, is_managed, scheme_of


def test_a_bare_value_is_still_a_value():
    assert scheme_of("hunter2") == "literal"
    assert is_managed("hunter2") is False
    assert SecretResolver().resolve("hunter2") == "hunter2"


def test_known_schemes_are_recognised_and_unknown_ones_are_not():
    assert scheme_of("file:/run/secrets/x") == "file"
    assert scheme_of("vault:secret/data/app#field") == "vault"
    assert scheme_of("exec:aws secretsmanager get-secret-value") == "exec"
    # A password that happens to contain a colon must not be read as a scheme.
    assert scheme_of("postgres://user:pass@host") == "literal"
    assert scheme_of("file:") == "literal"


def test_env_references_resolve(monkeypatch):
    monkeypatch.setenv("ZN_TEST_SECRET", "from-the-environment")
    assert SecretResolver().resolve("env:ZN_TEST_SECRET") == "from-the-environment"


def test_a_missing_env_reference_fails_rather_than_returning_empty(monkeypatch):
    monkeypatch.delenv("ZN_TEST_SECRET", raising=False)
    with pytest.raises(SecretError):
        SecretResolver().resolve("env:ZN_TEST_SECRET")


def test_file_references_resolve_and_strip(tmp_path):
    path = tmp_path / "device_password"
    path.write_text("s3cret\n")
    assert SecretResolver().resolve(f"file:{path}") == "s3cret"


def test_a_missing_file_fails(tmp_path):
    with pytest.raises(SecretError, match="does not exist"):
        SecretResolver().resolve(f"file:{tmp_path / 'nope'}")


def test_exec_references_run_a_command():
    assert SecretResolver().resolve("exec:echo from-a-command") == "from-a-command"


def test_a_failing_command_fails_the_resolution():
    with pytest.raises(SecretError):
        SecretResolver().resolve("exec:false")


def test_an_empty_result_is_an_error_not_an_empty_password(tmp_path):
    path = tmp_path / "blank"
    path.write_text("   \n")
    with pytest.raises(SecretError, match="empty"):
        SecretResolver().resolve(f"file:{path}")


def test_values_are_cached_until_the_ttl_expires(tmp_path):
    path = tmp_path / "rotating"
    path.write_text("first")
    resolver = SecretResolver(ttl_seconds=300)
    assert resolver.resolve(f"file:{path}") == "first"

    path.write_text("second")
    assert resolver.resolve(f"file:{path}") == "first"

    # A short TTL is what makes rotation take effect without a restart.
    fresh = SecretResolver(ttl_seconds=0)
    assert fresh.resolve(f"file:{path}") == "second"


def test_a_getter_defers_resolution_to_the_moment_of_use(tmp_path):
    path = tmp_path / "late"
    path.write_text("value")
    getter = SecretResolver(ttl_seconds=0).getter(f"file:{path}")
    path.write_text("rotated")
    assert getter() == "rotated"


def test_descriptions_name_the_source_and_never_the_value(tmp_path):
    assert describe("file:/run/secrets/asa") == "file:/run/secrets/asa"
    assert describe("vault:secret/data/zeronode#asa_password") == "vault:secret/data/zeronode"
    assert describe("exec:aws secretsmanager get-secret-value --secret-id asa") == "exec:<command>"
    assert describe("hunter2") == "inline value"
    assert describe("") == "unset"


def test_vault_without_configuration_says_so():
    with pytest.raises(SecretError, match="VAULT_ADDR"):
        SecretResolver().resolve("vault:secret/data/x#field")


def test_a_vault_reference_needs_a_field():
    resolver = SecretResolver(vault_addr="http://vault:8200", vault_token="t")
    with pytest.raises(SecretError, match="#field"):
        resolver.resolve("vault:secret/data/x")
