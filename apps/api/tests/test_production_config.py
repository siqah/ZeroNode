"""Production baseline configuration validation tests."""

from __future__ import annotations

from app.audit.ledger import Signer
from app.config import Settings
from app.config_validate import validate_production_config


def test_production_baseline_rejects_disabled_auth():
    settings = Settings(production_baseline=True, auth_enabled=False)
    errors = validate_production_config(settings)
    assert any("AUTH_ENABLED" in error for error in errors)


def test_production_baseline_requires_audit_and_anchor():
    settings = Settings(
        production_baseline=True,
        auth_enabled=True,
        jwt_secret="secret",
        audit_signing_key="",
        audit_anchor_file="",
        cookie_secure=True,
        strict_dependencies=True,
        bootstrap_admin_email="admin@example.com",
        bootstrap_admin_password="password12345",
        worker_embedded=False,
        model_allow_inference_fallback=False,
    )
    errors = validate_production_config(settings)
    assert any("AUDIT_SIGNING_KEY" in error for error in errors)
    assert any("AUDIT_ANCHOR_FILE" in error for error in errors)


def test_production_baseline_rejects_invalid_audit_key():
    settings = Settings(
        production_baseline=True,
        auth_enabled=True,
        jwt_secret="secret",
        audit_signing_key="not-a-valid-seed",
        audit_anchor_file="/tmp/anchors.jsonl",
        cookie_secure=True,
        strict_dependencies=True,
        bootstrap_admin_email="admin@example.com",
        bootstrap_admin_password="password12345",
        worker_embedded=False,
        model_allow_inference_fallback=False,
    )
    errors = validate_production_config(settings)
    assert any("AUDIT_SIGNING_KEY is invalid" in error for error in errors)


def test_production_baseline_ok_with_required_values(tmp_path):
    settings = Settings(
        production_baseline=True,
        auth_enabled=True,
        jwt_secret="secret",
        audit_signing_key=Signer.generate_seed(),
        audit_anchor_file=str(tmp_path / "anchors.jsonl"),
        cookie_secure=True,
        strict_dependencies=True,
        bootstrap_admin_email="admin@example.com",
        bootstrap_admin_password="password12345",
        worker_embedded=False,
        model_allow_inference_fallback=False,
        firewall_backend="mock",
    )
    assert validate_production_config(settings) == []
