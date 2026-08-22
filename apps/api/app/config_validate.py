"""Production-baseline configuration validation."""

from __future__ import annotations

import base64

from app.config import Settings


def _audit_key_error(seed_b64: str) -> str | None:
    cleaned = seed_b64.strip()
    if not cleaned:
        return None
    try:
        seed = base64.b64decode(cleaned)
        if len(seed) != 32:
            return (
                "AUDIT_SIGNING_KEY must decode to 32 bytes (Ed25519 seed); "
                "generate one with: python -m app.audit.keys generate"
            )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        return (
            "AUDIT_SIGNING_KEY is invalid; generate one with: "
            "python -m app.audit.keys generate"
        )
    return None


def validate_production_config(settings: Settings) -> list[str]:
    """Return fatal configuration errors when PRODUCTION_BASELINE is enabled."""
    if not settings.production_baseline:
        return []

    errors: list[str] = []
    if not settings.auth_enabled:
        errors.append("AUTH_ENABLED must be true in production baseline mode")
    if not settings.jwt_secret.strip():
        errors.append("JWT_SECRET must be set in production baseline mode")
    if not settings.audit_signing_key.strip():
        errors.append("AUDIT_SIGNING_KEY must be set in production baseline mode")
    else:
        key_error = _audit_key_error(settings.audit_signing_key)
        if key_error:
            errors.append(key_error)
    if not settings.audit_anchor_file.strip():
        errors.append("AUDIT_ANCHOR_FILE must be set in production baseline mode")
    if not settings.cookie_secure:
        errors.append("COOKIE_SECURE must be true in production baseline mode")
    if not settings.strict_dependencies:
        errors.append("STRICT_DEPENDENCIES must be true in production baseline mode")
    if settings.model_allow_inference_fallback:
        errors.append("MODEL_ALLOW_INFERENCE_FALLBACK must be false in production baseline mode")
    if settings.worker_embedded:
        errors.append("WORKER_EMBEDDED must be false in production baseline mode")
    if not settings.bootstrap_admin_email.strip() and not settings.bootstrap_admin_password.strip():
        errors.append(
            "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set for first deploy"
        )
    if settings.firewall_backend.strip().lower() != "mock":
        if not settings.require_managed_secrets:
            errors.append("REQUIRE_MANAGED_SECRETS must be true for device backends")
        elif settings.firewall_password.strip():
            password = settings.firewall_password.strip()
            if not password.startswith(("file:", "env:", "vault:", "exec:")):
                errors.append("FIREWALL_PASSWORD must use a managed secret reference in production")
    return errors


def format_production_errors(errors: list[str]) -> str:
    return "Production baseline configuration invalid:\n- " + "\n- ".join(errors)
