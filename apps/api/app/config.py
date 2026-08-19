from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "gemma4:e4b"
    ollama_num_predict: int = 640
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "zeronode"
    database_url: str = "postgresql://zeronode:zeronode@localhost:5433/zeronode"
    # Device access. "mock" uses fixtures; "cisco_asa" and "cisco_ios" open a
    # read-only SSH session.
    firewall_backend: str = "mock"
    firewall_host: str = ""
    firewall_username: str = ""
    firewall_password: str = ""
    # Enable secret, when `show` output requires privilege 15.
    firewall_secret: str = ""
    firewall_acl: str = ""
    firewall_device_id: str = "FW_Edge"

    # Auth. Disabling it is a deliberate, loudly logged development choice.
    auth_enabled: bool = True
    jwt_secret: str = ""
    jwt_ttl_minutes: int = 60
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    # Static token for machine callers (alerting systems) that only trigger incidents.
    service_token: str = ""

    # Session cookies. Set cookie_secure once the dashboard is served over TLS.
    cookie_secure: bool = False
    # Login throttling: per-IP window, then a persistent lock on the account.
    login_rate_limit: int = 10
    login_rate_window_seconds: int = 60
    login_lock_threshold: int = 5
    login_lock_minutes: int = 15
    # Approvers must have a second factor. Turning this off makes approvals
    # single-credential, which is exactly what the ledger cannot compensate for.
    mfa_required_for_approvers: bool = True

    # Ed25519 private key seed (base64) for the approval ledger. Without it the
    # ledger signs with an ephemeral key and past records cannot be verified.
    audit_signing_key: str = ""
    # Public keys of retired signing keys, comma separated. Records signed with
    # them stay verifiable after a rotation.
    audit_retired_keys: str = ""
    # Where to anchor the chain head. Put it on a volume the database cannot
    # write to, otherwise dropping the table also removes the evidence.
    audit_anchor_file: str = ""

    # Change windows, e.g. "mon-fri 22:00-04:00; sat,sun 00:00-06:00". Empty
    # means a change may be approved at any time. Freezes, e.g.
    # "2026-12-20..2027-01-02", always win over a window.
    change_windows: str = ""
    change_freezes: str = ""
    change_window_tz: str = "UTC"

    # Secrets. Any credential may be written as env:NAME, file:/path,
    # vault:path#field or exec:command instead of an inline value.
    secret_cache_seconds: int = 300
    vault_addr: str = ""
    vault_token: str = ""
    # Refuse to open a session to a real device with an inline credential.
    require_managed_secrets: bool = True
    # Refuse to start on a degraded store rather than quietly losing durability.
    strict_dependencies: bool = True

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "info"
    cors_origins: str = "http://localhost:3000"


def cypher_dir() -> Path:
    default = Path("/app/infra/neo4j")
    if (default / "seed.cypher").exists():
        return default
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "infra" / "neo4j"
        if (candidate / "seed.cypher").exists():
            return candidate
    return default


settings = Settings()
