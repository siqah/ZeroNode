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
    # NetBox topology ingest (Phase 5). When URL and token are set, the API
    # refreshes Neo4j on startup and on an interval.
    netbox_url: str = ""
    netbox_token: str = ""
    netbox_verify_tls: bool = True
    topology_site: str = ""
    topology_replace_on_ingest: bool = True
    topology_ingest_interval_seconds: int = 3600
    topology_stale_seconds: float = 86400.0
    # Inference backend: local Ollama or an OpenAI-compatible GPU server (vLLM).
    inference_backend: str = "ollama"  # ollama | openai_compatible
    openai_compatible_base_url: str = ""
    openai_compatible_api_key: str = "EMPTY"
    openai_compatible_model: str = ""
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "zeronode"
    database_url: str = "postgresql://zeronode:zeronode@localhost:5433/zeronode"
    # Device access. "mock" uses fixtures; device backends open read-only SSH.
    firewall_backend: str = "mock"  # mock | cisco_asa | cisco_ios | arista_eos | nokia_srl
    firewall_host: str = ""
    firewall_username: str = ""
    firewall_password: str = ""
    # Enable secret, when `show` output requires privilege 15.
    firewall_secret: str = ""
    firewall_acl: str = ""
    firewall_device_id: str = "FW_Edge"
    firewall_port: int = 22

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

    # Execution. Off means an approved change is logged, never sent. Turning it
    # on is not enough: EXECUTION_DEVICES must name the devices it may touch.
    execution_enabled: bool = False
    execution_devices: str = ""
    # After a failed post-change check, put the device back automatically.
    # Turning this off leaves a failed change in place for a human.
    execution_auto_rollback: bool = True

    # Ticketing and notifications. Both are webhooks: a ServiceNow or Jira
    # inbound endpoint for the first, a Slack, Teams or Mattermost one for the
    # second. Unset means the workflow runs without them.
    ticket_webhook_url: str = ""
    ticket_webhook_token: str = ""
    notify_webhook_url: str = ""
    notify_webhook_token: str = ""
    # Used to build direct links in tickets and notifications.
    dashboard_url: str = "http://localhost:3000"

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

    # Phase 3 reliability: durable investigation workers and bounded inference.
    # A worker leases jobs from Postgres; without one, investigations stay queued.
    worker_id: str = ""
    worker_concurrency: int = 2
    worker_poll_seconds: float = 1.0
    # When true, the API process also runs a worker. Prefer the dedicated
    # Compose service in production; this is for single-process local runs.
    worker_embedded: bool = False
    job_lease_seconds: int = 60
    job_heartbeat_seconds: int = 15
    job_max_attempts: int = 5
    job_queue_capacity: int = 100
    # Model-call bounds. A hung Ollama call used to block a thread forever.
    model_timeout_seconds: float = 90.0
    model_max_retries: int = 2
    model_retry_backoff_seconds: float = 1.5
    model_circuit_failures: int = 5
    model_circuit_reset_seconds: float = 60.0
    # End-to-end latency budgets for live investigations (0 disables).
    model_incident_budget_seconds: float = 480.0
    model_node_budget_seconds: float = 120.0
    # When false, truncated or malformed model output fails the job instead of
    # advancing via infer_tool_call. Production should keep this false.
    model_allow_inference_fallback: bool = False
    # When true, /health degrades once any inference fallback has been recorded.
    model_fallback_degrades_health: bool = True
    # Observability. Metrics are always on; OTLP export is opt-in.
    log_json: bool = False
    metrics_enabled: bool = True
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "zeronode"
    # Outbound ticket/notification webhooks: transient failures are retried briefly.
    outbound_max_retries: int = 2
    outbound_retry_backoff_seconds: float = 0.5

    # Inbound alert webhooks.
    webhooks_enabled: bool = True
    webhook_rate_limit: int = 60
    webhook_rate_window_seconds: int = 60
    webhook_max_body_bytes: int = 262144
    pagerduty_webhook_secret: str = ""
    alertmanager_thread_prefix: str = "AM"
    pagerduty_thread_prefix: str = "PD"
    webhook_default_site: str = ""

    # Fail closed in production deployments.
    production_baseline: bool = False

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
