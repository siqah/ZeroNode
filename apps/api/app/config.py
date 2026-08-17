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
