"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed application settings.

    Attributes:
        db_host: MySQL/MariaDB host.
        db_port: MySQL/MariaDB port.
        db_user: Database user (never `root`).
        db_password: Database user password.
        db_config: Name of the `ares_config` database.
        db_sessions: Name of the `ares_sessions` database.
        google_client_id: OAuth 2.0 client ID used to verify Google ID tokens.
        jwt_secret: Secret key used to sign and verify JWTs.
        jwt_algorithm: JWT signing algorithm.
        jwt_expire_minutes: JWT expiry in minutes.
        elasticsearch_url: Base URL of the Elasticsearch cluster.
    """

    db_host: str
    db_port: int
    db_user: str
    db_password: str
    db_config: str
    db_sessions: str

    google_client_id: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 10080

    elasticsearch_url: str

    agent_path: str

    reports_dir: str

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()  # type: ignore[call-arg]  # values are loaded from .env
