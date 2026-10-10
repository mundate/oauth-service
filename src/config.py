from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Read from environment variables (case-insensitive), or from a .env file in the working directory."""

    model_config = SettingsConfigDict(env_prefix="OAUTH_", env_file=".env", extra="ignore")

    # Sent as `iss` on every /authorize redirect so clients can tell which server the response came from (RFC 9207).
    ISSUER: str = "http://localhost:8000"


settings = Settings()
