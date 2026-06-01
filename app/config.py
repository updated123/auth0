"""
Application configuration — loaded once at startup from environment variables.
All other modules import `settings` from here; never import dotenv elsewhere.
"""
from __future__ import annotations

from functools import lru_cache

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    # Auth0 Regular Web App
    auth0_domain: str = Field(..., validation_alias="AUTH0_DOMAIN")
    auth0_client_id: str = Field(..., validation_alias="AUTH0_CLIENT_ID")
    auth0_client_secret: str = Field(..., validation_alias="AUTH0_CLIENT_SECRET")
    auth0_audience: str = Field("platform-api", validation_alias="AUTH0_AUDIENCE")

    # Auth0 Management API (Machine-to-Machine)
    auth0_mgmt_client_id: str = Field(..., validation_alias="AUTH0_MGMT_CLIENT_ID")
    auth0_mgmt_client_secret: str = Field(..., validation_alias="AUTH0_MGMT_CLIENT_SECRET")

    # Platform
    app_base_url: str = Field("http://localhost:8000", validation_alias="APP_BASE_URL")
    secret_key: str = Field(..., validation_alias="SECRET_KEY")
    webhook_secret: str = Field(..., validation_alias="WEBHOOK_SECRET")
    database_url: str = Field("sqlite:///./poc.db", validation_alias="DATABASE_URL")

    # Derived helpers — not env vars
    @property
    def auth0_issuer(self) -> str:
        return f"https://{self.auth0_domain}/"

    @property
    def auth0_jwks_uri(self) -> str:
        return f"https://{self.auth0_domain}/.well-known/jwks.json"

    @property
    def auth0_token_url(self) -> str:
        return f"https://{self.auth0_domain}/oauth/token"

    @property
    def auth0_authorize_url(self) -> str:
        return f"https://{self.auth0_domain}/authorize"

    @property
    def auth0_logout_url(self) -> str:
        return f"https://{self.auth0_domain}/v2/logout"

    @property
    def auth0_mgmt_base(self) -> str:
        return f"https://{self.auth0_domain}/api/v2"

    @property
    def callback_url(self) -> str:
        return f"{self.app_base_url}/callback"

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
        "populate_by_name": True,
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
