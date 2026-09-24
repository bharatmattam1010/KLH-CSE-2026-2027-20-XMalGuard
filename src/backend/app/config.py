"""Configuration module for XMalGuard backend application.

Loads environment variables and application settings using Pydantic.
"""

from functools import lru_cache
import logging
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _USE_PYDANTIC_V2 = True
except ImportError:  # pragma: no cover
    from pydantic import BaseSettings  # type: ignore
    _USE_PYDANTIC_V2 = False

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings and configuration parameters loaded from environment."""

    # Security
    SECRET_KEY: str = "change-this-to-a-random-secret-key"

    # Database
    DATABASE_URL: str = "sqlite:///./xmalguard.db"

    # File Upload Configuration
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_EXTENSIONS: str = ".exe,.dll"
    UPLOAD_DIR: str = "temp_uploads"

    # Model Artifact Paths
    MODEL_PATH: str = "../models/final_model.joblib"
    SCALER_PATH: str = "../models/scaler.joblib"
    FEATURE_NAMES_PATH: str = "../models/feature_names.json"

    # Threat Intelligence
    VT_API_KEY: Optional[str] = ""

    # Risk Scoring Thresholds
    RISK_LOW_MAX: int = 24
    RISK_MEDIUM_MAX: int = 49
    RISK_HIGH_MAX: int = 74

    if _USE_PYDANTIC_V2:
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )
    else:  # pragma: no cover
        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "ignore"

    @property
    def allowed_extensions_list(self) -> List[str]:
        """Return allowed file extensions as a normalized list of strings."""
        return [
            ext.strip().lower()
            for ext in self.ALLOWED_EXTENSIONS.split(",")
            if ext.strip()
        ]

    @property
    def max_upload_size_bytes(self) -> int:
        """Return the maximum allowed upload size in bytes."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached application settings instance.

    Returns:
        Settings: The singleton application configuration settings.
    """
    logger.debug("Loading application settings from environment/cache")
    return Settings()
