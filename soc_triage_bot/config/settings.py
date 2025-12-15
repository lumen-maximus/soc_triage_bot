"""Application settings and configuration.

Loads configuration from environment variables with sensible defaults.
Follows singleton pattern for consistent settings across the application.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AISettings:
    """AI/LLM provider settings."""

    enabled: bool = False
    provider: str = "mock"  # mock, openai, anthropic, ollama
    model: str = "gpt-4o"
    api_key_env: str = "OPENAI_API_KEY"  # Env var name containing API key
    endpoint: Optional[str] = None  # Custom endpoint (for Ollama, Azure, etc.)
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout_seconds: int = 30
    cache_enabled: bool = False  # SQLite cache (placeholder for future)
    prompts_version: str = "1.0.0"


@dataclass
class DatabaseSettings:
    """Database settings for caching and persistence."""

    cache_enabled: bool = False
    cache_path: str = "soc_triage_bot/data/cache.db"
    cache_ttl_hours: int = 24


@dataclass
class LoggingSettings:
    """Logging configuration."""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    json_logs: bool = False


@dataclass
class AppSettings:
    """Main application settings container."""

    ai: AISettings = field(default_factory=AISettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)

    # Application paths
    config_dir: Path = field(default_factory=lambda: Path(__file__).parent)
    prompts_dir: Path = field(default_factory=lambda: Path(__file__).parent / "prompts")

    # Feature flags
    forecast_enabled: bool = True
    similarity_enabled: bool = True
    case_harvesting_enabled: bool = True


class SettingsLoader:
    """Singleton loader for application settings.

    Loads settings from environment variables with fallback to defaults.
    """

    _instance: Optional["SettingsLoader"] = None
    _settings: Optional[AppSettings] = None

    def __new__(cls) -> "SettingsLoader":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, force_reload: bool = False) -> AppSettings:
        """Load settings from environment.

        Args:
            force_reload: Force reload even if already loaded

        Returns:
            Loaded AppSettings instance
        """
        if self._settings is not None and not force_reload:
            return self._settings

        # Load AI settings from environment
        ai_settings = AISettings(
            enabled=os.environ.get("AI_ENABLED", "false").lower() == "true",
            provider=os.environ.get("AI_PROVIDER", "mock"),
            model=os.environ.get("AI_MODEL", "gpt-4o"),
            api_key_env=os.environ.get("AI_API_KEY_ENV", "OPENAI_API_KEY"),
            endpoint=os.environ.get("AI_ENDPOINT") or None,
            temperature=float(os.environ.get("AI_TEMPERATURE", "0.7")),
            max_tokens=int(os.environ.get("AI_MAX_TOKENS", "2048")),
            timeout_seconds=int(os.environ.get("AI_TIMEOUT", "30")),
            cache_enabled=os.environ.get("AI_CACHE_ENABLED", "false").lower() == "true",
            prompts_version=os.environ.get("AI_PROMPTS_VERSION", "1.0.0"),
        )

        # Load database settings from environment
        db_settings = DatabaseSettings(
            cache_enabled=os.environ.get("CACHE_ENABLED", "false").lower() == "true",
            cache_path=os.environ.get("CACHE_PATH", "soc_triage_bot/data/cache.db"),
            cache_ttl_hours=int(os.environ.get("CACHE_TTL_HOURS", "24")),
        )

        # Load logging settings from environment
        log_settings = LoggingSettings(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            format=os.environ.get(
                "LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            ),
            json_logs=os.environ.get("LOG_JSON", "false").lower() == "true",
        )

        # Create paths
        config_dir = Path(__file__).parent
        prompts_dir = config_dir / "prompts"

        # Feature flags from environment
        forecast_enabled = os.environ.get("FORECAST_ENABLED", "true").lower() == "true"
        similarity_enabled = (
            os.environ.get("SIMILARITY_ENABLED", "true").lower() == "true"
        )
        case_harvesting_enabled = (
            os.environ.get("CASE_HARVESTING_ENABLED", "true").lower() == "true"
        )

        self._settings = AppSettings(
            ai=ai_settings,
            database=db_settings,
            logging=log_settings,
            config_dir=config_dir,
            prompts_dir=prompts_dir,
            forecast_enabled=forecast_enabled,
            similarity_enabled=similarity_enabled,
            case_harvesting_enabled=case_harvesting_enabled,
        )

        return self._settings


def get_settings(force_reload: bool = False) -> AppSettings:
    """Get application settings.

    Convenience function for accessing settings.

    Args:
        force_reload: Force reload from environment

    Returns:
        AppSettings instance
    """
    return SettingsLoader().load(force_reload=force_reload)


def get_ai_provider_config():
    """Get AI provider configuration for adapter initialization.

    Returns:
        AIProviderConfig compatible dict
    """
    settings = get_settings()
    from ..adapters.ai_provider import AIProviderConfig

    return AIProviderConfig(
        provider_name=settings.ai.provider,
        model=settings.ai.model,
        api_key_env=settings.ai.api_key_env,
        endpoint=settings.ai.endpoint,
        temperature=settings.ai.temperature,
        max_tokens=settings.ai.max_tokens,
        timeout_seconds=settings.ai.timeout_seconds,
    )
