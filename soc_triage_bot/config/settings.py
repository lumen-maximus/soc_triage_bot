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
class SIEMSettings:
    """SIEM adapter settings (Splunk, QRadar, Sentinel, etc.)."""

    enabled: bool = False
    provider: str = "mock"  # mock, splunk, qradar, sentinel, elasticsearch
    api_url: Optional[str] = None
    api_key_env: str = "SIEM_API_KEY"  # Env var name for API key
    username_env: str = "SIEM_USERNAME"  # For basic auth
    password_env: str = "SIEM_PASSWORD"  # For basic auth
    timeout_seconds: int = 30
    verify_ssl: bool = True
    # Query configuration
    default_index: Optional[str] = None  # Default index/source
    max_results: int = 1000
    search_timeout_seconds: int = 60


@dataclass
class EDRSettings:
    """EDR adapter settings (CrowdStrike, Carbon Black, SentinelOne, etc.)."""

    enabled: bool = False
    provider: str = "mock"  # mock, crowdstrike, carbonblack, sentinelone
    api_url: Optional[str] = None
    client_id_env: str = "EDR_CLIENT_ID"
    client_secret_env: str = "EDR_CLIENT_SECRET"
    api_key_env: str = "EDR_API_KEY"  # Alternative to client_id/secret
    timeout_seconds: int = 30
    verify_ssl: bool = True
    # Tenant configuration
    tenant_id: Optional[str] = None  # For multi-tenant EDRs
    # Query limits
    max_hosts: int = 100
    lookback_hours: int = 24


@dataclass
class ThreatIntelSettings:
    """Threat Intelligence adapter settings (multi-feed support)."""

    enabled: bool = False
    # Primary feeds
    virustotal_enabled: bool = False
    virustotal_api_key_env: str = "VIRUSTOTAL_API_KEY"
    alienvault_enabled: bool = False
    alienvault_api_key_env: str = "ALIENVAULT_API_KEY"
    abuseipdb_enabled: bool = False
    abuseipdb_api_key_env: str = "ABUSEIPDB_API_KEY"
    # Generic feed support
    custom_feed_url: Optional[str] = None
    custom_feed_api_key_env: str = "TI_CUSTOM_API_KEY"
    # Configuration
    timeout_seconds: int = 30
    cache_ttl_hours: int = 24  # Cache TI lookups
    max_indicators_per_query: int = 100


@dataclass
class CMDBSettings:
    """CMDB adapter settings (ServiceNow, Device42, etc.)."""

    enabled: bool = False
    provider: str = "mock"  # mock, servicenow, device42, custom
    api_url: Optional[str] = None
    username_env: str = "CMDB_USERNAME"
    password_env: str = "CMDB_PASSWORD"
    api_key_env: str = "CMDB_API_KEY"  # Alternative auth
    timeout_seconds: int = 30
    verify_ssl: bool = True
    # Configuration
    asset_table: str = "cmdb_ci"  # ServiceNow table name
    max_results: int = 100


@dataclass
class VulnerabilitySettings:
    """Vulnerability adapter settings (NVD, Tenable, Qualys, etc.)."""

    enabled: bool = False
    provider: str = "mock"  # mock, nvd, tenable, qualys
    # NVD settings
    nvd_api_key_env: str = "NVD_API_KEY"
    nvd_enabled: bool = True
    # Tenable settings
    tenable_access_key_env: str = "TENABLE_ACCESS_KEY"
    tenable_secret_key_env: str = "TENABLE_SECRET_KEY"
    tenable_enabled: bool = False
    # Generic settings
    api_url: Optional[str] = None
    timeout_seconds: int = 30
    cache_ttl_hours: int = 168  # 7 days - CVE data changes slowly


@dataclass
class SOARSettings:
    """SOAR adapter settings (Phantom, XSOAR, Swimlane, etc.)."""

    enabled: bool = False
    provider: str = "mock"  # mock, phantom, xsoar, swimlane
    api_url: Optional[str] = None
    api_token_env: str = "SOAR_API_TOKEN"
    username_env: str = "SOAR_USERNAME"  # For basic auth
    password_env: str = "SOAR_PASSWORD"  # For basic auth
    timeout_seconds: int = 30
    verify_ssl: bool = True
    # Configuration
    container_prefix: str = "SOAR"  # Prefix for container IDs
    auto_create_cases: bool = False  # Auto-create cases for signals


@dataclass
class ActionProposalSettings:
    """Action proposal service configuration.

    Controls limits, thresholds, and feature flags for action proposals.
    """

    # Proposal limits
    top_proposals_min: int = 3  # Minimum actions to show in top recommendations
    top_proposals_max: int = 6  # Maximum actions in top recommendations
    full_plan_max: int = 15  # Maximum actions in full plan

    # Case learning thresholds
    min_similarity_for_learning: float = 0.75  # Minimum similarity to learn from case
    max_case_age_days: int = 90  # Maximum age of cases to learn from
    require_successful_outcome: bool = True  # Only learn from successful outcomes

    # Feature flags
    enable_runbook_registry: bool = True  # Enable governed runbooks (source 1)
    enable_case_harvester: bool = True  # Enable SOAR artifact harvesting (source 2)
    enable_learned_actions: bool = True  # Enable similar case learning (source 3)
    enable_contextual_actions: bool = True  # Enable enrichment-based actions (source 4)
    enable_template_actions: bool = True  # Enable fallback templates (source 5)

    # Gating configuration
    block_containment_on_fp: bool = True  # Block isolate/block for FP
    require_approval_on_unknown: bool = (
        True  # Require approval for unknown classification
    )
    min_confidence_for_auto_containment: float = 0.5  # Below this, require approval


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

    # AI and adapter settings
    ai: AISettings = field(default_factory=AISettings)
    siem: SIEMSettings = field(default_factory=SIEMSettings)
    edr: EDRSettings = field(default_factory=EDRSettings)
    threat_intel: ThreatIntelSettings = field(default_factory=ThreatIntelSettings)
    cmdb: CMDBSettings = field(default_factory=CMDBSettings)
    vulnerability: VulnerabilitySettings = field(default_factory=VulnerabilitySettings)
    soar: SOARSettings = field(default_factory=SOARSettings)

    # Service settings
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    action_proposal: ActionProposalSettings = field(
        default_factory=ActionProposalSettings
    )

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

        # Load SIEM settings from environment
        siem_settings = SIEMSettings(
            enabled=os.environ.get("SIEM_ENABLED", "false").lower() == "true",
            provider=os.environ.get("SIEM_PROVIDER", "mock"),
            api_url=os.environ.get("SIEM_API_URL"),
            api_key_env=os.environ.get("SIEM_API_KEY_ENV", "SIEM_API_KEY"),
            username_env=os.environ.get("SIEM_USERNAME_ENV", "SIEM_USERNAME"),
            password_env=os.environ.get("SIEM_PASSWORD_ENV", "SIEM_PASSWORD"),
            timeout_seconds=int(os.environ.get("SIEM_TIMEOUT", "30")),
            verify_ssl=os.environ.get("SIEM_VERIFY_SSL", "true").lower() == "true",
            default_index=os.environ.get("SIEM_DEFAULT_INDEX"),
            max_results=int(os.environ.get("SIEM_MAX_RESULTS", "1000")),
            search_timeout_seconds=int(os.environ.get("SIEM_SEARCH_TIMEOUT", "60")),
        )

        # Load EDR settings from environment
        edr_settings = EDRSettings(
            enabled=os.environ.get("EDR_ENABLED", "false").lower() == "true",
            provider=os.environ.get("EDR_PROVIDER", "mock"),
            api_url=os.environ.get("EDR_API_URL"),
            client_id_env=os.environ.get("EDR_CLIENT_ID_ENV", "EDR_CLIENT_ID"),
            client_secret_env=os.environ.get("EDR_CLIENT_SECRET_ENV", "EDR_CLIENT_SECRET"),
            api_key_env=os.environ.get("EDR_API_KEY_ENV", "EDR_API_KEY"),
            timeout_seconds=int(os.environ.get("EDR_TIMEOUT", "30")),
            verify_ssl=os.environ.get("EDR_VERIFY_SSL", "true").lower() == "true",
            tenant_id=os.environ.get("EDR_TENANT_ID"),
            max_hosts=int(os.environ.get("EDR_MAX_HOSTS", "100")),
            lookback_hours=int(os.environ.get("EDR_LOOKBACK_HOURS", "24")),
        )

        # Load Threat Intel settings from environment
        ti_settings = ThreatIntelSettings(
            enabled=os.environ.get("TI_ENABLED", "false").lower() == "true",
            virustotal_enabled=os.environ.get("TI_VT_ENABLED", "false").lower() == "true",
            virustotal_api_key_env=os.environ.get("TI_VT_API_KEY_ENV", "VIRUSTOTAL_API_KEY"),
            alienvault_enabled=os.environ.get("TI_AV_ENABLED", "false").lower() == "true",
            alienvault_api_key_env=os.environ.get("TI_AV_API_KEY_ENV", "ALIENVAULT_API_KEY"),
            abuseipdb_enabled=os.environ.get("TI_ABUSE_ENABLED", "false").lower() == "true",
            abuseipdb_api_key_env=os.environ.get("TI_ABUSE_API_KEY_ENV", "ABUSEIPDB_API_KEY"),
            custom_feed_url=os.environ.get("TI_CUSTOM_URL"),
            custom_feed_api_key_env=os.environ.get("TI_CUSTOM_API_KEY_ENV", "TI_CUSTOM_API_KEY"),
            timeout_seconds=int(os.environ.get("TI_TIMEOUT", "30")),
            cache_ttl_hours=int(os.environ.get("TI_CACHE_TTL_HOURS", "24")),
            max_indicators_per_query=int(os.environ.get("TI_MAX_INDICATORS", "100")),
        )

        # Load CMDB settings from environment
        cmdb_settings = CMDBSettings(
            enabled=os.environ.get("CMDB_ENABLED", "false").lower() == "true",
            provider=os.environ.get("CMDB_PROVIDER", "mock"),
            api_url=os.environ.get("CMDB_API_URL"),
            username_env=os.environ.get("CMDB_USERNAME_ENV", "CMDB_USERNAME"),
            password_env=os.environ.get("CMDB_PASSWORD_ENV", "CMDB_PASSWORD"),
            api_key_env=os.environ.get("CMDB_API_KEY_ENV", "CMDB_API_KEY"),
            timeout_seconds=int(os.environ.get("CMDB_TIMEOUT", "30")),
            verify_ssl=os.environ.get("CMDB_VERIFY_SSL", "true").lower() == "true",
            asset_table=os.environ.get("CMDB_ASSET_TABLE", "cmdb_ci"),
            max_results=int(os.environ.get("CMDB_MAX_RESULTS", "100")),
        )

        # Load Vulnerability settings from environment
        vuln_settings = VulnerabilitySettings(
            enabled=os.environ.get("VULN_ENABLED", "false").lower() == "true",
            provider=os.environ.get("VULN_PROVIDER", "mock"),
            nvd_api_key_env=os.environ.get("VULN_NVD_API_KEY_ENV", "NVD_API_KEY"),
            nvd_enabled=os.environ.get("VULN_NVD_ENABLED", "true").lower() == "true",
            tenable_access_key_env=os.environ.get("VULN_TENABLE_ACCESS_ENV", "TENABLE_ACCESS_KEY"),
            tenable_secret_key_env=os.environ.get("VULN_TENABLE_SECRET_ENV", "TENABLE_SECRET_KEY"),
            tenable_enabled=os.environ.get("VULN_TENABLE_ENABLED", "false").lower() == "true",
            api_url=os.environ.get("VULN_API_URL"),
            timeout_seconds=int(os.environ.get("VULN_TIMEOUT", "30")),
            cache_ttl_hours=int(os.environ.get("VULN_CACHE_TTL_HOURS", "168")),
        )

        # Load SOAR settings from environment
        soar_settings = SOARSettings(
            enabled=os.environ.get("SOAR_ENABLED", "false").lower() == "true",
            provider=os.environ.get("SOAR_PROVIDER", "mock"),
            api_url=os.environ.get("SOAR_API_URL"),
            api_token_env=os.environ.get("SOAR_API_TOKEN_ENV", "SOAR_API_TOKEN"),
            username_env=os.environ.get("SOAR_USERNAME_ENV", "SOAR_USERNAME"),
            password_env=os.environ.get("SOAR_PASSWORD_ENV", "SOAR_PASSWORD"),
            timeout_seconds=int(os.environ.get("SOAR_TIMEOUT", "30")),
            verify_ssl=os.environ.get("SOAR_VERIFY_SSL", "true").lower() == "true",
            container_prefix=os.environ.get("SOAR_CONTAINER_PREFIX", "SOAR"),
            auto_create_cases=os.environ.get("SOAR_AUTO_CREATE", "false").lower() == "true",
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

        # Load action proposal settings from environment
        action_proposal_settings = ActionProposalSettings(
            top_proposals_min=int(os.environ.get("ACTION_TOP_MIN", "3")),
            top_proposals_max=int(os.environ.get("ACTION_TOP_MAX", "6")),
            full_plan_max=int(os.environ.get("ACTION_FULL_PLAN_MAX", "15")),
            min_similarity_for_learning=float(
                os.environ.get("ACTION_MIN_SIMILARITY", "0.75")
            ),
            max_case_age_days=int(os.environ.get("ACTION_MAX_CASE_AGE_DAYS", "90")),
            require_successful_outcome=os.environ.get(
                "ACTION_REQUIRE_SUCCESS", "true"
            ).lower()
            == "true",
            enable_runbook_registry=os.environ.get(
                "ACTION_ENABLE_RUNBOOKS", "true"
            ).lower()
            == "true",
            enable_case_harvester=os.environ.get(
                "ACTION_ENABLE_HARVESTER", "true"
            ).lower()
            == "true",
            enable_learned_actions=os.environ.get(
                "ACTION_ENABLE_LEARNED", "true"
            ).lower()
            == "true",
            enable_contextual_actions=os.environ.get(
                "ACTION_ENABLE_CONTEXTUAL", "true"
            ).lower()
            == "true",
            enable_template_actions=os.environ.get(
                "ACTION_ENABLE_TEMPLATES", "true"
            ).lower()
            == "true",
            block_containment_on_fp=os.environ.get(
                "ACTION_BLOCK_CONTAINMENT_FP", "true"
            ).lower()
            == "true",
            require_approval_on_unknown=os.environ.get(
                "ACTION_REQUIRE_APPROVAL_UNKNOWN", "true"
            ).lower()
            == "true",
            min_confidence_for_auto_containment=float(
                os.environ.get("ACTION_MIN_CONFIDENCE_AUTO", "0.5")
            ),
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
            siem=siem_settings,
            edr=edr_settings,
            threat_intel=ti_settings,
            cmdb=cmdb_settings,
            vulnerability=vuln_settings,
            soar=soar_settings,
            database=db_settings,
            logging=log_settings,
            action_proposal=action_proposal_settings,
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
