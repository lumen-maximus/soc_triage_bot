"""Dependency Injection Container for SOC Triage Bot.

Centralized service and adapter management to avoid:
- Repeated adapter instantiation across CLI/API/tests
- Configuration drift between entry points
- Tight coupling and difficult testing

Usage:
    # In CLI
    container = ServiceContainer()
    await container.startup()
    result = await container.triage_service.triage_extended(signal)
    await container.shutdown()

    # In API
    container = ServiceContainer()

    @app.on_event("startup")
    async def startup():
        await container.startup()

    @app.post("/triage")
    async def triage(signal: Signal):
        return await container.triage_service.triage_extended(signal)

    # In Tests
    container = ServiceContainer()
    container._siem_adapter = MockSIEMAdapter()
    service = container.triage_service  # Uses mock
"""

import os
from typing import List, Optional

from .adapters import (
    BaseAdapter,
    CMDBAdapter,
    EDRAdapter,
    HistoricalQueryCapable,
    MockHistoricalAdapter,
    SIEMAdapter,
    ThreatIntelAdapter,
    VulnerabilityAdapter,
)
from .config.settings import AppSettings, get_settings
from .services import (
    ActionProposalService,
    AIService,
    CaseContextLinkingService,
    ClassificationService,
    EnrichmentService,
    ForecastingService,
    ReportService,
    TriageService,
)
from .services.canonicalize import CanonicalizeService
from .services.case_artifact_harvester import CaseArtifactHarvester
from .services.case_bootstrap import CaseBootstrapService
from .services.governance_gate import GovernanceGate
from .services.historical_data import HistoricalDataService
from .services.runbook_registry import RunbookRegistry
from .services.signal_router import SignalRouter
from .services.source_hydrator import SourceHydrator


class ServiceContainer:
    """Centralized dependency injection container.

    Provides singleton instances of all adapters and services with:
    - Lazy initialization (created on first access)
    - Shared configuration
    - Lifecycle management (startup/shutdown)
    - Easy test mocking (override private attributes)

    Example:
        container = ServiceContainer()
        await container.startup()

        # All services use same adapter instances
        result = await container.triage_service.triage_extended(signal)

        await container.shutdown()
    """

    def __init__(
        self,
        config: Optional[AppSettings] = None,
        enable_ckg: bool = True,
        demo_mode: bool = False,
    ):
        """Initialize container with configuration.

        Args:
            config: Application settings (defaults to get_settings())
            enable_ckg: Enable Case Knowledge Graph features
            demo_mode: Use mock adapters for demo/testing
        """
        self.config = config or get_settings()
        self.enable_ckg = enable_ckg
        self.demo_mode = demo_mode

        # Adapter singletons (lazy-initialized)
        self._siem_adapter: Optional[SIEMAdapter] = None
        self._edr_adapter: Optional[EDRAdapter] = None
        self._ti_adapter: Optional[ThreatIntelAdapter] = None
        self._vuln_adapter: Optional[VulnerabilityAdapter] = None
        self._cmdb_adapter: Optional[CMDBAdapter] = None
        self._soar_adapter: Optional[BaseAdapter] = None

        # Enrichment adapter list cache
        self._enrichment_adapters: Optional[List[BaseAdapter]] = None

        # Service singletons (lazy-initialized)
        self._enrichment_service: Optional[EnrichmentService] = None
        self._classification_service: Optional[ClassificationService] = None
        self._forecasting_service: Optional[ForecastingService] = None
        self._action_proposal_service: Optional[ActionProposalService] = None
        self._report_service: Optional[ReportService] = None
        self._ai_service: Optional[AIService] = None
        self._historical_data_service: Optional[HistoricalDataService] = None

        # CKG services
        self._case_bootstrap_service: Optional[CaseBootstrapService] = None
        self._canonicalize_service: Optional[CanonicalizeService] = None
        self._source_hydrator: Optional[SourceHydrator] = None
        self._governance_gate: Optional[GovernanceGate] = None
        self._runbook_registry: Optional[RunbookRegistry] = None
        self._case_context_linking: Optional[CaseContextLinkingService] = None
        self._case_artifact_harvester: Optional[CaseArtifactHarvester] = None

        # Utility services
        self._signal_router: Optional[SignalRouter] = None

        # Main orchestrator
        self._triage_service: Optional[TriageService] = None

    # =========================================================================
    # ADAPTERS
    # =========================================================================

    @property
    def siem_adapter(self) -> SIEMAdapter:
        """Get or create SIEM adapter singleton."""
        if self._siem_adapter is None:
            settings = get_settings()
            config = {
                "enabled": settings.siem.enabled,
                "provider": settings.siem.provider,
                "api_url": settings.siem.api_url,
                "api_key": os.getenv(settings.siem.api_key_env),
                "username": os.getenv(settings.siem.username_env),
                "password": os.getenv(settings.siem.password_env),
                "timeout": settings.siem.timeout_seconds,
                "verify_ssl": settings.siem.verify_ssl,
                "default_index": settings.siem.default_index,
                "max_results": settings.siem.max_results,
                "search_timeout": settings.siem.search_timeout_seconds,
            }
            self._siem_adapter = SIEMAdapter(config)
        return self._siem_adapter

    @property
    def edr_adapter(self) -> EDRAdapter:
        """Get or create EDR adapter singleton."""
        if self._edr_adapter is None:
            settings = get_settings()
            config = {
                "enabled": settings.edr.enabled,
                "provider": settings.edr.provider,
                "api_url": settings.edr.api_url,
                "client_id": os.getenv(settings.edr.client_id_env),
                "client_secret": os.getenv(settings.edr.client_secret_env),
                "api_key": os.getenv(settings.edr.api_key_env),
                "timeout": settings.edr.timeout_seconds,
                "verify_ssl": settings.edr.verify_ssl,
                "tenant_id": settings.edr.tenant_id,
                "max_hosts": settings.edr.max_hosts,
                "lookback_hours": settings.edr.lookback_hours,
            }
            self._edr_adapter = EDRAdapter(config)
        return self._edr_adapter

    @property
    def ti_adapter(self) -> ThreatIntelAdapter:
        """Get or create Threat Intel adapter singleton."""
        if self._ti_adapter is None:
            settings = get_settings()
            config = {
                "enabled": settings.threat_intel.enabled,
                "virustotal_enabled": settings.threat_intel.virustotal_enabled,
                "virustotal_api_key": os.getenv(
                    settings.threat_intel.virustotal_api_key_env
                ),
                "alienvault_enabled": settings.threat_intel.alienvault_enabled,
                "alienvault_api_key": os.getenv(
                    settings.threat_intel.alienvault_api_key_env
                ),
                "abuseipdb_enabled": settings.threat_intel.abuseipdb_enabled,
                "abuseipdb_api_key": os.getenv(
                    settings.threat_intel.abuseipdb_api_key_env
                ),
                "custom_feed_url": settings.threat_intel.custom_feed_url,
                "custom_feed_api_key": os.getenv(
                    settings.threat_intel.custom_feed_api_key_env
                ),
                "timeout": settings.threat_intel.timeout_seconds,
                "cache_ttl_hours": settings.threat_intel.cache_ttl_hours,
                "max_indicators": settings.threat_intel.max_indicators_per_query,
            }
            self._ti_adapter = ThreatIntelAdapter(config)
        return self._ti_adapter

    @property
    def vuln_adapter(self) -> VulnerabilityAdapter:
        """Get or create Vulnerability adapter singleton."""
        if self._vuln_adapter is None:
            settings = get_settings()
            config = {
                "enabled": settings.vulnerability.enabled,
                "provider": settings.vulnerability.provider,
                "nvd_api_key": os.getenv(settings.vulnerability.nvd_api_key_env),
                "nvd_enabled": settings.vulnerability.nvd_enabled,
                "tenable_access_key": os.getenv(
                    settings.vulnerability.tenable_access_key_env
                ),
                "tenable_secret_key": os.getenv(
                    settings.vulnerability.tenable_secret_key_env
                ),
                "tenable_enabled": settings.vulnerability.tenable_enabled,
                "api_url": settings.vulnerability.api_url,
                "timeout": settings.vulnerability.timeout_seconds,
                "cache_ttl_hours": settings.vulnerability.cache_ttl_hours,
            }
            self._vuln_adapter = VulnerabilityAdapter(config)
        return self._vuln_adapter

    @property
    def cmdb_adapter(self) -> CMDBAdapter:
        """Get or create CMDB adapter singleton."""
        if self._cmdb_adapter is None:
            settings = get_settings()
            config = {
                "enabled": settings.cmdb.enabled,
                "provider": settings.cmdb.provider,
                "api_url": settings.cmdb.api_url,
                "username": os.getenv(settings.cmdb.username_env),
                "password": os.getenv(settings.cmdb.password_env),
                "api_key": os.getenv(settings.cmdb.api_key_env),
                "timeout": settings.cmdb.timeout_seconds,
                "verify_ssl": settings.cmdb.verify_ssl,
                "asset_table": settings.cmdb.asset_table,
                "max_results": settings.cmdb.max_results,
            }
            self._cmdb_adapter = CMDBAdapter(config)
        return self._cmdb_adapter

    @property
    def soar_adapter(self) -> Optional[BaseAdapter]:
        """Get or create SOAR adapter singleton (if configured)."""
        if self._soar_adapter is None:
            settings = get_settings()
            if settings.soar.enabled:
                from .adapters.soar import SOARAdapter

                config = {
                    "enabled": settings.soar.enabled,
                    "provider": settings.soar.provider,
                    "api_url": settings.soar.api_url,
                    "api_token": os.getenv(settings.soar.api_token_env),
                    "username": os.getenv(settings.soar.username_env),
                    "password": os.getenv(settings.soar.password_env),
                    "timeout": settings.soar.timeout_seconds,
                    "verify_ssl": settings.soar.verify_ssl,
                    "container_prefix": settings.soar.container_prefix,
                    "auto_create_cases": settings.soar.auto_create_cases,
                }
                # Pass api_url and api_token directly for backward compatibility
                self._soar_adapter = SOARAdapter(
                    api_url=settings.soar.api_url,
                    api_token=os.getenv(settings.soar.api_token_env),
                )
                self._soar_adapter.config = config
        return self._soar_adapter

    @property
    def enrichment_adapters(self) -> List[BaseAdapter]:
        """Get list of all enrichment adapters."""
        if self._enrichment_adapters is None:
            self._enrichment_adapters = [
                self.siem_adapter,
                self.edr_adapter,
                self.ti_adapter,
                self.vuln_adapter,
                self.cmdb_adapter,
            ]
        return self._enrichment_adapters

    @property
    def historical_capable_adapters(self) -> List[HistoricalQueryCapable]:
        """Get adapters that support historical queries."""
        capable = []
        for adapter in self.enrichment_adapters:
            if hasattr(adapter, "supports_historical_query") and callable(
                getattr(adapter, "supports_historical_query")
            ):
                try:
                    # Type narrowing: adapter has supports_historical_query at runtime
                    if adapter.supports_historical_query():  # type: ignore[attr-defined]
                        capable.append(adapter)  # type: ignore[arg-type]
                except Exception:
                    pass
        return capable

    # =========================================================================
    # CORE SERVICES
    # =========================================================================

    @property
    def enrichment_service(self) -> EnrichmentService:
        """Get or create enrichment service singleton."""
        if self._enrichment_service is None:
            self._enrichment_service = EnrichmentService(self.enrichment_adapters)
        return self._enrichment_service

    @property
    def classification_service(self) -> ClassificationService:
        """Get or create classification service singleton."""
        if self._classification_service is None:
            self._classification_service = ClassificationService()
        return self._classification_service

    @property
    def forecasting_service(self) -> ForecastingService:
        """Get or create forecasting service singleton."""
        if self._forecasting_service is None:
            self._forecasting_service = ForecastingService()
        return self._forecasting_service

    @property
    def action_proposal_service(self) -> ActionProposalService:
        """Get or create action proposal service singleton."""
        if self._action_proposal_service is None:
            self._action_proposal_service = ActionProposalService(
                runbook_registry=self.runbook_registry,
                case_artifact_harvester=self.case_artifact_harvester,
            )
        return self._action_proposal_service

    @property
    def report_service(self) -> ReportService:
        """Get or create report service singleton."""
        if self._report_service is None:
            self._report_service = ReportService()
        return self._report_service

    @property
    def ai_service(self) -> Optional[AIService]:
        """Get or create AI service singleton (if enabled in config)."""
        if self._ai_service is None and self.config.ai and self.config.ai.enabled:
            self._ai_service = AIService.from_settings(self.config.ai)
        return self._ai_service

    @property
    def historical_data_service(self) -> Optional[HistoricalDataService]:
        """Get or create historical data service singleton."""
        if self._historical_data_service is None:
            if self.demo_mode:
                # Demo mode: use mock adapter
                self._historical_data_service = HistoricalDataService(
                    [MockHistoricalAdapter()]
                )
            else:
                # Live mode: use capable adapters
                capable = self.historical_capable_adapters
                if capable:
                    self._historical_data_service = HistoricalDataService(capable)
        return self._historical_data_service

    # =========================================================================
    # CKG SERVICES
    # =========================================================================

    @property
    def case_bootstrap_service(self) -> CaseBootstrapService:
        """Get or create case bootstrap service singleton."""
        if self._case_bootstrap_service is None:
            self._case_bootstrap_service = CaseBootstrapService()
        return self._case_bootstrap_service

    @property
    def canonicalize_service(self) -> CanonicalizeService:
        """Get or create canonicalize service singleton."""
        if self._canonicalize_service is None:
            self._canonicalize_service = CanonicalizeService()
        return self._canonicalize_service

    @property
    def source_hydrator(self) -> SourceHydrator:
        """Get or create source hydrator singleton."""
        if self._source_hydrator is None:
            self._source_hydrator = SourceHydrator(
                siem_adapter=self.siem_adapter,
                soar_adapter=self.soar_adapter,
            )
        return self._source_hydrator

    @property
    def governance_gate(self) -> GovernanceGate:
        """Get or create governance gate singleton."""
        if self._governance_gate is None:
            self._governance_gate = GovernanceGate()
        return self._governance_gate

    @property
    def runbook_registry(self) -> RunbookRegistry:
        """Get or create runbook registry singleton."""
        if self._runbook_registry is None:
            self._runbook_registry = RunbookRegistry(soar_adapter=self.soar_adapter)
        return self._runbook_registry

    @property
    def case_context_linking(self) -> CaseContextLinkingService:
        """Get or create case context linking service singleton."""
        if self._case_context_linking is None:
            self._case_context_linking = CaseContextLinkingService(
                soar_adapter=self.soar_adapter
            )
        return self._case_context_linking

    @property
    def case_artifact_harvester(self) -> CaseArtifactHarvester:
        """Get or create case artifact harvester singleton."""
        if self._case_artifact_harvester is None:
            self._case_artifact_harvester = CaseArtifactHarvester(
                soar_adapter=self.soar_adapter,
                runbook_registry=self.runbook_registry,
            )
        return self._case_artifact_harvester

    # =========================================================================
    # UTILITY SERVICES
    # =========================================================================

    @property
    def signal_router(self) -> SignalRouter:
        """Get or create signal router singleton."""
        if self._signal_router is None:
            self._signal_router = SignalRouter()
        return self._signal_router

    # =========================================================================
    # MAIN ORCHESTRATOR
    # =========================================================================

    @property
    def triage_service(self) -> TriageService:
        """Get or create triage service singleton with all dependencies."""
        if self._triage_service is None:
            self._triage_service = TriageService(
                enrichment_service=self.enrichment_service,
                forecasting_service=self.forecasting_service,
                classification_service=self.classification_service,
                action_proposal_service=self.action_proposal_service,
                report_service=self.report_service,
                ai_service=self.ai_service,
                historical_data_service=self.historical_data_service,
                # CKG services
                case_bootstrap_service=self.case_bootstrap_service,
                canonicalize_service=self.canonicalize_service,
                source_hydrator=self.source_hydrator,
                governance_gate=self.governance_gate,
                runbook_registry=self.runbook_registry,
                case_context_linking=self.case_context_linking,
                enable_ckg=self.enable_ckg,
            )
        return self._triage_service

    # =========================================================================
    # LIFECYCLE MANAGEMENT
    # =========================================================================

    async def startup(self):
        """Initialize all adapters and establish connections.

        Call this at application startup (CLI/API) to:
        - Establish database connections
        - Initialize connection pools
        - Validate configurations
        - Warm up caches
        """
        # Initialize all adapters to trigger connection setup
        for adapter in self.enrichment_adapters:
            if hasattr(adapter, "connect") and callable(adapter.connect):  # type: ignore[attr-defined]
                try:
                    await adapter.connect()  # type: ignore[attr-defined]
                except Exception as e:
                    # Log but don't fail - graceful degradation
                    print(f"Warning: Failed to connect {adapter.name}: {e}")

        # Initialize SOAR adapter if available
        if self.soar_adapter and hasattr(self.soar_adapter, "connect"):
            try:
                await self.soar_adapter.connect()  # type: ignore[attr-defined]
            except Exception as e:
                print(f"Warning: Failed to connect SOAR adapter: {e}")

        # Trigger AI service initialization if enabled
        if self.ai_service:
            # AI service validates API keys on first use
            pass

    async def shutdown(self):
        """Close all adapter connections and cleanup resources.

        Call this at application shutdown to:
        - Close database connections
        - Release connection pools
        - Cleanup temporary files
        """
        # Close all enrichment adapter connections
        for adapter in self.enrichment_adapters:
            if hasattr(adapter, "close") and callable(adapter.close):  # type: ignore[attr-defined]
                try:
                    await adapter.close()  # type: ignore[attr-defined]
                except Exception as e:
                    print(f"Warning: Failed to close {adapter.name}: {e}")

        # Close SOAR adapter if available
        if self.soar_adapter and hasattr(self.soar_adapter, "close"):
            try:
                await self.soar_adapter.close()  # type: ignore[attr-defined]
            except Exception as e:
                print(f"Warning: Failed to close SOAR adapter: {e}")

    async def health_check(self) -> dict:
        """Check health of all adapters and services.

        Returns:
            Dictionary with health status of each component
        """
        health = {}

        # Check enrichment adapters
        adapter_health = await self.enrichment_service.health_check()
        health["adapters"] = adapter_health

        # Check AI service
        if self.ai_service:
            health["ai_service"] = {"status": "configured", "enabled": True}
        else:
            health["ai_service"] = {"status": "disabled", "enabled": False}

        # Check historical data service
        if self.historical_data_service:
            capable_count = len(self.historical_capable_adapters)
            health["historical_data"] = {
                "status": "available",
                "capable_adapters": capable_count,
            }
        else:
            health["historical_data"] = {"status": "unavailable"}

        # Overall status
        all_healthy = all(
            status for status in adapter_health.values() if isinstance(status, bool)
        )
        health["overall"] = "healthy" if all_healthy else "degraded"

        return health
