"""EDR adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict, Optional

from ..models import EnrichmentResult, EnrichmentStatus, Signal
from .base import BaseAdapter


class EDRAdapter(BaseAdapter):
    """Generic EDR adapter for endpoint context."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize EDR adapter with configuration.

        Args:
            config: Configuration dict with keys:
                - enabled: bool
                - provider: str (mock, crowdstrike, carbonblack, etc.)
                - api_url: str
                - client_id: str
                - client_secret: str
                - api_key: str
                - timeout: int
                - verify_ssl: bool
                - tenant_id: str
                - max_hosts: int
                - lookback_hours: int
        """
        super().__init__(config)
        self.name = "edr"

        # Store commonly used config values
        self.enabled = self.config.get("enabled", False)
        self.provider = self.config.get("provider", "mock")
        self.api_url = self.config.get("api_url")
        self.client_id = self.config.get("client_id")
        self.client_secret = self.config.get("client_secret")
        self.api_key = self.config.get("api_key")
        self.timeout = self.config.get("timeout", 30)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.tenant_id = self.config.get("tenant_id")
        self.max_hosts = self.config.get("max_hosts", 100)
        self.lookback_hours = self.config.get("lookback_hours", 24)

    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with EDR data.

        This is a generic implementation. In production, this would
        connect to specific EDR systems (CrowdStrike, Carbon Black, etc.)

        Args:
            signal: The signal to enrich

        Returns:
            EnrichmentResult with EDR context
        """
        start_time = datetime.utcnow()

        try:
            # Extract SOAR baseline if available
            from ..services.case_artifact_harvester import CaseArtifactHarvester

            soar_edr = CaseArtifactHarvester.extract_baseline_enrichments(signal).get(
                "edr", {}
            )

            # Mock enrichment - in production, query EDR for:
            # - Process tree
            # - Network connections
            # - File modifications
            # - Host containment status

            enrichment_data: Dict[str, Any] = {
                "host_online": True,
                "containment_status": "not_contained",
                "agent_version": "7.2.1",
                "last_seen": datetime.utcnow().isoformat(),
            }

            # Add process information if available
            if "process" in signal.entities:
                enrichment_data["process_info"] = {
                    "parent_process": "explorer.exe",
                    "command_line": signal.raw_data.get("command_line", ""),
                    "child_processes": [],
                    "network_connections": [],
                    "file_modifications": [],
                }

            # Add host information
            if "hostname" in signal.entities:
                enrichment_data["host_info"] = {
                    "os": "Windows 10 Enterprise",
                    "criticality": "medium",
                    "patch_level": "2024-11",
                    "installed_software": [],
                }

            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Merge SOAR baseline with fresh data
            if soar_edr:
                enrichment_data["soar_baseline"] = soar_edr

            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.SUCCESS,
                data=enrichment_data,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.FAILED,
                error=str(e),
                duration_ms=duration_ms,
            )
