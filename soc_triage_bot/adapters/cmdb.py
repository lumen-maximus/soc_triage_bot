"""CMDB adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict, Optional

from ..models import EnrichmentResult, EnrichmentStatus, Signal
from .base import BaseAdapter


class CMDBAdapter(BaseAdapter):
    """Configuration Management Database adapter."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize CMDB adapter with configuration.
        
        Args:
            config: Configuration dict with keys:
                - enabled: bool
                - provider: str (mock, servicenow, device42, etc.)
                - api_url: str
                - username: str
                - password: str
                - api_key: str
                - timeout: int
                - verify_ssl: bool
                - asset_table: str
                - max_results: int
        """
        super().__init__(config)
        self.name = "cmdb"
        
        # Store commonly used config values
        self.enabled = self.config.get("enabled", False)
        self.provider = self.config.get("provider", "mock")
        self.api_url = self.config.get("api_url")
        self.username = self.config.get("username")
        self.password = self.config.get("password")
        self.api_key = self.config.get("api_key")
        self.timeout = self.config.get("timeout", 30)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.asset_table = self.config.get("asset_table", "cmdb_ci")
        self.max_results = self.config.get("max_results", 100)

    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with CMDB/asset data.

        This is a generic implementation. In production, this would
        connect to CMDB systems (ServiceNow, etc.)

        For SOAR signals, augments fresh queries with baseline data.

        Args:
            signal: The signal to enrich

        Returns:
            EnrichmentResult with CMDB/asset context (merged with SOAR baseline)
        """
        start_time = datetime.utcnow()

        try:
            # Extract SOAR baseline if available
            from ..services.case_artifact_harvester import CaseArtifactHarvester

            soar_cmdb = CaseArtifactHarvester.extract_baseline_enrichments(signal).get(
                "cmdb", {}
            )

            # Mock enrichment - in production, query CMDB for:
            # - Asset details
            # - Business criticality
            # - Owner information
            # - Compliance requirements

            enrichment_data: Dict[str, Any] = {"assets_found": 0}

            # Check hostnames
            if "hostname" in signal.entities:
                enrichment_data["host_assets"] = {}
                for hostname in signal.entities["hostname"]:
                    enrichment_data["host_assets"][hostname] = {
                        "asset_id": f"asset-{hash(hostname) % 10000}",
                        "owner": "IT Department",
                        "location": "Building A, Floor 3",
                        "business_criticality": "medium",
                        "compliance_scope": ["SOC2", "PCI-DSS"],
                        "business_function": "Development",
                        "environment": "production",
                        "cost_center": "ENG-001",
                    }
                    enrichment_data["assets_found"] += 1

            # Check users
            if "user" in signal.entities:
                enrichment_data["user_assets"] = {}
                for user in signal.entities["user"]:
                    enrichment_data["user_assets"][user] = {
                        "employee_id": f"emp-{hash(user) % 10000}",
                        "department": "Engineering",
                        "title": "Software Engineer",
                        "manager": "Jane Doe",
                        "privileged_access": False,
                        "clearance_level": "standard",
                    }
                    enrichment_data["assets_found"] += 1

            # Check applications
            if "application" in signal.entities:
                enrichment_data["app_assets"] = {}
                for app in signal.entities["application"]:
                    enrichment_data["app_assets"][app] = {
                        "app_id": f"app-{hash(app) % 10000}",
                        "owner_team": "Product Team",
                        "criticality": "high",
                        "data_classification": "confidential",
                        "public_facing": True,
                    }
                    enrichment_data["assets_found"] += 1

            # Augment with SOAR context if available
            if soar_cmdb:
                enrichment_data["soar_context"] = {
                    "had_previous_asset_data": True,
                    "previous_owner": soar_cmdb.get("soar_owner"),
                    "previous_criticality": soar_cmdb.get("soar_criticality"),
                    "soar_business_unit": soar_cmdb.get("soar_business_unit"),
                    "soar_department": soar_cmdb.get("soar_department"),
                    "soar_os": soar_cmdb.get("soar_os"),
                    "soar_last_updated": soar_cmdb.get("soar_last_updated"),
                }

            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

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
