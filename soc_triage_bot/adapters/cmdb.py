"""CMDB adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict
from .base import BaseAdapter
from ..models import Signal, EnrichmentResult, EnrichmentStatus


class CMDBAdapter(BaseAdapter):
    """Configuration Management Database adapter."""
    
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
            from ..services.soar_extractor import SOARDataExtractor
            soar_baseline = SOARDataExtractor.extract_baseline_enrichments(signal)
            soar_cmdb = soar_baseline.get("cmdb", {})
            
            # Mock enrichment - in production, query CMDB for:
            # - Asset details
            # - Business criticality
            # - Owner information
            # - Compliance requirements
            
            enrichment_data: Dict[str, Any] = {
                "assets_found": 0
            }
            
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
                        "cost_center": "ENG-001"
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
                        "clearance_level": "standard"
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
                        "public_facing": True
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
                    "soar_last_updated": soar_cmdb.get("soar_last_updated")
                }
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.SUCCESS,
                data=enrichment_data,
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.FAILED,
                error=str(e),
                duration_ms=duration_ms
            )
