"""EDR adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict
from .base import BaseAdapter
from ..models import Signal, EnrichmentResult, EnrichmentStatus


class EDRAdapter(BaseAdapter):
    """Generic EDR adapter for endpoint context."""
    
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
            # Mock enrichment - in production, query EDR for:
            # - Process tree
            # - Network connections
            # - File modifications
            # - Host containment status
            
            enrichment_data: Dict[str, Any] = {
                "host_online": True,
                "containment_status": "not_contained",
                "agent_version": "7.2.1",
                "last_seen": datetime.utcnow().isoformat()
            }
            
            # Add process information if available
            if "process" in signal.entities:
                enrichment_data["process_info"] = {
                    "parent_process": "explorer.exe",
                    "command_line": signal.raw_data.get("command_line", ""),
                    "child_processes": [],
                    "network_connections": [],
                    "file_modifications": []
                }
            
            # Add host information
            if "hostname" in signal.entities:
                enrichment_data["host_info"] = {
                    "os": "Windows 10 Enterprise",
                    "criticality": "medium",
                    "patch_level": "2024-11",
                    "installed_software": []
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
