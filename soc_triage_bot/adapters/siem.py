"""SIEM adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict
from .base import BaseAdapter
from ..models import Signal, EnrichmentResult, EnrichmentStatus


class SIEMAdapter(BaseAdapter):
    """Generic SIEM adapter for additional context."""
    
    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with SIEM data.
        
        This is a generic implementation. In production, this would
        connect to specific SIEM systems (Splunk, QRadar, etc.)
        
        Args:
            signal: The signal to enrich
            
        Returns:
            EnrichmentResult with SIEM context
        """
        start_time = datetime.utcnow()
        
        try:
            # Mock enrichment - in production, query SIEM for:
            # - Historical alerts for same entities
            # - Related events in time window
            # - Alert frequency for this rule
            
            enrichment_data: Dict[str, Any] = {
                "alert_frequency_24h": 5,
                "related_alerts": [],
                "historical_fp_rate": 0.15,
                "rule_first_seen": "2024-01-15T10:00:00Z",
                "entity_history": {
                    "user_alerts_30d": 2,
                    "host_alerts_30d": 8
                }
            }
            
            # If entities exist, add entity-specific data
            if signal.entities:
                if "ip" in signal.entities:
                    enrichment_data["ip_history"] = {
                        "total_alerts": 3,
                        "unique_hosts": 1
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
