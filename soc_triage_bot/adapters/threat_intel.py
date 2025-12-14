"""Threat Intelligence adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict
from .base import BaseAdapter
from ..models import Signal, EnrichmentResult, EnrichmentStatus


class ThreatIntelAdapter(BaseAdapter):
    """Generic Threat Intelligence adapter."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the adapter."""
        super().__init__(config)
        self.name = "threat_intel"  # Override to use underscore
    
    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with threat intelligence data.
        
        This is a generic implementation. In production, this would
        connect to TI feeds (VirusTotal, AlienVault, etc.)
        
        Args:
            signal: The signal to enrich
            
        Returns:
            EnrichmentResult with threat intel context
        """
        start_time = datetime.utcnow()
        
        try:
            # Mock enrichment - in production, query TI sources for:
            # - IP/domain/hash reputation
            # - Known campaigns
            # - Threat actor attribution
            # - CVE details
            
            enrichment_data: Dict[str, Any] = {
                "feeds_checked": ["feed1", "feed2", "feed3"],
                "matches_found": 0,
                "reputation": "unknown"
            }
            
            # Check IPs
            if "ip" in signal.entities:
                for ip in signal.entities["ip"]:
                    # Mock check - in production, query TI feeds
                    if self._is_suspicious_ip(ip):
                        enrichment_data["matches_found"] += 1
                        enrichment_data["reputation"] = "suspicious"
                        enrichment_data["ip_intel"] = {
                            ip: {
                                "reputation": "malicious",
                                "threat_score": 85,
                                "categories": ["malware", "c2"],
                                "first_seen": "2024-11-20",
                                "last_seen": "2025-12-14",
                                "references": ["campaign-xyz"]
                            }
                        }
            
            # Check domains
            if "domain" in signal.entities:
                enrichment_data["domain_intel"] = {}
                for domain in signal.entities["domain"]:
                    enrichment_data["domain_intel"][domain] = {
                        "reputation": "unknown",
                        "age_days": 730,
                        "registrar": "example-registrar"
                    }
            
            # Check file hashes
            if "file_hash" in signal.entities:
                enrichment_data["file_intel"] = {}
                for hash_val in signal.entities["file_hash"]:
                    enrichment_data["file_intel"][hash_val] = {
                        "known_malware": False,
                        "detection_rate": 0,
                        "family": None
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
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Mock function to check if IP is suspicious.
        
        In production, this would query actual TI feeds.
        """
        # Simple mock: IPs starting with 10. are suspicious (for demo)
        return ip.startswith("192.0.2.") or ip.startswith("198.51.100.")
